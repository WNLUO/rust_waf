pub(crate) async fn ai_audit_summary_handler(
    State(state): State<ApiState>,
    Query(params): Query<AiAuditSummaryQueryParams>,
) -> ApiResult<Json<AiAuditSummaryResponse>> {
    Ok(Json(
        build_ai_audit_summary(
            state.context.as_ref(),
            params.window_seconds,
            params.sample_limit,
            params.recent_limit,
        )
        .await?,
    ))
}

pub(crate) async fn ai_audit_report_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<AiAuditReportResponse>> {
    let store = sqlite_store(&state)?;
    let result = store
        .list_ai_audit_reports(&crate::storage::AiAuditReportQuery {
            limit: 1,
            offset: 0,
            feedback_status: None,
        })
        .await
        .map_err(ApiError::internal)?;
    let Some(entry) = result.items.into_iter().next() else {
        return Err(ApiError::not_found(
            "暂无 AI 审计历史，请先执行一次 AI 审计",
        ));
    };
    let report = crate::api::ai_audit::history_item_from_entry(entry)
        .map_err(ApiError::internal)?
        .report;
    Ok(Json(report))
}
pub(crate) async fn run_ai_audit_report_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<AiAuditRunRequest>,
) -> ApiResult<Json<AiAuditReportResponse>> {
    let runtime_policy = management_runtime_policy(state.context.as_ref());
    let params = AiAuditReportQueryParams {
        window_seconds: payload.window_seconds,
        sample_limit: payload.sample_limit,
        recent_limit: payload.recent_limit,
        provider: payload.provider,
        fallback_to_rules: payload.fallback_to_rules,
    };
    Ok(Json(
        run_ai_audit_report_for_context(
            Arc::clone(&state.context),
            params,
            runtime_policy.force_local_rules,
            None,
        )
        .await
        .map_err(ApiError::internal)?,
    ))
}

pub(crate) async fn run_ai_audit_report_for_context(
    context: Arc<WafContext>,
    params: AiAuditReportQueryParams,
    force_local_rules: bool,
    trigger_reason: Option<String>,
) -> anyhow::Result<AiAuditReportResponse> {
    let config = context.config_snapshot();
    let mut execution = crate::api::ai_audit::resolve_report_execution(&config, &params);
    if force_local_rules && execution.provider != crate::api::ai_audit::AiAuditProvider::LocalRules
    {
        execution.provider = crate::api::ai_audit::AiAuditProvider::LocalRules;
        execution
            .execution_notes
            .push("runtime pressure forced ai audit into local_rules mode".to_string());
    }
    if let Some(reason) = trigger_reason {
        execution
            .execution_notes
            .push(format!("auto audit trigger reason: {}", reason));
    }
    let summary_query = crate::api::ai_audit::summary_query_from_report(&params);
    let summary = build_ai_audit_summary(
        context.as_ref(),
        summary_query.window_seconds,
        summary_query.sample_limit,
        summary_query.recent_limit,
    )
    .await
    .map_err(|err| anyhow::anyhow!("build ai audit summary failed: {:?}", err))?;
    let mut report =
        crate::api::ai_audit::execute_report(execution, summary, build_ai_audit_report)
            .await
            .map_err(|err| anyhow::anyhow!("execute ai audit report failed: {:?}", err))?;
    if force_local_rules {
        report
            .degraded_reasons
            .push("management_ai_audit_forced_local_rules_under_runtime_pressure".to_string());
    }
    if let Some(store) = context.sqlite_store.as_ref() {
        let persist_result = match serde_json::to_string(&report) {
            Ok(report_json) => store
                .create_ai_audit_report(
                    report.generated_at,
                    &report.provider_used,
                    report.fallback_used,
                    &report.risk_level,
                    &report.headline,
                    &report_json,
                )
                .await
                .map_err(anyhow::Error::from),
            Err(err) => Err(anyhow::Error::from(err)),
        };
        match persist_result {
            Ok(id) => report.report_id = Some(id),
            Err(err) => {
                log::warn!("Failed to persist AI audit report: {:?}", err);
                report
                    .execution_notes
                    .push("failed to persist ai audit report snapshot".to_string());
            }
        }
        if config.integrations.ai_audit.auto_apply_temp_policies {
            match apply_ai_temp_policies_from_report(
                store,
                report.report_id,
                &report,
                &config.integrations.ai_audit,
            )
            .await
            {
                Ok(applied) => {
                    if applied > 0 {
                        report.execution_notes.push(format!(
                            "auto applied {} temporary cc/behavior policies",
                            applied
                        ));
                    }
                }
                Err(err) => {
                    log::warn!("Failed to auto-apply AI temp policies: {:?}", err);
                    report
                        .execution_notes
                        .push("failed to auto apply ai temporary policies".to_string());
                }
            }
            let _ = context.refresh_ai_temp_policies().await;
        }
    }
    Ok(report)
}

pub(crate) async fn list_ai_audit_reports_handler(
    State(state): State<ApiState>,
    Query(params): Query<AiAuditReportsQueryParams>,
) -> ApiResult<Json<AiAuditReportsResponse>> {
    let store = sqlite_store(&state)?;
    let result = store
        .list_ai_audit_reports(&crate::storage::AiAuditReportQuery {
            limit: params.limit.unwrap_or(20),
            offset: params.offset.unwrap_or(0),
            feedback_status: params.feedback_status,
        })
        .await
        .map_err(ApiError::internal)?;

    let reports = result
        .items
        .into_iter()
        .map(crate::api::ai_audit::history_item_from_entry)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::internal)?;

    Ok(Json(AiAuditReportsResponse {
        total: result.total,
        limit: result.limit,
        offset: result.offset,
        reports,
    }))
}
pub(crate) async fn update_ai_audit_report_feedback_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
    ExtractJson(payload): ExtractJson<AiAuditFeedbackUpdateRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let feedback_status = payload
        .feedback_status
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(status) = feedback_status {
        let normalized = status.to_ascii_lowercase();
        if !matches!(
            normalized.as_str(),
            "confirmed" | "false_positive" | "follow_up"
        ) {
            return Err(ApiError::bad_request(
                "feedback_status 仅支持 confirmed / false_positive / follow_up",
            ));
        }
    }
    let updated = store
        .update_ai_audit_report_feedback(
            id,
            feedback_status,
            payload
                .feedback_notes
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
        )
        .await
        .map_err(ApiError::internal)?;
    if !updated {
        return Err(ApiError::not_found("未找到对应的 AI 审计报告"));
    }

    Ok(Json(WriteStatusResponse {
        success: true,
        message: "AI 审计反馈已更新".to_string(),
    }))
}
use super::*;
