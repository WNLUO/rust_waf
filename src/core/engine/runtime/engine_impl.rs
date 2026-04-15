use super::*;
use crate::core::engine_maintenance;

pub struct WafEngine {
    context: Arc<WafContext>,
    _shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: mpsc::Receiver<()>,
    connection_semaphore: Arc<Semaphore>,
}

impl WafEngine {
    pub async fn new(config: Config) -> Result<Self> {
        info!("Initializing WAF engine...");

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let concurrency_limit = config.max_concurrent_tasks.max(1);
        let context = Arc::new(WafContext::new(config).await?);

        Ok(Self {
            context,
            _shutdown_tx: shutdown_tx,
            shutdown_rx,
            connection_semaphore: Arc::new(Semaphore::new(concurrency_limit)),
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        let startup_config = self.context.config_snapshot();
        info!("WAF engine started");
        info!(
            "Concurrency limit set to {} inflight connections",
            startup_config.max_concurrent_tasks
        );

        if let Some(l4_inspector) = self.context.l4_inspector() {
            l4_inspector.start(self.context.as_ref()).await?;
        }

        self.context
            .http_processor
            .start(self.context.as_ref())
            .await?;
        self.context.refresh_ai_temp_policies().await?;

        #[cfg(feature = "api")]
        if startup_config.api_enabled {
            let addr = startup_config.api_bind.parse()?;
            let context = Arc::clone(&self.context);
            tokio::spawn(async move {
                if let Err(err) = crate::api::ApiServer::new(addr, context).start().await {
                    warn!("API server exited with error: {}", err);
                }
            });
        }

        #[cfg(not(feature = "api"))]
        if startup_config.api_enabled {
            warn!("API support was requested but the binary was built without the 'api' feature");
        }

        let context = Arc::clone(&self.context);
        tokio::spawn(async move {
            engine_maintenance::run_upstream_healthcheck_loop(context).await;
        });

        let context = Arc::clone(&self.context);
        tokio::spawn(async move {
            engine_maintenance::run_auto_tuning_loop(context).await;
        });

        let context = Arc::clone(&self.context);
        tokio::spawn(async move {
            engine_maintenance::run_trusted_cdn_sync_loop(context).await;
        });

        if let Some(store) = self.context.sqlite_store.as_ref().cloned() {
            let fallback_config = startup_config.clone();
            tokio::spawn(async move {
                engine_maintenance::run_safeline_auto_sync_loop(store, fallback_config).await;
            });
        }

        let maintenance_interval = startup_config.maintenance_interval_secs.max(5);
        let mut maintenance =
            tokio::time::interval(tokio::time::Duration::from_secs(maintenance_interval));

        let mut shutdown_senders = Vec::new();
        let mut udp_listener_addresses = Vec::new();

        for addr in &startup_config.listen_addrs {
            match UdpSocket::bind(addr).await {
                Ok(socket) => {
                    let addr = socket.local_addr()?;
                    udp_listener_addresses.push((addr, Arc::new(socket)));
                }
                Err(err) => {
                    warn!("Failed to bind UDP listener on {}: {}", addr, err);
                }
            }
        }

        #[cfg(not(feature = "http3"))]
        if startup_config.http3_config.enabled {
            self.context.set_http3_runtime(
                "unsupported",
                false,
                None,
                Some("Binary was built without the 'http3' feature".to_string()),
            );
            warn!(
                "HTTP/3 support was requested but the binary was built without the 'http3' feature"
            );
        } else {
            self.context
                .set_http3_runtime("disabled", false, None, None);
        }

        for (addr, socket) in udp_listener_addresses {
            info!("UDP inspection listener started on {}", addr);
            let context = Arc::clone(&self.context);
            let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
            let connection_semaphore = Arc::clone(&self.connection_semaphore);

            let task = tokio::spawn(async move {
                let mut buffer = vec![0u8; 65_535];
                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            info!("UDP listener shutdown signal received for {}", addr);
                            break;
                        }
                        recv_result = socket.recv_from(&mut buffer) => {
                            match recv_result {
                                Ok((bytes_read, peer_addr)) => {
                                    match connection_semaphore.clone().try_acquire_owned() {
                                        Ok(permit) => {
                                            let ctx = Arc::clone(&context);
                                            let listener_socket = Arc::clone(&socket);
                                            let payload = buffer[..bytes_read].to_vec();
                                            tokio::spawn(async move {
                                                if let Err(err) = handle_udp_datagram(
                                                    ctx,
                                                    listener_socket,
                                                    peer_addr,
                                                    addr,
                                                    payload,
                                                    permit,
                                                ).await {
                                                    warn!("UDP datagram handling failed: {}", err);
                                                }
                                            });
                                        }
                                        Err(_) => {
                                            warn!(
                                                "Dropping UDP datagram from {} due to concurrency limit",
                                                peer_addr
                                            );
                                        }
                                    }
                                }
                                Err(err) => {
                                    warn!("Failed to receive UDP datagram on {}: {}", addr, err);
                                }
                            }
                        }
                        _ = tokio::signal::ctrl_c() => {
                            info!("Ctrl+C received, shutting down UDP listener on {}", addr);
                            break;
                        }
                    }
                }
            });
            shutdown_senders.push((task, shutdown_tx));
        }

        info!(
            "Successfully started {} listener task(s)",
            shutdown_senders.len()
        );

        let entry_runtime = EntryListenerRuntime::global();
        entry_runtime
            .sync(
                Arc::clone(&self.context),
                Arc::clone(&self.connection_semaphore),
            )
            .await?;
        #[cfg(feature = "http3")]
        super::sync_http3_listener_runtime(
            Arc::clone(&self.context),
            startup_config.max_concurrent_tasks,
        )
        .await?;

        loop {
            tokio::select! {
                _ = self.shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    for (_, shutdown_tx) in &shutdown_senders {
                        let _ = shutdown_tx.send(()).await;
                    }
                    super::shutdown_entry_listener_runtime().await;
                    #[cfg(feature = "http3")]
                    super::shutdown_http3_listener_runtime(Arc::clone(&self.context)).await;
                    self.context.shutdown_storage().await?;
                    break Ok(());
                }
                _ = maintenance.tick() => {
                    self.run_maintenance().await;
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl+C received, shutting down");
                    for (_, shutdown_tx) in &shutdown_senders {
                        let _ = shutdown_tx.send(()).await;
                    }
                    super::shutdown_entry_listener_runtime().await;
                    #[cfg(feature = "http3")]
                    super::shutdown_http3_listener_runtime(Arc::clone(&self.context)).await;
                    self.context.shutdown_storage().await?;
                    break Ok(());
                }
            }
        }
    }

    async fn run_maintenance(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if let Err(err) = self.context.refresh_rules_from_storage().await {
            warn!("Failed to refresh rules from SQLite: {}", err);
        }

        if let Some(store) = self.context.sqlite_store.as_ref() {
            let storage_policy = self.context.config_snapshot().storage_policy;
            let thresholds = [
                (
                    "security events",
                    store
                        .purge_old_security_events(now.saturating_sub(
                            (storage_policy.security_event_retention_days * 24 * 3600) as i64,
                        ))
                        .await,
                ),
                (
                    "behavior events",
                    store
                        .purge_old_behavior_events(now.saturating_sub(
                            (storage_policy.behavior_event_retention_days * 24 * 3600) as i64,
                        ))
                        .await,
                ),
                (
                    "behavior sessions",
                    store
                        .purge_old_behavior_sessions(now.saturating_sub(
                            (storage_policy.behavior_session_retention_days * 24 * 3600) as i64,
                        ))
                        .await,
                ),
                (
                    "fingerprint profiles",
                    store
                        .purge_old_fingerprint_profiles(now.saturating_sub(
                            (storage_policy.fingerprint_profile_retention_days * 24 * 3600) as i64,
                        ))
                        .await,
                ),
                (
                    "AI audit reports",
                    store
                        .purge_old_ai_audit_reports(now.saturating_sub(
                            (storage_policy.ai_audit_report_retention_days * 24 * 3600) as i64,
                        ))
                        .await,
                ),
                (
                    "inactive AI temp policies",
                    store
                        .purge_inactive_ai_temp_policies(now.saturating_sub(
                            (storage_policy.ai_audit_report_retention_days * 24 * 3600) as i64,
                        ))
                        .await,
                ),
            ];
            for (label, result) in thresholds {
                match result {
                    Ok(removed) if removed > 0 => {
                        debug!("Maintenance purged {} stale {}", removed, label);
                    }
                    Ok(_) => {}
                    Err(err) => warn!("Failed to purge stale {}: {}", label, err),
                }
            }

            if let Err(err) = self.auto_govern_ai_temp_policies(store.as_ref(), now).await {
                warn!("Failed to auto-govern AI temp policies: {}", err);
            }
        }

        if let Err(err) = self.context.refresh_ai_temp_policies().await {
            warn!("Failed to refresh AI temp policies: {}", err);
        }

        #[cfg(feature = "api")]
        if let Err(err) = self.run_ai_auto_audit(now).await {
            warn!("Failed to run AI auto audit: {}", err);
        }

        if let Some(l4_inspector) = self.context.l4_inspector() {
            l4_inspector.maintenance_tick();
            if matches!(
                self.context.config_snapshot().runtime_profile,
                RuntimeProfile::Standard
            ) {
                let stats = l4_inspector.get_statistics();
                debug!(
                    "Maintenance tick: active_connections={}, blocked_connections={}, rate_limit_hits={}",
                    stats.connections.active_connections,
                    stats.connections.blocked_connections,
                    stats.connections.rate_limit_hits
                );
                debug!(
                    "L4 counters: ddos_events={}, protocol_anomalies={}, traffic={}, defense_actions={}",
                    stats.ddos_events,
                    stats.protocol_anomalies,
                    stats.traffic,
                    stats.defense_actions
                );

                if !stats.per_port_stats.is_empty() {
                    debug!("=== Per-Port Statistics ===");
                    for (port, port_stats) in &stats.per_port_stats {
                        debug!(
                            "Port {}: connections={}, blocks={}, ddos_events={}",
                            port, port_stats.connections, port_stats.blocks, port_stats.ddos_events
                        );
                    }
                    debug!("=============================");
                }
            }
        }
    }

    async fn auto_govern_ai_temp_policies(
        &self,
        store: &crate::storage::SqliteStore,
        now: i64,
    ) -> Result<()> {
        let current_identity = self
            .context
            .auto_tuning_snapshot()
            .last_observed_identity_resolution_pressure_percent;
        let current_l7 = self
            .context
            .auto_tuning_snapshot()
            .last_observed_l7_friction_pressure_percent;
        let ai_config = self.context.config_snapshot().integrations.ai_audit;
        let policies = store.list_active_ai_temp_policies(now).await?;

        for policy in policies {
            let mut effect = serde_json::from_str::<crate::storage::AiTempPolicyEffectStats>(
                &policy.effect_json,
            )
            .unwrap_or_default();
            effect.last_effectiveness_check_at = Some(now);

            let age_secs = now.saturating_sub(policy.created_at);
            let ttl_remaining = policy.expires_at.saturating_sub(now);
            let l7_improved = effect
                .baseline_l7_friction_percent
                .map(|baseline| current_l7 <= baseline - 3.0)
                .unwrap_or(false);
            let identity_improved = effect
                .baseline_identity_pressure_percent
                .map(|baseline| current_identity <= baseline - 1.5)
                .unwrap_or(false);
            let governance_mode = ai_temp_policy_governance_mode(
                policy.action.as_str(),
                policy.hit_count,
                l7_improved,
                identity_improved,
            );

            let should_revoke = ai_config.auto_apply_temp_policies
                && age_secs >= ai_config.auto_revoke_warmup_secs as i64
                && governance_mode == "cold"
                && !effect.auto_revoked;
            if should_revoke {
                effect.auto_revoked = true;
                effect.auto_revoke_reason =
                    Some(format!("{}_after_warmup", policy.action.replace(':', "_")));
                let _ = store
                    .revoke_ai_temp_policy_with_effect(policy.id, &effect, now)
                    .await?;
                continue;
            }

            let should_extend = ai_config.allow_auto_extend_effective_policies
                && ttl_remaining <= 300
                && governance_mode == "effective"
                && effect.auto_extensions < 2;
            if should_extend {
                effect.auto_extensions += 1;
                let extension_secs = match policy.action.as_str() {
                    "add_temp_block" => 300,
                    "increase_delay" => 600,
                    "tighten_route_cc" | "tighten_host_cc" | "increase_challenge" => 900,
                    "raise_identity_risk" | "add_behavior_watch" => 600,
                    _ => 300,
                };
                let _ = store
                    .extend_ai_temp_policy_expiry_with_effect(
                        policy.id,
                        policy.expires_at.saturating_add(extension_secs),
                        &effect,
                        now,
                    )
                    .await?;
                continue;
            }

            if effect.last_effectiveness_check_at == Some(now) {
                let _ = store
                    .extend_ai_temp_policy_expiry_with_effect(
                        policy.id,
                        policy.expires_at,
                        &effect,
                        now,
                    )
                    .await?;
            }
        }

        Ok(())
    }

    #[cfg(feature = "api")]
    async fn run_ai_auto_audit(&self, now: i64) -> Result<()> {
        let config = self.context.config_snapshot();
        let ai_config = config.integrations.ai_audit.clone();
        const SHORT_WINDOW_SECS: u32 = 3 * 60;
        const LONG_WINDOW_SECS: u32 = 15 * 60;
        if !ai_config.auto_audit_enabled {
            return Ok(());
        }
        if self.context.sqlite_store.is_none() {
            return Ok(());
        }

        let runtime = self.context.ai_auto_audit_runtime_snapshot().await;
        if runtime
            .last_run_at
            .is_some_and(|last| now.saturating_sub(last) < ai_config.auto_audit_interval_secs as i64)
        {
            return Ok(());
        }

        let trigger_summary = crate::api::build_ai_audit_summary_for_context(
            self.context.as_ref(),
            Some(SHORT_WINDOW_SECS),
            Some(ai_config.event_sample_limit.min(80)),
            Some(ai_config.recent_event_limit.min(8)),
        )
        .await?;
        if let Some(pause_reason) = ai_auto_audit_pause_reason(&trigger_summary) {
            info!("AI auto audit paused: {}", pause_reason);
            return Ok(());
        }

        let signature = ai_auto_audit_signature(&trigger_summary);
        self.context
            .note_ai_auto_audit_observed_signature(Some(signature.clone()))
            .await;

        let trigger_reasons = ai_auto_audit_trigger_reasons(
            &ai_config,
            &trigger_summary,
            runtime.last_observed_signature.as_deref(),
            &signature,
        );
        if trigger_reasons.is_empty() {
            return Ok(());
        }
        if runtime.last_run_at.is_some_and(|last| {
            now.saturating_sub(last) < ai_config.auto_audit_cooldown_secs as i64
        }) {
            return Ok(());
        }
        if runtime
            .last_trigger_signature
            .as_deref()
            .is_some_and(|previous| previous == signature)
        {
            return Ok(());
        }

        let reason = trigger_reasons.join("+");
        self.context
            .note_ai_auto_audit_run_started(signature, reason.clone(), now)
            .await;

        let report = crate::api::run_ai_audit_report_for_context(
            Arc::clone(&self.context),
            crate::api::AiAuditReportQueryParams {
                window_seconds: Some(LONG_WINDOW_SECS),
                sample_limit: Some(ai_config.event_sample_limit.min(120)),
                recent_limit: Some(ai_config.recent_event_limit.min(8)),
                provider: None,
                fallback_to_rules: Some(ai_config.fallback_to_rules),
            },
            ai_config.auto_audit_force_local_rules_under_attack
                && trigger_summary.runtime_pressure_level == "attack",
            Some(reason.clone()),
        )
        .await?;
        self.context
            .note_ai_auto_audit_run_completed(report.report_id, now)
            .await;
        info!(
            "AI auto audit completed: reason={} risk_level={} provider={}",
            reason, report.risk_level, report.provider_used
        );
        Ok(())
    }
}

fn ai_temp_policy_governance_mode(
    action: &str,
    hit_count: i64,
    l7_improved: bool,
    identity_improved: bool,
) -> &'static str {
    match action {
        "increase_delay" => {
            if hit_count >= 3 && l7_improved {
                "effective"
            } else if hit_count == 0 {
                "cold"
            } else {
                "watch"
            }
        }
        "tighten_route_cc" | "tighten_host_cc" | "increase_challenge" => {
            if hit_count >= 2 && l7_improved {
                "effective"
            } else if hit_count == 0 {
                "cold"
            } else {
                "watch"
            }
        }
        "raise_identity_risk" | "add_behavior_watch" => {
            if hit_count >= 2 && identity_improved {
                "effective"
            } else if hit_count == 0 {
                "cold"
            } else {
                "watch"
            }
        }
        "add_temp_block" => {
            if hit_count >= 1 && (l7_improved || identity_improved) {
                "effective"
            } else if hit_count == 0 {
                "cold"
            } else {
                "watch"
            }
        }
        _ => {
            if hit_count == 0 {
                "cold"
            } else {
                "watch"
            }
        }
    }
}

#[cfg(feature = "api")]
fn ai_auto_audit_signature(summary: &crate::api::AiAuditSummaryResponse) -> String {
    let top_route = summary
        .top_routes
        .first()
        .map(|item| item.key.as_str())
        .unwrap_or("-");
    let top_source = summary
        .top_source_ips
        .first()
        .map(|item| item.key.as_str())
        .unwrap_or("-");
    let top_signal = summary
        .primary_signals
        .first()
        .map(|item| item.key.as_str())
        .unwrap_or("-");
    format!(
        "{}|{}|{}|{}|{}",
        summary.runtime_pressure_level, top_route, top_source, top_signal, summary.total_events
    )
}

#[cfg(feature = "api")]
fn ai_auto_audit_trigger_reasons(
    config: &crate::config::AiAuditConfig,
    summary: &crate::api::AiAuditSummaryResponse,
    previous_signature: Option<&str>,
    current_signature: &str,
) -> Vec<String> {
    let mut trigger_reasons = Vec::new();
    if config.auto_audit_on_attack_mode && summary.runtime_pressure_level == "attack" {
        trigger_reasons.push("attack_mode".to_string());
    } else if config.auto_audit_on_pressure_high
        && matches!(summary.runtime_pressure_level.as_str(), "high" | "attack")
    {
        trigger_reasons.push("pressure_high".to_string());
    }
    if config.auto_audit_on_hotspot_shift
        && previous_signature.is_some_and(|previous| previous != current_signature)
        && summary.sampled_events > 0
    {
        trigger_reasons.push("hotspot_shift".to_string());
    }
    if summary.data_quality.analysis_confidence == "medium"
        && (summary.data_quality.detail_slimming_active
            || summary.data_quality.sqlite_queue_usage_percent >= 75.0)
    {
        trigger_reasons.push("data_quality_degraded".to_string());
    }
    trigger_reasons
}

#[cfg(feature = "api")]
fn ai_auto_audit_pause_reason(summary: &crate::api::AiAuditSummaryResponse) -> Option<String> {
    if summary.data_quality.analysis_confidence != "low" {
        return None;
    }
    if summary.data_quality.dropped_security_events > 0 {
        return Some(format!(
            "data quality degraded: dropped_security_events={}",
            summary.data_quality.dropped_security_events
        ));
    }
    if summary.data_quality.persistence_coverage_ratio < 0.95 {
        return Some(format!(
            "data quality degraded: persistence_coverage_ratio={:.2}",
            summary.data_quality.persistence_coverage_ratio
        ));
    }
    if summary.data_quality.detail_slimming_active {
        return Some("data quality degraded: detail slimming active".to_string());
    }
    None
}

#[cfg(all(test, feature = "api"))]
mod tests {
    use super::*;

    fn sample_summary() -> crate::api::AiAuditSummaryResponse {
        crate::api::AiAuditSummaryResponse {
            generated_at: 1,
            window_seconds: 900,
            sampled_events: 10,
            total_events: 12,
            active_rules: 3,
            runtime_pressure_level: "high".to_string(),
            degraded_reasons: Vec::new(),
            data_quality: crate::api::AiAuditDataQualityResponse::default(),
            current: crate::api::AiAuditCurrentStateResponse::default(),
            counters: crate::api::AiAuditCountersResponse::default(),
            action_breakdown: Vec::new(),
            provider_breakdown: Vec::new(),
            identity_states: Vec::new(),
            primary_signals: vec![crate::api::AiAuditCountItem {
                key: "l7_cc:block".to_string(),
                count: 4,
            }],
            labels: Vec::new(),
            top_source_ips: vec![crate::api::AiAuditCountItem {
                key: "203.0.113.10".to_string(),
                count: 5,
            }],
            top_routes: vec![crate::api::AiAuditCountItem {
                key: "/login".to_string(),
                count: 6,
            }],
            top_hosts: Vec::new(),
            safeline_correlation: crate::api::AiAuditSafeLineCorrelationResponse::default(),
            trend_windows: Vec::new(),
            recent_policy_feedback: Vec::new(),
            recent_events: Vec::new(),
        }
    }

    #[test]
    fn ai_auto_audit_trigger_reasons_cover_pressure_and_hotspot_shift() {
        let config = crate::config::AiAuditConfig {
            auto_audit_enabled: true,
            auto_audit_on_pressure_high: true,
            auto_audit_on_attack_mode: true,
            auto_audit_on_hotspot_shift: true,
            ..crate::config::AiAuditConfig::default()
        };
        let summary = sample_summary();
        let signature = ai_auto_audit_signature(&summary);

        let reasons =
            ai_auto_audit_trigger_reasons(&config, &summary, Some("old|signature"), &signature);

        assert!(reasons.iter().any(|item| item == "pressure_high"));
        assert!(reasons.iter().any(|item| item == "hotspot_shift"));
    }

    #[test]
    fn ai_auto_audit_trigger_reasons_include_data_quality_degraded() {
        let config = crate::config::AiAuditConfig {
            auto_audit_enabled: true,
            auto_audit_on_pressure_high: true,
            auto_audit_on_attack_mode: true,
            auto_audit_on_hotspot_shift: true,
            ..crate::config::AiAuditConfig::default()
        };
        let mut summary = sample_summary();
        summary.data_quality.analysis_confidence = "medium".to_string();
        summary.data_quality.detail_slimming_active = true;
        summary.data_quality.sqlite_queue_usage_percent = 82.0;
        let signature = ai_auto_audit_signature(&summary);

        let reasons =
            ai_auto_audit_trigger_reasons(&config, &summary, Some(&signature), &signature);

        assert!(reasons.iter().any(|item| item == "data_quality_degraded"));
    }

    #[test]
    fn ai_auto_audit_pause_reason_blocks_low_confidence_data_quality() {
        let mut summary = sample_summary();
        summary.data_quality.analysis_confidence = "low".to_string();
        summary.data_quality.dropped_security_events = 3;

        let reason = ai_auto_audit_pause_reason(&summary);

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("dropped_security_events"));
    }
}
