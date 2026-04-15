impl SqliteStore {
    #[cfg(any(feature = "api", test))]
    pub async fn create_ai_audit_report(
        &self,
        generated_at: i64,
        provider_used: &str,
        fallback_used: bool,
        risk_level: &str,
        headline: &str,
        report_json: &str,
    ) -> Result<i64> {
        let result = sqlx::query(
            r#"
            INSERT INTO ai_audit_reports (
                generated_at, provider_used, fallback_used, risk_level, headline, report_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(generated_at)
        .bind(provider_used)
        .bind(fallback_used)
        .bind(risk_level)
        .bind(headline)
        .bind(report_json)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    #[cfg(any(feature = "api", test))]
    pub async fn list_ai_audit_reports(
        &self,
        query: &AiAuditReportQuery,
    ) -> Result<PagedResult<AiAuditReportEntry>> {
        let limit = normalized_limit(query.limit);
        let offset = query.offset;

        let mut count_builder =
            QueryBuilder::<Sqlite>::new("SELECT COUNT(*) FROM ai_audit_reports WHERE 1=1");
        if let Some(status) = query.feedback_status.as_deref() {
            if status.eq_ignore_ascii_case("unreviewed") {
                count_builder.push(" AND feedback_status IS NULL");
            } else {
                count_builder.push(" AND LOWER(feedback_status) = LOWER(");
                count_builder.push_bind(status);
                count_builder.push(")");
            }
        }
        let total: i64 = count_builder
            .build_query_scalar()
            .fetch_one(&self.pool)
            .await?;

        let mut builder = QueryBuilder::<Sqlite>::new(
            r#"
            SELECT id, generated_at, provider_used, fallback_used, risk_level, headline, report_json,
                   feedback_status, feedback_notes, feedback_updated_at
            FROM ai_audit_reports
            WHERE 1=1
            "#,
        );
        if let Some(status) = query.feedback_status.as_deref() {
            if status.eq_ignore_ascii_case("unreviewed") {
                builder.push(" AND feedback_status IS NULL");
            } else {
                builder.push(" AND LOWER(feedback_status) = LOWER(");
                builder.push_bind(status);
                builder.push(")");
            }
        }
        builder.push(" ORDER BY generated_at DESC, id DESC LIMIT ");
        builder.push_bind(i64::from(limit));
        builder.push(" OFFSET ");
        builder.push_bind(i64::from(offset));

        let items = builder
            .build_query_as::<AiAuditReportEntry>()
            .fetch_all(&self.pool)
            .await?;

        Ok(PagedResult {
            total: total.max(0) as u64,
            limit,
            offset,
            items,
        })
    }

    #[cfg(any(feature = "api", test))]
    pub async fn update_ai_audit_report_feedback(
        &self,
        id: i64,
        feedback_status: Option<&str>,
        feedback_notes: Option<&str>,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE ai_audit_reports
            SET feedback_status = ?, feedback_notes = ?, feedback_updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(feedback_status)
        .bind(feedback_notes)
        .bind(unix_timestamp())
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}
