use anyhow::Result;
use sqlx::SqlitePool;

pub(super) async fn initialize_schema(pool: &SqlitePool) -> Result<()> {
    sqlx::raw_sql(
        r#"
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            layer TEXT NOT NULL,
            provider TEXT,
            provider_event_id TEXT,
            provider_site_id TEXT,
            provider_site_name TEXT,
            provider_site_domain TEXT,
            action TEXT NOT NULL,
            reason TEXT NOT NULL,
            details_json TEXT,
            source_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL,
            source_port INTEGER NOT NULL,
            dest_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            http_method TEXT,
            uri TEXT,
            http_version TEXT,
            created_at INTEGER NOT NULL,
            handled INTEGER NOT NULL DEFAULT 0,
            handled_at INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_security_events_created_at
            ON security_events(created_at);
        CREATE INDEX IF NOT EXISTS idx_security_events_source_ip
            ON security_events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_security_events_action_created_at
            ON security_events(action, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_security_events_handled_created_at
            ON security_events(handled, created_at DESC);

        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT,
            provider_remote_id TEXT,
            ip TEXT NOT NULL,
            reason TEXT NOT NULL,
            blocked_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip
            ON blocked_ips(ip);
        CREATE INDEX IF NOT EXISTS idx_blocked_ips_expires_at
            ON blocked_ips(expires_at);
        CREATE INDEX IF NOT EXISTS idx_blocked_ips_provider_blocked_at
            ON blocked_ips(provider, blocked_at DESC);
        CREATE INDEX IF NOT EXISTS idx_blocked_ips_provider_ip_expires_at
            ON blocked_ips(provider, ip, expires_at DESC);

        CREATE TABLE IF NOT EXISTS ai_visitor_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identity_key TEXT NOT NULL,
            identity_source TEXT NOT NULL,
            site_id TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            first_seen_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL,
            request_count INTEGER NOT NULL DEFAULT 0,
            document_count INTEGER NOT NULL DEFAULT 0,
            api_count INTEGER NOT NULL DEFAULT 0,
            static_count INTEGER NOT NULL DEFAULT 0,
            admin_count INTEGER NOT NULL DEFAULT 0,
            challenge_count INTEGER NOT NULL DEFAULT 0,
            challenge_verified_count INTEGER NOT NULL DEFAULT 0,
            fingerprint_seen INTEGER NOT NULL DEFAULT 0,
            human_confidence INTEGER NOT NULL DEFAULT 0,
            automation_risk INTEGER NOT NULL DEFAULT 0,
            probe_risk INTEGER NOT NULL DEFAULT 0,
            abuse_risk INTEGER NOT NULL DEFAULT 0,
            false_positive_risk TEXT NOT NULL DEFAULT 'low',
            state TEXT NOT NULL DEFAULT 'observing',
            summary_json TEXT NOT NULL DEFAULT '{}',
            last_ai_review_at INTEGER,
            ai_rationale TEXT NOT NULL DEFAULT '',
            expires_at INTEGER NOT NULL,
            UNIQUE(identity_key, site_id)
        );

        CREATE INDEX IF NOT EXISTS idx_ai_visitor_profiles_last_seen_at
            ON ai_visitor_profiles(last_seen_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ai_visitor_profiles_state
            ON ai_visitor_profiles(state, last_seen_at DESC);

        CREATE TABLE IF NOT EXISTS ai_visitor_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            decision_key TEXT NOT NULL UNIQUE,
            identity_key TEXT NOT NULL,
            site_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            action TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            ttl_secs INTEGER NOT NULL,
            rationale TEXT NOT NULL,
            applied INTEGER NOT NULL DEFAULT 0,
            effect_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_ai_visitor_decisions_created_at
            ON ai_visitor_decisions(created_at DESC);

        CREATE TABLE IF NOT EXISTS fingerprint_profiles (
            identity TEXT PRIMARY KEY,
            identity_kind TEXT NOT NULL,
            source_ip TEXT,
            first_seen_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL,
            first_site_domain TEXT,
            last_site_domain TEXT,
            first_user_agent TEXT,
            last_user_agent TEXT,
            total_security_events INTEGER NOT NULL DEFAULT 0,
            total_behavior_events INTEGER NOT NULL DEFAULT 0,
            total_challenges INTEGER NOT NULL DEFAULT 0,
            total_blocks INTEGER NOT NULL DEFAULT 0,
            latest_score INTEGER,
            max_score INTEGER NOT NULL DEFAULT 0,
            latest_action TEXT,
            reputation_score INTEGER NOT NULL DEFAULT 0,
            notes TEXT NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_fingerprint_profiles_last_seen_at
            ON fingerprint_profiles(last_seen_at);
        CREATE INDEX IF NOT EXISTS idx_fingerprint_profiles_source_ip
            ON fingerprint_profiles(source_ip);

        CREATE TABLE IF NOT EXISTS behavior_sessions (
            session_key TEXT PRIMARY KEY,
            identity TEXT NOT NULL,
            source_ip TEXT,
            site_domain TEXT,
            opened_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL,
            event_count INTEGER NOT NULL DEFAULT 0,
            challenge_count INTEGER NOT NULL DEFAULT 0,
            block_count INTEGER NOT NULL DEFAULT 0,
            latest_action TEXT,
            latest_uri TEXT,
            latest_reason TEXT,
            dominant_route TEXT,
            focused_document_route TEXT,
            focused_api_route TEXT,
            distinct_routes INTEGER NOT NULL DEFAULT 0,
            repeated_ratio INTEGER NOT NULL DEFAULT 0,
            document_repeated_ratio INTEGER NOT NULL DEFAULT 0,
            api_repeated_ratio INTEGER NOT NULL DEFAULT 0,
            document_requests INTEGER NOT NULL DEFAULT 0,
            api_requests INTEGER NOT NULL DEFAULT 0,
            non_document_requests INTEGER NOT NULL DEFAULT 0,
            interval_jitter_ms INTEGER,
            session_span_secs INTEGER NOT NULL DEFAULT 0,
            flags_json TEXT NOT NULL DEFAULT '[]'
        );

        CREATE INDEX IF NOT EXISTS idx_behavior_sessions_identity
            ON behavior_sessions(identity);
        CREATE INDEX IF NOT EXISTS idx_behavior_sessions_last_seen_at
            ON behavior_sessions(last_seen_at);

        CREATE TABLE IF NOT EXISTS behavior_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            security_event_id INTEGER,
            identity TEXT NOT NULL,
            session_key TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            site_domain TEXT,
            http_method TEXT,
            uri TEXT,
            action TEXT,
            reason TEXT NOT NULL,
            score INTEGER NOT NULL DEFAULT 0,
            dominant_route TEXT,
            focused_document_route TEXT,
            focused_api_route TEXT,
            distinct_routes INTEGER NOT NULL DEFAULT 0,
            repeated_ratio INTEGER NOT NULL DEFAULT 0,
            document_repeated_ratio INTEGER NOT NULL DEFAULT 0,
            api_repeated_ratio INTEGER NOT NULL DEFAULT 0,
            document_requests INTEGER NOT NULL DEFAULT 0,
            api_requests INTEGER NOT NULL DEFAULT 0,
            non_document_requests INTEGER NOT NULL DEFAULT 0,
            interval_jitter_ms INTEGER,
            challenge_count_window INTEGER NOT NULL DEFAULT 0,
            session_span_secs INTEGER NOT NULL DEFAULT 0,
            flags_json TEXT NOT NULL DEFAULT '[]',
            created_at INTEGER NOT NULL,
            FOREIGN KEY(security_event_id) REFERENCES security_events(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_behavior_events_identity
            ON behavior_events(identity);
        CREATE INDEX IF NOT EXISTS idx_behavior_events_session_key
            ON behavior_events(session_key);
        CREATE INDEX IF NOT EXISTS idx_behavior_events_created_at
            ON behavior_events(created_at);

        CREATE TABLE IF NOT EXISTS ai_audit_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            generated_at INTEGER NOT NULL,
            provider_used TEXT NOT NULL,
            fallback_used INTEGER NOT NULL DEFAULT 0,
            risk_level TEXT NOT NULL,
            headline TEXT NOT NULL,
            report_json TEXT NOT NULL,
            feedback_status TEXT,
            feedback_notes TEXT,
            feedback_updated_at INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_ai_audit_reports_generated_at
            ON ai_audit_reports(generated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ai_audit_reports_feedback_status
            ON ai_audit_reports(feedback_status);
        CREATE TABLE IF NOT EXISTS ai_temp_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            status TEXT NOT NULL,
            source_report_id INTEGER,
            policy_key TEXT NOT NULL,
            title TEXT NOT NULL,
            policy_type TEXT NOT NULL,
            layer TEXT NOT NULL,
            scope_type TEXT NOT NULL,
            scope_value TEXT NOT NULL,
            action TEXT NOT NULL,
            operator TEXT NOT NULL,
            suggested_value TEXT NOT NULL,
            rationale TEXT NOT NULL,
            confidence INTEGER NOT NULL DEFAULT 0,
            auto_applied INTEGER NOT NULL DEFAULT 0,
            hit_count INTEGER NOT NULL DEFAULT 0,
            last_hit_at INTEGER,
            effect_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(policy_key, scope_type, scope_value, status)
        );

        CREATE INDEX IF NOT EXISTS idx_ai_temp_policies_expires_at
            ON ai_temp_policies(expires_at);
        CREATE INDEX IF NOT EXISTS idx_ai_temp_policies_status
            ON ai_temp_policies(status);
        CREATE INDEX IF NOT EXISTS idx_ai_temp_policies_scope
            ON ai_temp_policies(scope_type, scope_value);

        CREATE TABLE IF NOT EXISTS ai_route_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            last_observed_at INTEGER,
            site_id TEXT NOT NULL,
            route_pattern TEXT NOT NULL,
            match_mode TEXT NOT NULL DEFAULT 'exact',
            route_type TEXT NOT NULL DEFAULT 'unknown',
            sensitivity TEXT NOT NULL DEFAULT 'unknown',
            auth_required TEXT NOT NULL DEFAULT 'unknown',
            normal_traffic_pattern TEXT NOT NULL DEFAULT 'unknown',
            recommended_actions_json TEXT NOT NULL DEFAULT '[]',
            avoid_actions_json TEXT NOT NULL DEFAULT '[]',
            evidence_json TEXT NOT NULL DEFAULT '{}',
            confidence INTEGER NOT NULL DEFAULT 0,
            source TEXT NOT NULL DEFAULT 'ai_observed',
            status TEXT NOT NULL DEFAULT 'candidate',
            rationale TEXT NOT NULL DEFAULT '',
            reviewed_at INTEGER,
            UNIQUE(site_id, route_pattern, match_mode)
        );

        CREATE INDEX IF NOT EXISTS idx_ai_route_profiles_site_status
            ON ai_route_profiles(site_id, status);
        CREATE INDEX IF NOT EXISTS idx_ai_route_profiles_route
            ON ai_route_profiles(route_pattern, match_mode);
        CREATE INDEX IF NOT EXISTS idx_ai_route_profiles_updated_at
            ON ai_route_profiles(updated_at DESC);

        CREATE TABLE IF NOT EXISTS resource_sentinel_attack_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL UNIQUE,
            phase TEXT NOT NULL,
            started_at_ms INTEGER NOT NULL,
            ended_at_ms INTEGER,
            duration_ms INTEGER NOT NULL DEFAULT 0,
            peak_severity TEXT NOT NULL DEFAULT 'normal',
            peak_attack_score INTEGER NOT NULL DEFAULT 0,
            primary_pressure TEXT NOT NULL DEFAULT 'none',
            final_outcome TEXT NOT NULL DEFAULT 'idle',
            summary TEXT NOT NULL DEFAULT '',
            diagnosis_json TEXT NOT NULL DEFAULT '{}',
            lifecycle_json TEXT NOT NULL DEFAULT '{}',
            session_json TEXT NOT NULL DEFAULT '{}',
            top_clusters_json TEXT NOT NULL DEFAULT '[]',
            defense_effects_json TEXT NOT NULL DEFAULT '[]',
            decision_traces_json TEXT NOT NULL DEFAULT '[]',
            ingress_gap_json TEXT NOT NULL DEFAULT '{}',
            resource_pressure_json TEXT NOT NULL DEFAULT '{}',
            migrations_json TEXT NOT NULL DEFAULT '[]',
            report_json TEXT,
            pre_admission_rejections INTEGER NOT NULL DEFAULT 0,
            aggregated_events INTEGER NOT NULL DEFAULT 0,
            defense_actions INTEGER NOT NULL DEFAULT 0,
            defense_extensions INTEGER NOT NULL DEFAULT 0,
            defense_relaxations INTEGER NOT NULL DEFAULT 0,
            audit_event_count INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_resource_sentinel_attack_sessions_updated_at
            ON resource_sentinel_attack_sessions(updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_resource_sentinel_attack_sessions_phase
            ON resource_sentinel_attack_sessions(phase, updated_at DESC);

        CREATE TABLE IF NOT EXISTS resource_sentinel_defense_memory (
            attack_type TEXT PRIMARY KEY,
            preferred_action TEXT NOT NULL,
            effective_score INTEGER NOT NULL DEFAULT 0,
            ineffective_score INTEGER NOT NULL DEFAULT 0,
            weak_score INTEGER NOT NULL DEFAULT 0,
            harmful_score INTEGER NOT NULL DEFAULT 0,
            last_outcome TEXT NOT NULL DEFAULT 'unknown',
            last_rejection_delta INTEGER NOT NULL DEFAULT 0,
            last_score_delta INTEGER NOT NULL DEFAULT 0,
            last_seen_ms INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_resource_sentinel_defense_memory_updated_at
            ON resource_sentinel_defense_memory(updated_at DESC);
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            enabled INTEGER NOT NULL,
            layer TEXT NOT NULL,
            pattern TEXT NOT NULL,
            action TEXT NOT NULL,
            severity TEXT NOT NULL,
            plugin_template_id TEXT,
            response_template_json TEXT,
            updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_rules_updated_at
            ON rules(updated_at);

        CREATE TABLE IF NOT EXISTS rule_action_plugins (
            plugin_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            installed_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rule_action_templates (
            template_id TEXT PRIMARY KEY,
            plugin_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            layer TEXT NOT NULL,
            action TEXT NOT NULL,
            pattern TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL,
            response_template_json TEXT NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(plugin_id) REFERENCES rule_action_plugins(plugin_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_rule_action_templates_plugin_id
            ON rule_action_templates(plugin_id);

        CREATE TABLE IF NOT EXISTS action_idea_overrides (
            idea_id TEXT PRIMARY KEY,
            title TEXT,
            status_code INTEGER,
            content_type TEXT,
            response_content TEXT,
            body_file_path TEXT,
            uploaded_file_name TEXT,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS app_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            config_json TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS safeline_site_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            safeline_site_id TEXT NOT NULL UNIQUE,
            safeline_site_name TEXT NOT NULL,
            safeline_site_domain TEXT NOT NULL,
            local_alias TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            is_primary INTEGER NOT NULL DEFAULT 0,
            notes TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_safeline_site_mappings_updated_at
            ON safeline_site_mappings(updated_at);

        CREATE TABLE IF NOT EXISTS safeline_cached_sites (
            remote_site_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            domain TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT '',
            enabled INTEGER,
            server_names_json TEXT NOT NULL DEFAULT '[]',
            ports_json TEXT NOT NULL DEFAULT '[]',
            ssl_ports_json TEXT NOT NULL DEFAULT '[]',
            upstreams_json TEXT NOT NULL DEFAULT '[]',
            ssl_enabled INTEGER NOT NULL DEFAULT 0,
            cert_id INTEGER,
            cert_type INTEGER,
            cert_filename TEXT,
            key_filename TEXT,
            health_check INTEGER,
            raw_json TEXT NOT NULL DEFAULT '{}',
            updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_safeline_cached_sites_updated_at
            ON safeline_cached_sites(updated_at);

        CREATE TABLE IF NOT EXISTS local_certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            domains_json TEXT NOT NULL DEFAULT '[]',
            issuer TEXT NOT NULL DEFAULT '',
            valid_from INTEGER,
            valid_to INTEGER,
            source_type TEXT NOT NULL DEFAULT 'manual',
            provider_remote_id TEXT,
            provider_remote_domains_json TEXT NOT NULL DEFAULT '[]',
            last_remote_fingerprint TEXT,
            sync_status TEXT NOT NULL DEFAULT 'idle',
            sync_message TEXT NOT NULL DEFAULT '',
            auto_sync_enabled INTEGER NOT NULL DEFAULT 0,
            trusted INTEGER NOT NULL DEFAULT 0,
            expired INTEGER NOT NULL DEFAULT 0,
            notes TEXT NOT NULL DEFAULT '',
            last_synced_at INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_local_certificates_updated_at
            ON local_certificates(updated_at);
        CREATE INDEX IF NOT EXISTS idx_local_certificates_provider_remote_id
            ON local_certificates(provider_remote_id);

        CREATE TABLE IF NOT EXISTS local_certificate_secrets (
            certificate_id INTEGER PRIMARY KEY,
            certificate_pem TEXT NOT NULL DEFAULT '',
            private_key_pem TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(certificate_id) REFERENCES local_certificates(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS local_sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            primary_hostname TEXT NOT NULL,
            hostnames_json TEXT NOT NULL DEFAULT '[]',
            listen_ports_json TEXT NOT NULL DEFAULT '[]',
            upstreams_json TEXT NOT NULL DEFAULT '[]',
            safeline_intercept_json TEXT,
            priority TEXT NOT NULL DEFAULT 'normal',
            overload_policy TEXT NOT NULL DEFAULT 'inherit',
            reserved_concurrency INTEGER NOT NULL DEFAULT 0,
            reserved_rps INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            tls_enabled INTEGER NOT NULL DEFAULT 0,
            local_certificate_id INTEGER,
            source TEXT NOT NULL DEFAULT 'manual',
            sync_mode TEXT NOT NULL DEFAULT 'manual',
            notes TEXT NOT NULL DEFAULT '',
            last_synced_at INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(local_certificate_id) REFERENCES local_certificates(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_local_sites_updated_at
            ON local_sites(updated_at);
        CREATE INDEX IF NOT EXISTS idx_local_sites_primary_hostname
            ON local_sites(primary_hostname);
        CREATE INDEX IF NOT EXISTS idx_local_sites_local_certificate_id
            ON local_sites(local_certificate_id);

        CREATE TABLE IF NOT EXISTS site_sync_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            local_site_id INTEGER NOT NULL,
            provider TEXT NOT NULL,
            remote_site_id TEXT NOT NULL,
            remote_site_name TEXT NOT NULL DEFAULT '',
            remote_cert_id TEXT,
            sync_mode TEXT NOT NULL DEFAULT 'remote_to_local',
            last_local_hash TEXT,
            last_remote_hash TEXT,
            last_error TEXT,
            last_synced_at INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(local_site_id) REFERENCES local_sites(id) ON DELETE CASCADE,
            UNIQUE(provider, local_site_id),
            UNIQUE(provider, remote_site_id)
        );

        CREATE INDEX IF NOT EXISTS idx_site_sync_links_local_site_id
            ON site_sync_links(local_site_id);
        CREATE INDEX IF NOT EXISTS idx_site_sync_links_provider_remote_site_id
            ON site_sync_links(provider, remote_site_id);

        CREATE TABLE IF NOT EXISTS safeline_event_dedup (
            fingerprint TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL,
            imported_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_safeline_event_dedup_created_at
            ON safeline_event_dedup(created_at);

        CREATE TABLE IF NOT EXISTS safeline_sync_state (
            resource TEXT PRIMARY KEY,
            last_cursor INTEGER,
            last_success_at INTEGER,
            last_imported_count INTEGER NOT NULL DEFAULT 0,
            last_skipped_count INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS safeline_blocked_ip_sync_dedup (
            fingerprint TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            synced_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS safeline_blocked_ip_pull_dedup (
            fingerprint TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            synced_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS bot_ip_cache (
            provider TEXT PRIMARY KEY,
            ranges_json TEXT NOT NULL DEFAULT '[]',
            last_refresh_at INTEGER,
            last_success_at INTEGER,
            last_error TEXT,
            updated_at INTEGER NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    for column in [
        ("security_events", "handled", "INTEGER NOT NULL DEFAULT 0"),
        ("security_events", "handled_at", "INTEGER"),
        ("security_events", "provider", "TEXT"),
        ("security_events", "provider_event_id", "TEXT"),
        ("security_events", "provider_site_id", "TEXT"),
        ("security_events", "provider_site_name", "TEXT"),
        ("security_events", "provider_site_domain", "TEXT"),
        ("security_events", "details_json", "TEXT"),
        ("blocked_ips", "provider", "TEXT"),
        ("blocked_ips", "provider_remote_id", "TEXT"),
        ("rules", "plugin_template_id", "TEXT"),
        ("rules", "response_template_json", "TEXT"),
        (
            "rule_action_plugins",
            "enabled",
            "INTEGER NOT NULL DEFAULT 1",
        ),
        ("local_sites", "safeline_intercept_json", "TEXT"),
        ("local_sites", "priority", "TEXT NOT NULL DEFAULT 'normal'"),
        (
            "local_sites",
            "overload_policy",
            "TEXT NOT NULL DEFAULT 'inherit'",
        ),
        (
            "local_sites",
            "reserved_concurrency",
            "INTEGER NOT NULL DEFAULT 0",
        ),
        ("local_sites", "reserved_rps", "INTEGER NOT NULL DEFAULT 0"),
        (
            "local_certificates",
            "provider_remote_domains_json",
            "TEXT NOT NULL DEFAULT '[]'",
        ),
        ("local_certificates", "last_remote_fingerprint", "TEXT"),
        (
            "local_certificates",
            "sync_status",
            "TEXT NOT NULL DEFAULT 'idle'",
        ),
        (
            "local_certificates",
            "sync_message",
            "TEXT NOT NULL DEFAULT ''",
        ),
        (
            "local_certificates",
            "auto_sync_enabled",
            "INTEGER NOT NULL DEFAULT 0",
        ),
        ("action_idea_overrides", "status_code", "INTEGER"),
        ("action_idea_overrides", "content_type", "TEXT"),
        ("action_idea_overrides", "body_file_path", "TEXT"),
        ("action_idea_overrides", "uploaded_file_name", "TEXT"),
        (
            "ai_route_profiles",
            "evidence_json",
            "TEXT NOT NULL DEFAULT '{}'",
        ),
    ] {
        add_column_if_missing(pool, column.0, column.1, column.2).await?;
    }
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_security_events_provider_site_id ON security_events(provider_site_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_blocked_ips_provider ON blocked_ips(provider)")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_security_events_action_created_at ON security_events(action, created_at DESC)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_security_events_handled_created_at ON security_events(handled, created_at DESC)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_blocked_ips_provider_blocked_at ON blocked_ips(provider, blocked_at DESC)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_blocked_ips_provider_ip_expires_at ON blocked_ips(provider, ip, expires_at DESC)",
    )
    .execute(pool)
    .await?;

    Ok(())
}

async fn add_column_if_missing(
    pool: &SqlitePool,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    if column_exists(pool, table, column).await? {
        return Ok(());
    }
    sqlx::query(&format!(
        "ALTER TABLE {table} ADD COLUMN {column} {definition}"
    ))
    .execute(pool)
    .await?;
    Ok(())
}

async fn column_exists(pool: &SqlitePool, table: &str, column: &str) -> Result<bool> {
    debug_assert!(is_sql_identifier(table));
    debug_assert!(is_sql_identifier(column));
    let count: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = ?"
    ))
    .bind(column)
    .fetch_one(pool)
    .await?;
    Ok(count > 0)
}

fn is_sql_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}
