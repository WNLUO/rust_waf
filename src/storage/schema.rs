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
        "#,
    )
    .execute(pool)
    .await?;

    if let Err(err) =
        sqlx::query("ALTER TABLE security_events ADD COLUMN handled INTEGER NOT NULL DEFAULT 0")
            .execute(pool)
            .await
    {
        if !err.to_string().contains("duplicate column name") {
            return Err(err.into());
        }
    }
    if let Err(err) = sqlx::query("ALTER TABLE security_events ADD COLUMN handled_at INTEGER")
        .execute(pool)
        .await
    {
        if !err.to_string().contains("duplicate column name") {
            return Err(err.into());
        }
    }
    for statement in [
        "ALTER TABLE security_events ADD COLUMN provider TEXT",
        "ALTER TABLE security_events ADD COLUMN provider_event_id TEXT",
        "ALTER TABLE security_events ADD COLUMN provider_site_id TEXT",
        "ALTER TABLE security_events ADD COLUMN provider_site_name TEXT",
        "ALTER TABLE security_events ADD COLUMN provider_site_domain TEXT",
    ] {
        if let Err(err) = sqlx::query(statement).execute(pool).await {
            if !err.to_string().contains("duplicate column name") {
                return Err(err.into());
            }
        }
    }
    for statement in [
        "ALTER TABLE blocked_ips ADD COLUMN provider TEXT",
        "ALTER TABLE blocked_ips ADD COLUMN provider_remote_id TEXT",
        "ALTER TABLE rules ADD COLUMN plugin_template_id TEXT",
        "ALTER TABLE rules ADD COLUMN response_template_json TEXT",
        "ALTER TABLE rule_action_plugins ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1",
    ] {
        if let Err(err) = sqlx::query(statement).execute(pool).await {
            if !err.to_string().contains("duplicate column name") {
                return Err(err.into());
            }
        }
    }
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_security_events_provider_site_id ON security_events(provider_site_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_blocked_ips_provider ON blocked_ips(provider)")
        .execute(pool)
        .await?;

    Ok(())
}
