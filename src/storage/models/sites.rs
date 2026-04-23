#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SafeLineSiteMappingEntry {
    pub id: i64,
    pub safeline_site_id: String,
    pub safeline_site_name: String,
    pub safeline_site_domain: String,
    pub local_alias: String,
    pub enabled: bool,
    pub is_primary: bool,
    pub notes: String,
    pub updated_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SafeLineCachedSiteEntry {
    pub remote_site_id: String,
    pub name: String,
    pub domain: String,
    pub status: String,
    pub enabled: Option<bool>,
    pub server_names_json: String,
    pub ports_json: String,
    pub ssl_ports_json: String,
    pub upstreams_json: String,
    pub ssl_enabled: bool,
    pub cert_id: Option<i64>,
    pub cert_type: Option<i64>,
    pub cert_filename: Option<String>,
    pub key_filename: Option<String>,
    pub health_check: Option<bool>,
    pub raw_json: String,
    pub updated_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LocalSiteEntry {
    pub id: i64,
    pub name: String,
    pub primary_hostname: String,
    pub hostnames_json: String,
    pub listen_ports_json: String,
    pub upstreams_json: String,
    pub safeline_intercept_json: Option<String>,
    pub priority: String,
    pub overload_policy: String,
    pub reserved_concurrency: i64,
    pub reserved_rps: i64,
    pub enabled: bool,
    pub tls_enabled: bool,
    pub local_certificate_id: Option<i64>,
    pub source: String,
    pub sync_mode: String,
    pub notes: String,
    pub last_synced_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LocalCertificateEntry {
    pub id: i64,
    pub name: String,
    pub domains_json: String,
    pub issuer: String,
    pub valid_from: Option<i64>,
    pub valid_to: Option<i64>,
    pub source_type: String,
    pub provider_remote_id: Option<String>,
    pub provider_remote_domains_json: String,
    pub last_remote_fingerprint: Option<String>,
    pub sync_status: String,
    pub sync_message: String,
    pub auto_sync_enabled: bool,
    pub trusted: bool,
    pub expired: bool,
    pub notes: String,
    pub last_synced_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LocalCertificateSecretEntry {
    pub certificate_id: i64,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub updated_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SiteSyncLinkEntry {
    pub id: i64,
    pub local_site_id: i64,
    pub provider: String,
    pub remote_site_id: String,
    pub remote_site_name: String,
    pub remote_cert_id: Option<String>,
    pub sync_mode: String,
    pub last_local_hash: Option<String>,
    pub last_remote_hash: Option<String>,
    pub last_error: Option<String>,
    pub last_synced_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SafeLineSyncStateEntry {
    pub resource: String,
    pub last_cursor: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_imported_count: i64,
    pub last_skipped_count: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct SafeLineBlocklistSyncResult {
    pub synced: usize,
    pub skipped: usize,
    pub failed: usize,
    pub last_cursor: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct SafeLineBlocklistPullResult {
    pub imported: usize,
    pub skipped: usize,
    pub last_cursor: Option<i64>,
}
