#[derive(Debug, Clone)]
pub struct SafeLineSiteMappingUpsert {
    pub safeline_site_id: String,
    pub safeline_site_name: String,
    pub safeline_site_domain: String,
    pub local_alias: String,
    pub enabled: bool,
    pub is_primary: bool,
    pub notes: String,
}

#[derive(Debug, Clone)]
pub struct SafeLineCachedSiteUpsert {
    pub remote_site_id: String,
    pub name: String,
    pub domain: String,
    pub status: String,
    pub enabled: Option<bool>,
    pub server_names: Vec<String>,
    pub ports: Vec<String>,
    pub ssl_ports: Vec<String>,
    pub upstreams: Vec<String>,
    pub ssl_enabled: bool,
    pub cert_id: Option<i64>,
    pub cert_type: Option<i64>,
    pub cert_filename: Option<String>,
    pub key_filename: Option<String>,
    pub health_check: Option<bool>,
    pub raw_json: String,
}

#[derive(Debug, Clone)]
pub struct LocalSiteUpsert {
    pub name: String,
    pub primary_hostname: String,
    pub hostnames: Vec<String>,
    pub listen_ports: Vec<String>,
    pub upstreams: Vec<String>,
    pub safeline_intercept: Option<crate::config::l7::SafeLineInterceptConfig>,
    pub enabled: bool,
    pub tls_enabled: bool,
    pub local_certificate_id: Option<i64>,
    pub source: String,
    pub sync_mode: String,
    pub notes: String,
    pub last_synced_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct LocalCertificateUpsert {
    pub name: String,
    pub domains: Vec<String>,
    pub issuer: String,
    pub valid_from: Option<i64>,
    pub valid_to: Option<i64>,
    pub source_type: String,
    pub provider_remote_id: Option<String>,
    pub provider_remote_domains: Vec<String>,
    pub last_remote_fingerprint: Option<String>,
    pub sync_status: String,
    pub sync_message: String,
    pub auto_sync_enabled: bool,
    pub trusted: bool,
    pub expired: bool,
    pub notes: String,
    pub last_synced_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct SiteSyncLinkUpsert {
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
}

#[derive(Debug, Clone, Default)]
pub struct SafeLineImportResult {
    pub imported: usize,
    pub skipped: usize,
    pub last_cursor: Option<i64>,
}
