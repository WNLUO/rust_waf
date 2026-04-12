pub struct SafeLineSitesResponse {
    pub(crate) total: u32,
    pub(crate) cached_at: Option<i64>,
    pub(crate) sites: Vec<SafeLineSiteResponse>,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSiteResponse {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) domain: String,
    pub(crate) status: String,
    pub(crate) enabled: Option<bool>,
    pub(crate) server_names: Vec<String>,
    pub(crate) ports: Vec<String>,
    pub(crate) ssl_ports: Vec<String>,
    pub(crate) upstreams: Vec<String>,
    pub(crate) ssl_enabled: bool,
    pub(crate) cert_id: Option<i64>,
    pub(crate) cert_type: Option<i64>,
    pub(crate) cert_filename: Option<String>,
    pub(crate) key_filename: Option<String>,
    pub(crate) health_check: Option<bool>,
    pub(crate) raw: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct SafeLineMappingsResponse {
    pub(crate) total: u32,
    pub(crate) mappings: Vec<SafeLineMappingResponse>,
}

#[derive(Debug, Serialize)]
pub struct SafeLineMappingResponse {
    pub(crate) id: i64,
    pub(crate) safeline_site_id: String,
    pub(crate) safeline_site_name: String,
    pub(crate) safeline_site_domain: String,
    pub(crate) local_alias: String,
    pub(crate) enabled: bool,
    pub(crate) is_primary: bool,
    pub(crate) notes: String,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct SafeLineMappingsUpdateRequest {
    pub(crate) mappings: Vec<SafeLineMappingUpsertRequest>,
}

#[derive(Debug, Deserialize)]
pub struct SafeLineMappingUpsertRequest {
    pub(crate) safeline_site_id: String,
    pub(crate) safeline_site_name: String,
    pub(crate) safeline_site_domain: String,
    pub(crate) local_alias: String,
    pub(crate) enabled: bool,
    pub(crate) is_primary: bool,
    pub(crate) notes: String,
}

#[derive(Debug, Serialize)]
pub struct LocalSitesResponse {
    pub(crate) total: u32,
    pub(crate) sites: Vec<LocalSiteResponse>,
}

#[derive(Debug, Serialize)]
pub struct GlobalEntryConfigResponse {
    pub(crate) http_port: String,
    pub(crate) https_port: String,
}

#[derive(Debug, Deserialize)]
pub struct GlobalEntryConfigUpdateRequest {
    pub(crate) http_port: String,
    pub(crate) https_port: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderOperationPayload {
    pub(crate) scope: String,
    pub(crate) action: String,
    pub(crate) header: String,
    pub(crate) value: String,
}

#[derive(Debug, Serialize)]
pub struct GlobalSettingsResponse {
    pub(crate) enable_http1_0: bool,
    pub(crate) http2_enabled: bool,
    pub(crate) http3_enabled: bool,
    pub(crate) source_ip_strategy: String,
    pub(crate) custom_source_ip_header: String,
    pub(crate) trusted_proxy_cidrs: Vec<String>,
    pub(crate) http_to_https_redirect: bool,
    pub(crate) enable_hsts: bool,
    pub(crate) rewrite_host_enabled: bool,
    pub(crate) rewrite_host_value: String,
    pub(crate) add_x_forwarded_headers: bool,
    pub(crate) rewrite_x_forwarded_for: bool,
    pub(crate) support_gzip: bool,
    pub(crate) support_brotli: bool,
    pub(crate) support_sse: bool,
    pub(crate) enable_ntlm: bool,
    pub(crate) fallback_self_signed_certificate: bool,
    pub(crate) ssl_protocols: Vec<String>,
    pub(crate) ssl_ciphers: String,
    pub(crate) header_operations: Vec<HeaderOperationPayload>,
}

#[derive(Debug, Deserialize)]
pub struct GlobalSettingsUpdateRequest {
    pub(crate) enable_http1_0: bool,
    pub(crate) http2_enabled: bool,
    pub(crate) http3_enabled: bool,
    pub(crate) source_ip_strategy: String,
    pub(crate) custom_source_ip_header: String,
    pub(crate) trusted_proxy_cidrs: Vec<String>,
    pub(crate) http_to_https_redirect: bool,
    pub(crate) enable_hsts: bool,
    pub(crate) rewrite_host_enabled: bool,
    pub(crate) rewrite_host_value: String,
    pub(crate) add_x_forwarded_headers: bool,
    pub(crate) rewrite_x_forwarded_for: bool,
    pub(crate) support_gzip: bool,
    pub(crate) support_brotli: bool,
    pub(crate) support_sse: bool,
    pub(crate) enable_ntlm: bool,
    pub(crate) fallback_self_signed_certificate: bool,
    pub(crate) ssl_protocols: Vec<String>,
    pub(crate) ssl_ciphers: String,
    #[serde(default)]
    pub(crate) header_operations: Vec<HeaderOperationPayload>,
}

#[derive(Debug, Serialize)]
pub struct LocalSiteResponse {
    pub(crate) id: i64,
    pub(crate) name: String,
    pub(crate) primary_hostname: String,
    pub(crate) hostnames: Vec<String>,
    pub(crate) listen_ports: Vec<String>,
    pub(crate) upstreams: Vec<String>,
    pub(crate) safeline_intercept: Option<SafeLineInterceptConfigResponse>,
    pub(crate) enabled: bool,
    pub(crate) tls_enabled: bool,
    pub(crate) local_certificate_id: Option<i64>,
    pub(crate) source: String,
    pub(crate) sync_mode: String,
    pub(crate) notes: String,
    pub(crate) last_synced_at: Option<i64>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct LocalSiteUpsertRequest {
    pub(crate) name: String,
    pub(crate) primary_hostname: String,
    pub(crate) hostnames: Vec<String>,
    #[allow(dead_code)]
    pub(crate) listen_ports: Vec<String>,
    pub(crate) upstreams: Vec<String>,
    #[serde(default)]
    pub(crate) safeline_intercept: Option<SafeLineInterceptConfigRequest>,
    pub(crate) enabled: bool,
    pub(crate) tls_enabled: bool,
    pub(crate) local_certificate_id: Option<i64>,
    pub(crate) source: String,
    pub(crate) sync_mode: String,
    pub(crate) notes: String,
    pub(crate) last_synced_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct LocalCertificatesResponse {
    pub(crate) total: u32,
    pub(crate) certificates: Vec<LocalCertificateResponse>,
}

#[derive(Debug, Serialize)]
pub struct LocalCertificateResponse {
    pub(crate) id: i64,
    pub(crate) name: String,
    pub(crate) domains: Vec<String>,
    pub(crate) issuer: String,
    pub(crate) valid_from: Option<i64>,
    pub(crate) valid_to: Option<i64>,
    pub(crate) source_type: String,
    pub(crate) provider_remote_id: Option<String>,
    pub(crate) provider_remote_domains: Vec<String>,
    pub(crate) last_remote_fingerprint: Option<String>,
    pub(crate) sync_status: String,
    pub(crate) sync_message: String,
    pub(crate) auto_sync_enabled: bool,
    pub(crate) trusted: bool,
    pub(crate) expired: bool,
    pub(crate) notes: String,
    pub(crate) last_synced_at: Option<i64>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    pub(crate) certificate_pem: Option<String>,
    pub(crate) private_key_pem: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LocalCertificateUpsertRequest {
    pub(crate) name: String,
    pub(crate) domains: Vec<String>,
    pub(crate) issuer: String,
    pub(crate) valid_from: Option<i64>,
    pub(crate) valid_to: Option<i64>,
    pub(crate) source_type: String,
    pub(crate) provider_remote_id: Option<String>,
    #[serde(default)]
    pub(crate) provider_remote_domains: Vec<String>,
    #[serde(default)]
    pub(crate) last_remote_fingerprint: Option<String>,
    #[serde(default = "default_certificate_sync_status")]
    pub(crate) sync_status: String,
    #[serde(default)]
    pub(crate) sync_message: String,
    #[serde(default)]
    pub(crate) auto_sync_enabled: bool,
    pub(crate) trusted: bool,
    pub(crate) expired: bool,
    pub(crate) notes: String,
    pub(crate) last_synced_at: Option<i64>,
    pub(crate) certificate_pem: Option<String>,
    pub(crate) private_key_pem: Option<String>,
}

fn default_certificate_sync_status() -> String {
    "idle".to_string()
}

#[derive(Debug, Deserialize)]
pub struct GeneratedLocalCertificateRequest {
    pub(crate) name: Option<String>,
    pub(crate) domains: Vec<String>,
    pub(crate) notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LocalCertificateRemoteBindRequest {
    pub(crate) remote_certificate_id: String,
    #[serde(default)]
    pub(crate) remote_domains: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SiteSyncLinksResponse {
    pub(crate) total: u32,
    pub(crate) links: Vec<SiteSyncLinkResponse>,
}

#[derive(Debug, Serialize)]
pub struct SiteSyncLinkResponse {
    pub(crate) id: i64,
    pub(crate) local_site_id: i64,
    pub(crate) provider: String,
    pub(crate) remote_site_id: String,
    pub(crate) remote_site_name: String,
    pub(crate) remote_cert_id: Option<String>,
    pub(crate) sync_mode: String,
    pub(crate) last_local_hash: Option<String>,
    pub(crate) last_remote_hash: Option<String>,
    pub(crate) last_error: Option<String>,
    pub(crate) last_synced_at: Option<i64>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct SiteSyncLinkUpsertRequest {
    pub(crate) local_site_id: i64,
    pub(crate) provider: String,
    pub(crate) remote_site_id: String,
    pub(crate) remote_site_name: String,
    pub(crate) remote_cert_id: Option<String>,
    pub(crate) sync_mode: String,
    pub(crate) last_local_hash: Option<String>,
    pub(crate) last_remote_hash: Option<String>,
    pub(crate) last_error: Option<String>,
    pub(crate) last_synced_at: Option<i64>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone)]
pub struct SafeLineSitePullOptionsRequest {
    #[serde(default = "default_true")]
    pub(crate) name: bool,
    #[serde(default = "default_true")]
    pub(crate) primary_hostname: bool,
    #[serde(default = "default_true")]
    pub(crate) hostnames: bool,
    #[serde(default = "default_true")]
    pub(crate) listen_ports: bool,
    #[serde(default = "default_true")]
    pub(crate) upstreams: bool,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
}

impl Default for SafeLineSitePullOptionsRequest {
    fn default() -> Self {
        Self {
            name: true,
            primary_hostname: true,
            hostnames: true,
            listen_ports: true,
            upstreams: true,
            enabled: true,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct SafeLineSitePullRequest {
    #[serde(default)]
    pub(crate) options: SafeLineSitePullOptionsRequest,
}

#[derive(Debug, Clone)]
pub(super) struct LocalCertificateSecretDraft {
    pub(super) certificate_pem: String,
    pub(super) private_key_pem: String,
}

#[derive(Debug, Clone)]
pub(super) struct GeneratedLocalCertificateDraft {
    pub(super) certificate: crate::storage::LocalCertificateUpsert,
    pub(super) secret: LocalCertificateSecretDraft,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSitesPullResponse {
    pub(crate) success: bool,
    pub(crate) imported_sites: u32,
    pub(crate) updated_sites: u32,
    pub(crate) imported_certificates: u32,
    pub(crate) updated_certificates: u32,
    pub(crate) linked_sites: u32,
    pub(crate) skipped_sites: u32,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSitesPushResponse {
    pub(crate) success: bool,
    pub(crate) created_sites: u32,
    pub(crate) updated_sites: u32,
    pub(crate) created_certificates: u32,
    pub(crate) reused_certificates: u32,
    pub(crate) skipped_sites: u32,
    pub(crate) failed_sites: u32,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
pub struct SafeLineCertificatesPullResponse {
    pub(crate) success: bool,
    pub(crate) imported_certificates: u32,
    pub(crate) updated_certificates: u32,
    pub(crate) skipped_certificates: u32,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
pub struct SafeLineCertificateMatchCandidateResponse {
    pub(crate) id: String,
    pub(crate) domains: Vec<String>,
    pub(crate) issuer: String,
    pub(crate) valid_to: Option<i64>,
    pub(crate) related_sites: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SafeLineCertificateMatchPreviewResponse {
    pub(crate) success: bool,
    pub(crate) status: String,
    pub(crate) strategy: String,
    pub(crate) local_certificate_id: i64,
    pub(crate) local_domains: Vec<String>,
    pub(crate) linked_remote_id: Option<String>,
    pub(crate) matched_remote_id: Option<String>,
    pub(crate) message: String,
    pub(crate) candidates: Vec<SafeLineCertificateMatchCandidateResponse>,
}

#[derive(Debug, Serialize)]
pub struct SafeLineEventSyncResponse {
    pub(crate) success: bool,
    pub(crate) imported: u32,
    pub(crate) skipped: u32,
    pub(crate) last_cursor: Option<i64>,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSyncStateResponse {
    pub(crate) resource: String,
    pub(crate) last_cursor: Option<i64>,
    pub(crate) last_success_at: Option<i64>,
    pub(crate) last_imported_count: u32,
    pub(crate) last_skipped_count: u32,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSyncOverviewResponse {
    pub(crate) events: Option<SafeLineSyncStateResponse>,
    pub(crate) blocked_ips_push: Option<SafeLineSyncStateResponse>,
    pub(crate) blocked_ips_pull: Option<SafeLineSyncStateResponse>,
    pub(crate) blocked_ips_delete: Option<SafeLineSyncStateResponse>,
}

#[derive(Debug, Serialize)]
pub struct SafeLineBlocklistSyncResponse {
    pub(crate) success: bool,
    pub(crate) synced: u32,
    pub(crate) skipped: u32,
    pub(crate) failed: u32,
    pub(crate) last_cursor: Option<i64>,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
pub struct SafeLineBlocklistPullResponse {
    pub(crate) success: bool,
    pub(crate) imported: u32,
    pub(crate) skipped: u32,
    pub(crate) last_cursor: Option<i64>,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
