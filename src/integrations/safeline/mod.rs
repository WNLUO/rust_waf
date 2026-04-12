use serde::Serialize;
use serde_json::Value;

mod api_client;
mod payload;
mod sync_helpers;

pub use api_client::{
    create_certificate, delete_blocked_ip, list_blocked_ips, list_certificates,
    list_security_events, list_sites, load_certificate, probe, push_blocked_ip, update_certificate,
    upsert_site,
};

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineProbeResult {
    pub status: String,
    pub message: String,
    pub openapi_doc_reachable: bool,
    pub openapi_doc_status: Option<u16>,
    pub authenticated: bool,
    pub auth_probe_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineSiteSummary {
    pub id: String,
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
    pub raw: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineSecurityEventSummary {
    pub provider_site_id: Option<String>,
    pub provider_site_name: Option<String>,
    pub provider_site_domain: Option<String>,
    pub action: String,
    pub reason: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub source_port: i64,
    pub dest_port: i64,
    pub protocol: String,
    pub http_method: Option<String>,
    pub uri: Option<String>,
    pub http_version: Option<String>,
    pub created_at: i64,
    pub raw: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineBlockedIpSyncSummary {
    pub ip: String,
    pub accepted: bool,
    pub status_code: u16,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineBlockedIpDeleteSummary {
    pub ip: String,
    pub accepted: bool,
    pub status_code: u16,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineBlockedIpSummary {
    pub remote_id: Option<String>,
    pub ip: String,
    pub reason: String,
    pub blocked_at: i64,
    pub expires_at: i64,
    pub raw: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineCertificateSummary {
    pub id: String,
    pub domains: Vec<String>,
    pub issuer: String,
    pub trusted: bool,
    pub revoked: bool,
    pub expired: bool,
    pub cert_type: Option<i64>,
    pub valid_from: Option<i64>,
    pub valid_to: Option<i64>,
    pub related_sites: Vec<String>,
    pub raw: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineCertificateDetail {
    pub id: String,
    pub domains: Vec<String>,
    pub cert_type: Option<i64>,
    pub certificate_pem: Option<String>,
    pub private_key_pem: Option<String>,
    pub raw: Value,
}

#[derive(Debug, Clone)]
pub struct SafeLineCertificateUpsert {
    pub domains: Vec<String>,
    pub certificate_pem: String,
    pub private_key_pem: String,
}

#[derive(Debug, Clone)]
pub struct SafeLineSiteUpsert {
    pub remote_id: Option<String>,
    pub name: String,
    pub server_names: Vec<String>,
    pub ports: Vec<String>,
    pub upstreams: Vec<String>,
    pub enabled: bool,
    pub health_check: bool,
    pub cert_id: Option<i64>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineCertificateWriteSummary {
    pub remote_id: Option<String>,
    pub accepted: bool,
    pub status_code: u16,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineSiteWriteSummary {
    pub remote_id: Option<String>,
    pub accepted: bool,
    pub status_code: u16,
    pub message: String,
}
