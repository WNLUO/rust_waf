use super::payload::{
    extract_blocked_ips, extract_certificates, extract_security_events, extract_sites,
    parse_certificate_detail,
};
use super::sync_helpers::{
    body_or_status, build_site_upsert_payload, candidate_paths, configured_ip_group_ids,
    extract_write_response_id_from_body, format_failure, normalized_or_default,
    open_ipgroup_action_paths, DEFAULT_BLOCKLIST_PATH, OPEN_BLOCKLIST_APPEND_SUFFIX,
    OPEN_BLOCKLIST_REMOVE_SUFFIX,
};
use super::{
    SafeLineBlockedIpDeleteSummary, SafeLineBlockedIpSummary, SafeLineBlockedIpSyncSummary,
    SafeLineCertificateDetail, SafeLineCertificateSummary, SafeLineCertificateUpsert,
    SafeLineCertificateWriteSummary, SafeLineProbeResult, SafeLineSecurityEventSummary,
    SafeLineSiteSummary, SafeLineSiteUpsert, SafeLineSiteWriteSummary,
};
use crate::config::SafeLineConfig;
use crate::storage::BlockedIpEntry;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use std::process::{Command, Stdio};
use std::time::Duration;

mod auth;
mod blocklist;
mod certificates;
mod client;
mod probe;
mod sites;

pub use self::blocklist::{delete_blocked_ip, list_blocked_ips, push_blocked_ip};
pub use self::certificates::{
    create_certificate, list_certificates, load_certificate, update_certificate,
};
pub use self::probe::{list_security_events, probe};
pub use self::sites::{list_sites, upsert_site};

const DEFAULT_OPENAPI_DOC_PATH: &str = "/openapi_doc/";
const DEFAULT_AUTH_PROBE_PATH: &str = "/api/open/system/key";
const LEGACY_AUTH_PROBE_PATH: &str = "/api/IPGroupAPI";
const DEFAULT_SITE_LIST_PATH: &str = "/api/open/site";
const LEGACY_SITE_LIST_PATH: &str = "/api/WebsiteAPI";
const DEFAULT_EVENT_LIST_PATH: &str = "/api/open/records";
const LEGACY_EVENT_LIST_PATH: &str = "/api/AttackLogAPI";
const LEGACY_BLOCKLIST_PATH: &str = "/api/IPGroupAPI";
const DEFAULT_CERT_PATH: &str = "/api/open/cert";
const LOGIN_AES_KEY_PATH: &str = "/api/open/system/key";
const LOGIN_CSRF_PATH: &str = "/api/open/auth/csrf";
const LOGIN_PATH: &str = "/api/open/auth/login";

#[derive(Debug, Clone)]
struct AuthContext {
    api_token: Option<String>,
    bearer_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SafeLineSystemKeyEnvelope {
    data: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SafeLineCsrfEnvelope {
    data: SafeLineCsrfPayload,
}

#[derive(Debug, Clone, Deserialize)]
struct SafeLineCsrfPayload {
    csrf_token: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SafeLineLoginEnvelope {
    data: SafeLineLoginPayload,
    #[allow(dead_code)]
    err: Option<String>,
    msg: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SafeLineLoginPayload {
    jwt: String,
}

#[derive(Debug, Clone)]
struct ProbeAttempt {
    path: String,
    status: StatusCode,
}

enum DeleteAttempt {
    DeleteById(String),
    DeleteByBody(Value),
    PostDelete(Value),
}

enum SiteWriteAttempt {
    Post(String, Value),
    Put(String, Value),
}

impl SiteWriteAttempt {
    fn path(&self) -> &str {
        match self {
            Self::Post(path, _) | Self::Put(path, _) => path,
        }
    }
}

enum OpenIpGroupDeleteAttempt {
    PostRemove(String, Value),
    DeleteRemove(String, Value),
    PostAction(String, Value),
}

impl OpenIpGroupDeleteAttempt {
    fn path(&self) -> &str {
        match self {
            Self::PostRemove(path, _) | Self::DeleteRemove(path, _) | Self::PostAction(path, _) => {
                path
            }
        }
    }
}

fn normalize_base_url(value: &str) -> Result<String> {
    let base_url = value.trim().trim_end_matches('/').to_string();
    if base_url.is_empty() {
        return Err(anyhow!("雷池地址不能为空"));
    }
    Ok(base_url)
}

fn looks_like_html(value: &str) -> bool {
    let trimmed = value.trim_start();
    trimmed.starts_with("<!DOCTYPE html") || trimmed.starts_with("<html")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_password_matches_safeline_login_shape() {
        let encoded =
            auth::encrypt_password("KvJFHAoYlLU9xI4j", "260b8bf4f0b6e877", "Qq203342").unwrap();
        let decoded = BASE64.decode(encoded).unwrap();
        assert!(decoded.starts_with(b"260b8bf4f0b6e877"));
        assert!(decoded.len() > 16);
    }

    #[test]
    fn has_any_auth_supports_username_password() {
        let config = SafeLineConfig {
            username: "wnluo".to_string(),
            password: "Qq203342".to_string(),
            ..SafeLineConfig::default()
        };
        assert!(auth::has_any_auth(&config));
        assert!(auth::has_username_password(&config));
    }
}
