use super::super::unix_timestamp;

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SecurityEventEntry {
    pub id: i64,
    pub layer: String,
    pub provider: Option<String>,
    pub provider_event_id: Option<String>,
    pub provider_site_id: Option<String>,
    pub provider_site_name: Option<String>,
    pub provider_site_domain: Option<String>,
    pub action: String,
    pub reason: String,
    pub details_json: Option<String>,
    pub source_ip: String,
    pub dest_ip: String,
    pub source_port: i64,
    pub dest_port: i64,
    pub protocol: String,
    pub http_method: Option<String>,
    pub uri: Option<String>,
    pub http_version: Option<String>,
    pub created_at: i64,
    pub handled: bool,
    pub handled_at: Option<i64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BotIpCacheEntry {
    pub provider: String,
    pub ranges_json: String,
    pub last_refresh_at: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BlockedIpEntry {
    pub id: i64,
    pub provider: Option<String>,
    pub provider_remote_id: Option<String>,
    pub ip: String,
    pub reason: String,
    pub blocked_at: i64,
    pub expires_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FingerprintProfileEntry {
    pub identity: String,
    pub identity_kind: String,
    pub source_ip: Option<String>,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub first_site_domain: Option<String>,
    pub last_site_domain: Option<String>,
    pub first_user_agent: Option<String>,
    pub last_user_agent: Option<String>,
    pub total_security_events: i64,
    pub total_behavior_events: i64,
    pub total_challenges: i64,
    pub total_blocks: i64,
    pub latest_score: Option<i64>,
    pub max_score: i64,
    pub latest_action: Option<String>,
    pub reputation_score: i64,
    pub notes: String,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BehaviorSessionEntry {
    pub session_key: String,
    pub identity: String,
    pub source_ip: Option<String>,
    pub site_domain: Option<String>,
    pub opened_at: i64,
    pub last_seen_at: i64,
    pub event_count: i64,
    pub challenge_count: i64,
    pub block_count: i64,
    pub latest_action: Option<String>,
    pub latest_uri: Option<String>,
    pub latest_reason: Option<String>,
    pub dominant_route: Option<String>,
    pub focused_document_route: Option<String>,
    pub focused_api_route: Option<String>,
    pub distinct_routes: i64,
    pub repeated_ratio: i64,
    pub document_repeated_ratio: i64,
    pub api_repeated_ratio: i64,
    pub document_requests: i64,
    pub api_requests: i64,
    pub non_document_requests: i64,
    pub interval_jitter_ms: Option<i64>,
    pub session_span_secs: i64,
    pub flags_json: String,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BehaviorEventEntry {
    pub id: i64,
    pub security_event_id: Option<i64>,
    pub identity: String,
    pub session_key: String,
    pub source_ip: String,
    pub site_domain: Option<String>,
    pub http_method: Option<String>,
    pub uri: Option<String>,
    pub action: Option<String>,
    pub reason: String,
    pub score: i64,
    pub dominant_route: Option<String>,
    pub focused_document_route: Option<String>,
    pub focused_api_route: Option<String>,
    pub distinct_routes: i64,
    pub repeated_ratio: i64,
    pub document_repeated_ratio: i64,
    pub api_repeated_ratio: i64,
    pub document_requests: i64,
    pub api_requests: i64,
    pub non_document_requests: i64,
    pub interval_jitter_ms: Option<i64>,
    pub challenge_count_window: i64,
    pub session_span_secs: i64,
    pub flags_json: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct SecurityEventRecord {
    pub layer: String,
    pub provider: Option<String>,
    pub provider_event_id: Option<String>,
    pub provider_site_id: Option<String>,
    pub provider_site_name: Option<String>,
    pub provider_site_domain: Option<String>,
    pub action: String,
    pub reason: String,
    pub details_json: Option<String>,
    pub source_ip: String,
    pub dest_ip: String,
    pub source_port: i64,
    pub dest_port: i64,
    pub protocol: String,
    pub http_method: Option<String>,
    pub uri: Option<String>,
    pub http_version: Option<String>,
    pub created_at: i64,
    pub handled: bool,
    pub handled_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct BlockedIpRecord {
    pub provider: Option<String>,
    pub provider_remote_id: Option<String>,
    pub ip: String,
    pub reason: String,
    pub blocked_at: i64,
    pub expires_at: i64,
}

impl SecurityEventRecord {
    pub fn now(
        layer: impl Into<String>,
        action: impl Into<String>,
        reason: impl Into<String>,
        source_ip: impl Into<String>,
        dest_ip: impl Into<String>,
        source_port: u16,
        dest_port: u16,
        protocol: impl Into<String>,
    ) -> Self {
        Self {
            layer: layer.into(),
            provider: None,
            provider_event_id: None,
            provider_site_id: None,
            provider_site_name: None,
            provider_site_domain: None,
            action: action.into(),
            reason: reason.into(),
            details_json: None,
            source_ip: source_ip.into(),
            dest_ip: dest_ip.into(),
            source_port: i64::from(source_port),
            dest_port: i64::from(dest_port),
            protocol: protocol.into(),
            http_method: None,
            uri: None,
            http_version: None,
            created_at: unix_timestamp(),
            handled: false,
            handled_at: None,
        }
    }
}

impl BlockedIpRecord {
    pub fn new(
        ip: impl Into<String>,
        reason: impl Into<String>,
        blocked_at: i64,
        expires_at: i64,
    ) -> Self {
        Self {
            provider: None,
            provider_remote_id: None,
            ip: ip.into(),
            reason: reason.into(),
            blocked_at,
            expires_at,
        }
    }
}
