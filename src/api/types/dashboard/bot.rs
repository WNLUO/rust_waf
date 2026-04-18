#[derive(Debug, Serialize)]
pub struct BotVerifierStatusResponse {
    pub(crate) generated_at: i64,
    pub(crate) providers: Vec<BotVerifierProviderStatusResponse>,
}

#[derive(Debug, Serialize)]
pub struct BotVerifierProviderStatusResponse {
    pub(crate) provider: String,
    pub(crate) range_count: usize,
    pub(crate) last_refresh_at: Option<i64>,
    pub(crate) last_success_at: Option<i64>,
    pub(crate) last_error: Option<String>,
    pub(crate) status: String,
}

#[derive(Debug, Serialize)]
pub struct BotInsightsResponse {
    pub(crate) generated_at: i64,
    pub(crate) window_start: i64,
    pub(crate) total_bot_events: u64,
    pub(crate) by_trust_class: Vec<AiAuditCountItem>,
    pub(crate) top_bot_names: Vec<AiAuditCountItem>,
    pub(crate) top_mismatch_ips: Vec<AiAuditCountItem>,
    pub(crate) top_routes: Vec<AiAuditCountItem>,
}
use serde::Serialize;

use super::AiAuditCountItem;
