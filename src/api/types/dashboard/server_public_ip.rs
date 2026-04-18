#[derive(Debug, Serialize)]
pub struct ServerPublicIpSnapshotResponse {
    pub(crate) ips: Vec<String>,
    pub(crate) last_refresh_at: Option<i64>,
    pub(crate) last_success_at: Option<i64>,
    pub(crate) last_error: Option<String>,
}
use serde::Serialize;
