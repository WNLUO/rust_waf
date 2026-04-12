use super::error::{ApiError, ApiResult};
use crate::config::{Config, RuntimeProfile};
use crate::core::WafContext;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub(super) struct ApiState {
    pub(super) context: Arc<WafContext>,
}

pub(super) fn sqlite_store(state: &ApiState) -> ApiResult<&crate::storage::SqliteStore> {
    if !state.context.config_snapshot().sqlite_enabled {
        return Err(ApiError::conflict(
            "SQLite storage is disabled in configuration".to_string(),
        ));
    }

    state
        .context
        .sqlite_store
        .as_deref()
        .ok_or_else(|| ApiError::conflict("SQLite store is unavailable".to_string()))
}

pub(super) fn rules_store(state: &ApiState) -> ApiResult<&crate::storage::SqliteStore> {
    let store = sqlite_store(state)?;
    if !state.context.config_snapshot().sqlite_rules_enabled {
        return Err(ApiError::conflict(
            "SQLite-backed rules are disabled in configuration".to_string(),
        ));
    }
    Ok(store)
}

pub(super) async fn persisted_config(state: &ApiState) -> ApiResult<Config> {
    let store = sqlite_store(state)?;
    store
        .load_app_config()
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::conflict("数据库中未找到系统配置".to_string()))
}

pub(super) fn non_empty_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub(super) fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub(super) fn runtime_profile_label(profile: RuntimeProfile) -> &'static str {
    match profile {
        RuntimeProfile::Minimal => "minimal",
        RuntimeProfile::Standard => "standard",
    }
}
