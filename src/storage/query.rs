use sqlx::{QueryBuilder, Sqlite};

use super::unix_timestamp;

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, Default)]
pub struct StorageMetricsSummary {
    pub security_events: u64,
    pub blocked_ips: u64,
    pub latest_event_at: Option<i64>,
    pub rules: u64,
    pub latest_rule_update_at: Option<i64>,
}

#[cfg(any(feature = "api", test))]
#[derive(Debug, Clone, Default)]
pub struct SecurityEventQuery {
    pub limit: u32,
    pub offset: u32,
    pub layer: Option<String>,
    pub provider: Option<String>,
    pub provider_site_id: Option<String>,
    pub source_ip: Option<String>,
    pub action: Option<String>,
    pub blocked_only: bool,
    pub handled_only: Option<bool>,
    pub created_from: Option<i64>,
    pub created_to: Option<i64>,
    pub sort_by: EventSortField,
    pub sort_direction: SortDirection,
}

#[cfg(any(feature = "api", test))]
#[derive(Debug, Clone, Default)]
pub struct BlockedIpQuery {
    pub limit: u32,
    pub offset: u32,
    pub source_scope: BlockedIpSourceScope,
    pub provider: Option<String>,
    pub ip: Option<String>,
    pub keyword: Option<String>,
    pub active_only: bool,
    pub blocked_from: Option<i64>,
    pub blocked_to: Option<i64>,
    pub sort_by: BlockedIpSortField,
    pub sort_direction: SortDirection,
}

#[cfg(any(feature = "api", test))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BlockedIpSourceScope {
    Local,
    Remote,
    #[default]
    All,
}

#[cfg(any(feature = "api", test))]
#[derive(Debug, Clone, Copy, Default)]
pub enum SortDirection {
    Asc,
    #[default]
    Desc,
}

#[cfg(any(feature = "api", test))]
#[derive(Debug, Clone, Copy, Default)]
pub enum EventSortField {
    #[default]
    CreatedAt,
    SourceIp,
    DestPort,
}

#[cfg(any(feature = "api", test))]
#[derive(Debug, Clone, Copy, Default)]
pub enum BlockedIpSortField {
    #[default]
    BlockedAt,
    ExpiresAt,
    Ip,
}

#[cfg(any(feature = "api", test))]
#[derive(Debug, Clone)]
pub struct PagedResult<T> {
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
    pub items: Vec<T>,
}

#[cfg(any(feature = "api", test))]
pub(super) fn normalized_limit(limit: u32) -> u32 {
    if limit == 0 {
        50
    } else {
        limit.min(200)
    }
}

#[cfg(any(feature = "api", test))]
pub(super) fn append_security_event_filters<'a>(
    builder: &mut QueryBuilder<'a, Sqlite>,
    query: &'a SecurityEventQuery,
) {
    if let Some(layer) = query.layer.as_deref() {
        builder.push(" AND layer = ");
        builder.push_bind(layer);
    }
    if let Some(provider) = query.provider.as_deref() {
        builder.push(" AND provider = ");
        builder.push_bind(provider);
    }
    if let Some(provider_site_id) = query.provider_site_id.as_deref() {
        builder.push(" AND provider_site_id = ");
        builder.push_bind(provider_site_id);
    }
    if let Some(source_ip) = query.source_ip.as_deref() {
        builder.push(" AND source_ip = ");
        builder.push_bind(source_ip);
    }
    if query.blocked_only {
        builder.push(" AND action = ");
        builder.push_bind("block");
    } else if let Some(action) = query.action.as_deref() {
        builder.push(" AND action = ");
        builder.push_bind(action);
    }
    if let Some(handled_only) = query.handled_only {
        builder.push(" AND handled = ");
        builder.push_bind(if handled_only { 1 } else { 0 });
    }
    if let Some(created_from) = query.created_from {
        builder.push(" AND created_at >= ");
        builder.push_bind(created_from);
    }
    if let Some(created_to) = query.created_to {
        builder.push(" AND created_at <= ");
        builder.push_bind(created_to);
    }
}

#[cfg(any(feature = "api", test))]
pub(super) fn append_blocked_ip_filters<'a>(
    builder: &mut QueryBuilder<'a, Sqlite>,
    query: &'a BlockedIpQuery,
) {
    match query.source_scope {
        BlockedIpSourceScope::Local => {
            builder.push(" AND provider IS NULL");
        }
        BlockedIpSourceScope::Remote => {
            builder.push(" AND provider IS NOT NULL");
        }
        BlockedIpSourceScope::All => {}
    }
    if let Some(provider) = query.provider.as_deref() {
        builder.push(" AND provider = ");
        builder.push_bind(provider);
    }
    if let Some(ip) = query.ip.as_deref() {
        builder.push(" AND ip = ");
        builder.push_bind(ip);
    }
    if let Some(keyword) = query.keyword.as_deref() {
        let like_keyword = format!("%{}%", keyword);
        builder.push(" AND (ip LIKE ");
        builder.push_bind(like_keyword.clone());
        builder.push(" OR reason LIKE ");
        builder.push_bind(like_keyword.clone());
        builder.push(" OR COALESCE(provider, 'local') LIKE ");
        builder.push_bind(like_keyword);
        builder.push(")");
    }
    if query.active_only {
        builder.push(" AND expires_at > ");
        builder.push_bind(unix_timestamp());
    }
    if let Some(blocked_from) = query.blocked_from {
        builder.push(" AND blocked_at >= ");
        builder.push_bind(blocked_from);
    }
    if let Some(blocked_to) = query.blocked_to {
        builder.push(" AND blocked_at <= ");
        builder.push_bind(blocked_to);
    }
}

#[cfg(any(feature = "api", test))]
pub(super) fn append_event_sort<'a>(
    builder: &mut QueryBuilder<'a, Sqlite>,
    query: &SecurityEventQuery,
) {
    builder.push(" ORDER BY ");
    builder.push(match query.sort_by {
        EventSortField::CreatedAt => "created_at",
        EventSortField::SourceIp => "source_ip",
        EventSortField::DestPort => "dest_port",
    });
    builder.push(match query.sort_direction {
        SortDirection::Asc => " ASC",
        SortDirection::Desc => " DESC",
    });
    builder.push(", id ");
    builder.push(match query.sort_direction {
        SortDirection::Asc => "ASC",
        SortDirection::Desc => "DESC",
    });
}

#[cfg(any(feature = "api", test))]
pub(super) fn append_blocked_ip_sort<'a>(
    builder: &mut QueryBuilder<'a, Sqlite>,
    query: &BlockedIpQuery,
) {
    builder.push(" ORDER BY ");
    builder.push(match query.sort_by {
        BlockedIpSortField::BlockedAt => "blocked_at",
        BlockedIpSortField::ExpiresAt => "expires_at",
        BlockedIpSortField::Ip => "ip",
    });
    builder.push(match query.sort_direction {
        SortDirection::Asc => " ASC",
        SortDirection::Desc => " DESC",
    });
    builder.push(", id ");
    builder.push(match query.sort_direction {
        SortDirection::Asc => "ASC",
        SortDirection::Desc => "DESC",
    });
}
