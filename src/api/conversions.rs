use super::types::*;
use super::{
    non_empty_string, parse_blocked_ip_sort_field, parse_event_sort_field, parse_sort_direction,
    runtime_profile_label, unix_timestamp,
};
use crate::config::{
    Config, GatewayConfig, Http3Config, L4Config, Rule, RuleResponseBodySource, RuleResponseHeader,
    RuleResponseTemplate, RuntimeProfile, SafeLineConfig,
};
use crate::core::WafContext;
use crate::integrations::safeline::{SafeLineProbeResult, SafeLineSiteSummary};
use rand::{distributions::Alphanumeric, Rng};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::collections::HashSet;
use std::net::SocketAddr;

impl RuleResponse {
    pub(super) fn from_rule(rule: Rule) -> Self {
        Self {
            id: rule.id,
            name: rule.name,
            enabled: rule.enabled,
            layer: rule.layer.as_str().to_string(),
            pattern: rule.pattern,
            action: rule.action.as_str().to_string(),
            severity: rule.severity.as_str().to_string(),
            plugin_template_id: rule.plugin_template_id,
            response_template: rule
                .response_template
                .map(RuleResponseTemplatePayload::from_template),
        }
    }
}

impl SettingsResponse {
    pub(super) fn from_config(config: &Config) -> Self {
        Self {
            gateway_name: config.console_settings.gateway_name.clone(),
            auto_refresh_seconds: config.console_settings.auto_refresh_seconds,
            https_listen_addr: config.gateway_config.https_listen_addr.clone(),
            default_certificate_id: config.gateway_config.default_certificate_id,
            upstream_endpoint: config.tcp_upstream_addr.clone().unwrap_or_default(),
            api_endpoint: config.api_bind.clone(),
            notification_level: config.console_settings.notification_level.clone(),
            retain_days: config.console_settings.retain_days,
            notes: config.console_settings.notes.clone(),
            safeline: SafeLineSettingsResponse::from_config(&config.integrations.safeline),
        }
    }
}

impl L4ConfigResponse {
    pub(super) fn from_config(config: &Config, runtime_enabled: bool) -> Self {
        Self {
            ddos_protection_enabled: config.l4_config.ddos_protection_enabled,
            advanced_ddos_enabled: config.l4_config.advanced_ddos_enabled,
            connection_rate_limit: config.l4_config.connection_rate_limit,
            syn_flood_threshold: config.l4_config.syn_flood_threshold,
            max_tracked_ips: config.l4_config.max_tracked_ips,
            max_blocked_ips: config.l4_config.max_blocked_ips,
            state_ttl_secs: config.l4_config.state_ttl_secs,
            bloom_filter_scale: config.l4_config.bloom_filter_scale,
            runtime_enabled,
            bloom_enabled: config.bloom_enabled,
            bloom_false_positive_verification: config.l4_bloom_false_positive_verification,
            runtime_profile: runtime_profile_label(config.runtime_profile).to_string(),
        }
    }
}

impl L7ConfigResponse {
    pub(super) fn from_config(config: &Config, runtime_enabled: bool) -> Self {
        Self {
            max_request_size: config.l7_config.max_request_size,
            real_ip_headers: config.l7_config.real_ip_headers.clone(),
            trusted_proxy_cidrs: config.l7_config.trusted_proxy_cidrs.clone(),
            first_byte_timeout_ms: config.l7_config.first_byte_timeout_ms,
            read_idle_timeout_ms: config.l7_config.read_idle_timeout_ms,
            tls_handshake_timeout_ms: config.l7_config.tls_handshake_timeout_ms,
            proxy_connect_timeout_ms: config.l7_config.proxy_connect_timeout_ms,
            proxy_write_timeout_ms: config.l7_config.proxy_write_timeout_ms,
            proxy_read_timeout_ms: config.l7_config.proxy_read_timeout_ms,
            upstream_healthcheck_enabled: config.l7_config.upstream_healthcheck_enabled,
            upstream_healthcheck_interval_secs: config.l7_config.upstream_healthcheck_interval_secs,
            upstream_healthcheck_timeout_ms: config.l7_config.upstream_healthcheck_timeout_ms,
            upstream_failure_mode: match config.l7_config.upstream_failure_mode {
                crate::config::l7::UpstreamFailureMode::FailOpen => "fail_open".to_string(),
                crate::config::l7::UpstreamFailureMode::FailClose => "fail_close".to_string(),
            },
            bloom_filter_scale: config.l7_config.bloom_filter_scale,
            http2_enabled: config.l7_config.http2_config.enabled,
            http2_max_concurrent_streams: config.l7_config.http2_config.max_concurrent_streams,
            http2_max_frame_size: config.l7_config.http2_config.max_frame_size,
            http2_enable_priorities: config.l7_config.http2_config.enable_priorities,
            http2_initial_window_size: config.l7_config.http2_config.initial_window_size,
            runtime_enabled,
            bloom_enabled: config.bloom_enabled,
            bloom_false_positive_verification: config.l7_bloom_false_positive_verification,
            runtime_profile: runtime_profile_label(config.runtime_profile).to_string(),
            listen_addrs: config.listen_addrs.clone(),
            upstream_endpoint: config.tcp_upstream_addr.clone().unwrap_or_default(),
            http3_enabled: config.http3_config.enabled,
            http3_listen_addr: config.http3_config.listen_addr.clone(),
            http3_max_concurrent_streams: config.http3_config.max_concurrent_streams,
            http3_idle_timeout_secs: config.http3_config.idle_timeout_secs,
            http3_mtu: config.http3_config.mtu,
            http3_max_frame_size: config.http3_config.max_frame_size,
            http3_enable_connection_migration: config.http3_config.enable_connection_migration,
            http3_qpack_table_size: config.http3_config.qpack_table_size,
            http3_certificate_path: config
                .http3_config
                .certificate_path
                .clone()
                .unwrap_or_default(),
            http3_private_key_path: config
                .http3_config
                .private_key_path
                .clone()
                .unwrap_or_default(),
            http3_enable_tls13: config.http3_config.enable_tls13,
            safeline_intercept: SafeLineInterceptConfigResponse::from_config(
                &config.l7_config.safeline_intercept,
            ),
        }
    }
}

impl SafeLineInterceptConfigResponse {
    pub(super) fn from_config(config: &crate::config::l7::SafeLineInterceptConfig) -> Self {
        Self {
            enabled: config.enabled,
            action: match config.action {
                crate::config::l7::SafeLineInterceptAction::Pass => "pass".to_string(),
                crate::config::l7::SafeLineInterceptAction::Replace => "replace".to_string(),
                crate::config::l7::SafeLineInterceptAction::Drop => "drop".to_string(),
                crate::config::l7::SafeLineInterceptAction::ReplaceAndBlockIp => {
                    "replace_and_block_ip".to_string()
                }
            },
            match_mode: match config.match_mode {
                crate::config::l7::SafeLineInterceptMatchMode::Strict => {
                    "strict".to_string()
                }
                crate::config::l7::SafeLineInterceptMatchMode::Relaxed => {
                    "relaxed".to_string()
                }
            },
            max_body_bytes: config.max_body_bytes,
            block_duration_secs: config.block_duration_secs,
            response_template: RuleResponseTemplatePayload::from_template(
                config.response_template.clone(),
            ),
        }
    }
}

impl SafeLineSettingsResponse {
    pub(super) fn from_config(config: &SafeLineConfig) -> Self {
        Self {
            enabled: config.enabled,
            auto_sync_events: config.auto_sync_events,
            auto_sync_blocked_ips_push: config.auto_sync_blocked_ips_push,
            auto_sync_blocked_ips_pull: config.auto_sync_blocked_ips_pull,
            auto_sync_interval_secs: config.auto_sync_interval_secs,
            base_url: config.base_url.clone(),
            api_token: config.api_token.clone(),
            username: config.username.clone(),
            password: config.password.clone(),
            verify_tls: config.verify_tls,
            openapi_doc_path: config.openapi_doc_path.clone(),
            auth_probe_path: config.auth_probe_path.clone(),
            site_list_path: config.site_list_path.clone(),
            event_list_path: config.event_list_path.clone(),
            blocklist_sync_path: config.blocklist_sync_path.clone(),
            blocklist_delete_path: config.blocklist_delete_path.clone(),
            blocklist_ip_group_ids: config.blocklist_ip_group_ids.clone(),
        }
    }
}

impl L4ConfigUpdateRequest {
    pub(super) fn into_config(self, mut current: Config) -> Config {
        current.l4_config = L4Config {
            ddos_protection_enabled: self.ddos_protection_enabled,
            advanced_ddos_enabled: self.advanced_ddos_enabled,
            connection_rate_limit: self.connection_rate_limit,
            syn_flood_threshold: self.syn_flood_threshold,
            max_tracked_ips: self.max_tracked_ips,
            max_blocked_ips: self.max_blocked_ips,
            state_ttl_secs: self.state_ttl_secs,
            bloom_filter_scale: self.bloom_filter_scale,
        };

        current.normalized()
    }
}

impl L7ConfigUpdateRequest {
    pub(super) fn into_config(self, mut current: Config) -> Result<Config, String> {
        current.runtime_profile = match self.runtime_profile.as_str() {
            "minimal" => RuntimeProfile::Minimal,
            "standard" => RuntimeProfile::Standard,
            _ => return Err("运行档位仅支持 minimal 或 standard".to_string()),
        };

        let listen_addrs = self
            .listen_addrs
            .into_iter()
            .map(|addr| addr.trim().to_string())
            .filter(|addr| !addr.is_empty())
            .collect::<Vec<_>>();
        if listen_addrs.is_empty() {
            return Err("至少需要保留一个监听地址".to_string());
        }
        for addr in &listen_addrs {
            addr.parse::<SocketAddr>()
                .map_err(|err| format!("监听地址 '{}' 无效: {}", addr, err))?;
        }

        let upstream_endpoint = self.upstream_endpoint.trim().to_string();
        if !upstream_endpoint.is_empty() {
            upstream_endpoint
                .parse::<SocketAddr>()
                .map_err(|err| format!("上游地址 '{}' 无效: {}", upstream_endpoint, err))?;
        }

        let http3_listen_addr = self.http3_listen_addr.trim().to_string();
        http3_listen_addr
            .parse::<SocketAddr>()
            .map_err(|err| format!("HTTP/3 监听地址 '{}' 无效: {}", http3_listen_addr, err))?;

        let http3_config = Http3Config {
            enabled: self.http3_enabled,
            listen_addr: http3_listen_addr,
            max_concurrent_streams: self.http3_max_concurrent_streams,
            idle_timeout_secs: self.http3_idle_timeout_secs,
            mtu: self.http3_mtu,
            max_frame_size: self.http3_max_frame_size,
            enable_connection_migration: self.http3_enable_connection_migration,
            qpack_table_size: self.http3_qpack_table_size,
            certificate_path: non_empty_string(self.http3_certificate_path),
            private_key_path: non_empty_string(self.http3_private_key_path),
            enable_tls13: self.http3_enable_tls13,
        };
        http3_config.validate()?;

        current.l7_config.max_request_size = self.max_request_size;
        current.l7_config.real_ip_headers = self.real_ip_headers;
        current.l7_config.trusted_proxy_cidrs = self.trusted_proxy_cidrs;
        current.l7_config.first_byte_timeout_ms = self.first_byte_timeout_ms;
        current.l7_config.read_idle_timeout_ms = self.read_idle_timeout_ms;
        current.l7_config.tls_handshake_timeout_ms = self.tls_handshake_timeout_ms;
        current.l7_config.proxy_connect_timeout_ms = self.proxy_connect_timeout_ms;
        current.l7_config.proxy_write_timeout_ms = self.proxy_write_timeout_ms;
        current.l7_config.proxy_read_timeout_ms = self.proxy_read_timeout_ms;
        current.l7_config.upstream_healthcheck_enabled = self.upstream_healthcheck_enabled;
        current.l7_config.upstream_healthcheck_interval_secs =
            self.upstream_healthcheck_interval_secs;
        current.l7_config.upstream_healthcheck_timeout_ms = self.upstream_healthcheck_timeout_ms;
        current.l7_config.upstream_failure_mode = match self.upstream_failure_mode.as_str() {
            "fail_open" => crate::config::l7::UpstreamFailureMode::FailOpen,
            "fail_close" => crate::config::l7::UpstreamFailureMode::FailClose,
            _ => return Err("上游失败策略仅支持 fail_open 或 fail_close".to_string()),
        };
        current.l7_config.bloom_filter_scale = self.bloom_filter_scale;
        current.l7_config.http2_config.enabled = self.http2_enabled;
        current.l7_config.http2_config.max_concurrent_streams = self.http2_max_concurrent_streams;
        current.l7_config.http2_config.max_frame_size = self.http2_max_frame_size;
        current.l7_config.http2_config.enable_priorities = self.http2_enable_priorities;
        current.l7_config.http2_config.initial_window_size = self.http2_initial_window_size;
        current.bloom_enabled = self.bloom_enabled;
        current.l7_bloom_false_positive_verification = self.bloom_false_positive_verification;
        current.listen_addrs = listen_addrs;
        current.tcp_upstream_addr = non_empty_string(upstream_endpoint);
        current.http3_config = http3_config;
        if let Some(safeline_intercept) = self.safeline_intercept {
            current.l7_config.safeline_intercept = safeline_intercept.into_config()?;
        }

        Ok(current.normalized())
    }
}

impl SafeLineInterceptConfigRequest {
    pub(super) fn into_config(self) -> Result<crate::config::l7::SafeLineInterceptConfig, String> {
        let action = match self.action.trim().to_ascii_lowercase().as_str() {
            "pass" => crate::config::l7::SafeLineInterceptAction::Pass,
            "replace" => crate::config::l7::SafeLineInterceptAction::Replace,
            "drop" => crate::config::l7::SafeLineInterceptAction::Drop,
            "replace_and_block_ip" => {
                crate::config::l7::SafeLineInterceptAction::ReplaceAndBlockIp
            }
            other => {
                return Err(format!(
                    "SafeLine 响应动作仅支持 pass、replace、drop、replace_and_block_ip，收到 '{}'",
                    other
                ))
            }
        };

        let match_mode = match self.match_mode.trim().to_ascii_lowercase().as_str() {
            "strict" => crate::config::l7::SafeLineInterceptMatchMode::Strict,
            "relaxed" => crate::config::l7::SafeLineInterceptMatchMode::Relaxed,
            other => {
                return Err(format!(
                    "SafeLine 匹配模式仅支持 strict 或 relaxed，收到 '{}'",
                    other
                ))
            }
        };

        let config = crate::config::l7::SafeLineInterceptConfig {
            enabled: self.enabled,
            action,
            match_mode,
            max_body_bytes: self.max_body_bytes,
            block_duration_secs: self.block_duration_secs,
            response_template: self.response_template.into(),
        };

        crate::rules::validate_response_template(&config.response_template)
            .map_err(|err| format!("SafeLine 自定义响应模板无效: {}", err))?;

        Ok(config)
    }
}

impl SettingsUpdateRequest {
    pub(super) async fn into_config(
        self,
        mut current: Config,
        store: Option<&crate::storage::SqliteStore>,
    ) -> Result<Config, String> {
        if self.gateway_name.trim().is_empty() {
            return Err("网关名称不能为空".to_string());
        }
        if self.api_endpoint.trim().is_empty() {
            return Err("控制面 API 地址不能为空".to_string());
        }
        let https_listen_addr = self.https_listen_addr.trim().to_string();
        if !https_listen_addr.is_empty() {
            https_listen_addr
                .parse::<SocketAddr>()
                .map_err(|err| format!("HTTPS 入口地址 '{}' 无效: {}", https_listen_addr, err))?;
        }

        if let (Some(store), Some(default_certificate_id)) = (store, self.default_certificate_id) {
            ensure_local_certificate_exists(store, default_certificate_id).await?;
        }

        current.console_settings.gateway_name = self.gateway_name;
        current.console_settings.auto_refresh_seconds = self.auto_refresh_seconds;
        current.gateway_config = GatewayConfig {
            https_listen_addr,
            default_certificate_id: self.default_certificate_id,
        };
        current.tcp_upstream_addr = non_empty_string(self.upstream_endpoint);
        current.api_bind = self.api_endpoint.trim().to_string();
        current.sqlite_enabled = true;
        current.console_settings.notification_level = self.notification_level;
        current.console_settings.retain_days = self.retain_days;
        current.console_settings.notes = self.notes;
        current.integrations.safeline = self.safeline.into_config();

        Ok(current.normalized())
    }
}

impl SafeLineSettingsRequest {
    pub(super) fn into_config(self) -> SafeLineConfig {
        SafeLineConfig {
            enabled: true,
            auto_sync_events: self.auto_sync_events,
            auto_sync_blocked_ips_push: self.auto_sync_blocked_ips_push,
            auto_sync_blocked_ips_pull: self.auto_sync_blocked_ips_pull,
            auto_sync_interval_secs: self.auto_sync_interval_secs,
            base_url: self.base_url,
            api_token: self.api_token,
            username: self.username,
            password: self.password,
            verify_tls: self.verify_tls,
            openapi_doc_path: "/openapi_doc/".to_string(),
            auth_probe_path: "/api/open/system/key".to_string(),
            site_list_path: "/api/open/site".to_string(),
            event_list_path: "/api/open/records".to_string(),
            blocklist_sync_path: "/api/open/ipgroup".to_string(),
            blocklist_delete_path: "/api/open/ipgroup".to_string(),
            blocklist_ip_group_ids: Vec::new(),
        }
    }
}

impl SafeLineTestRequest {
    pub(super) fn into_config(self) -> SafeLineConfig {
        SafeLineConfig {
            enabled: true,
            auto_sync_events: false,
            auto_sync_blocked_ips_push: false,
            auto_sync_blocked_ips_pull: false,
            auto_sync_interval_secs: 0,
            base_url: self.base_url,
            api_token: self.api_token,
            username: self.username,
            password: self.password,
            verify_tls: self.verify_tls,
            openapi_doc_path: self.openapi_doc_path,
            auth_probe_path: self.auth_probe_path,
            site_list_path: self.site_list_path,
            event_list_path: self.event_list_path,
            blocklist_sync_path: self.blocklist_sync_path,
            blocklist_delete_path: self.blocklist_delete_path,
            blocklist_ip_group_ids: self.blocklist_ip_group_ids,
        }
    }
}

impl L4StatsResponse {
    pub(super) fn disabled() -> Self {
        Self {
            enabled: false,
            connections: crate::l4::connection::ConnectionStats {
                total_connections: 0,
                active_connections: 0,
                blocked_connections: 0,
                rate_limit_hits: 0,
            },
            ddos_events: 0,
            protocol_anomalies: 0,
            traffic: 0,
            defense_actions: 0,
            bloom_stats: None,
            false_positive_stats: None,
            per_port_stats: Vec::new(),
        }
    }

    pub(super) fn from_stats(stats: crate::l4::inspector::L4Statistics) -> Self {
        let mut per_port_stats = stats.per_port_stats.into_values().collect::<Vec<_>>();
        per_port_stats.sort_by(|left, right| {
            right
                .blocks
                .cmp(&left.blocks)
                .then(right.ddos_events.cmp(&left.ddos_events))
                .then(right.connections.cmp(&left.connections))
                .then(left.port.cmp(&right.port))
        });

        Self {
            enabled: true,
            connections: stats.connections,
            ddos_events: stats.ddos_events,
            protocol_anomalies: stats.protocol_anomalies,
            traffic: stats.traffic,
            defense_actions: stats.defense_actions,
            bloom_stats: stats.bloom_stats,
            false_positive_stats: stats.false_positive_stats,
            per_port_stats,
        }
    }
}

impl L7StatsResponse {
    pub(super) fn from_context(context: &WafContext) -> Self {
        let metrics = context.metrics_snapshot();
        let upstream = context.upstream_health_snapshot();
        let http3 = context.http3_runtime_snapshot();

        Self {
            enabled: true,
            blocked_requests: metrics.as_ref().map(|value| value.blocked_l7).unwrap_or(0),
            proxied_requests: metrics
                .as_ref()
                .map(|value| value.proxied_requests)
                .unwrap_or(0),
            proxy_successes: metrics
                .as_ref()
                .map(|value| value.proxy_successes)
                .unwrap_or(0),
            proxy_failures: metrics
                .as_ref()
                .map(|value| value.proxy_failures)
                .unwrap_or(0),
            proxy_fail_close_rejections: metrics
                .as_ref()
                .map(|value| value.proxy_fail_close_rejections)
                .unwrap_or(0),
            average_proxy_latency_micros: metrics
                .as_ref()
                .map(|value| value.average_proxy_latency_micros)
                .unwrap_or(0),
            upstream_healthy: upstream.healthy,
            upstream_last_check_at: upstream.last_check_at,
            upstream_last_error: upstream.last_error,
            http3_feature_available: http3.feature_available,
            http3_configured_enabled: http3.configured_enabled,
            http3_tls13_enabled: http3.tls13_enabled,
            http3_certificate_configured: http3.certificate_configured,
            http3_private_key_configured: http3.private_key_configured,
            http3_listener_started: http3.listener_started,
            http3_listener_addr: http3.listener_addr,
            http3_status: http3.status,
            http3_last_error: http3.last_error,
        }
    }
}

impl From<SafeLineProbeResult> for SafeLineTestResponse {
    fn from(value: SafeLineProbeResult) -> Self {
        Self {
            status: value.status,
            message: value.message,
            openapi_doc_reachable: value.openapi_doc_reachable,
            openapi_doc_status: value.openapi_doc_status,
            authenticated: value.authenticated,
            auth_probe_status: value.auth_probe_status,
        }
    }
}

impl From<SafeLineSiteSummary> for SafeLineSiteResponse {
    fn from(value: SafeLineSiteSummary) -> Self {
        Self {
            id: value.id,
            name: value.name,
            domain: value.domain,
            status: value.status,
            enabled: value.enabled,
            server_names: value.server_names,
            ports: value.ports,
            ssl_ports: value.ssl_ports,
            upstreams: value.upstreams,
            ssl_enabled: value.ssl_enabled,
            cert_id: value.cert_id,
            cert_type: value.cert_type,
            cert_filename: value.cert_filename,
            key_filename: value.key_filename,
            health_check: value.health_check,
            raw: value.raw,
        }
    }
}

impl TryFrom<crate::storage::SafeLineCachedSiteEntry> for SafeLineSiteResponse {
    type Error = anyhow::Error;

    fn try_from(value: crate::storage::SafeLineCachedSiteEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.remote_site_id,
            name: value.name,
            domain: value.domain,
            status: value.status,
            enabled: value.enabled,
            server_names: parse_json_string_vec(&value.server_names_json)?,
            ports: parse_json_string_vec(&value.ports_json)?,
            ssl_ports: parse_json_string_vec(&value.ssl_ports_json)?,
            upstreams: parse_json_string_vec(&value.upstreams_json)?,
            ssl_enabled: value.ssl_enabled,
            cert_id: value.cert_id,
            cert_type: value.cert_type,
            cert_filename: value.cert_filename,
            key_filename: value.key_filename,
            health_check: value.health_check,
            raw: parse_json_value(&value.raw_json)?,
        })
    }
}

impl crate::storage::SafeLineCachedSiteUpsert {
    pub(super) fn from_summary(value: &SafeLineSiteSummary) -> Result<Self, anyhow::Error> {
        Ok(Self {
            remote_site_id: value.id.clone(),
            name: value.name.clone(),
            domain: value.domain.clone(),
            status: value.status.clone(),
            enabled: value.enabled,
            server_names: value.server_names.clone(),
            ports: value.ports.clone(),
            ssl_ports: value.ssl_ports.clone(),
            upstreams: value.upstreams.clone(),
            ssl_enabled: value.ssl_enabled,
            cert_id: value.cert_id,
            cert_type: value.cert_type,
            cert_filename: value.cert_filename.clone(),
            key_filename: value.key_filename.clone(),
            health_check: value.health_check,
            raw_json: serde_json::to_string(&value.raw)?,
        })
    }
}

impl From<crate::storage::SafeLineSiteMappingEntry> for SafeLineMappingResponse {
    fn from(value: crate::storage::SafeLineSiteMappingEntry) -> Self {
        Self {
            id: value.id,
            safeline_site_id: value.safeline_site_id,
            safeline_site_name: value.safeline_site_name,
            safeline_site_domain: value.safeline_site_domain,
            local_alias: value.local_alias,
            enabled: value.enabled,
            is_primary: value.is_primary,
            notes: value.notes,
            updated_at: value.updated_at,
        }
    }
}

impl SafeLineMappingsUpdateRequest {
    pub(super) fn into_storage_mappings(
        self,
    ) -> Result<Vec<crate::storage::SafeLineSiteMappingUpsert>, String> {
        let mut primary_count = 0usize;
        let mut seen_site_ids = HashSet::new();
        let mut mappings = Vec::with_capacity(self.mappings.len());

        for item in self.mappings {
            let safeline_site_id = item.safeline_site_id.trim().to_string();
            let safeline_site_name = item.safeline_site_name.trim().to_string();
            let safeline_site_domain = item.safeline_site_domain.trim().to_string();
            let local_alias = item.local_alias.trim().to_string();
            let notes = item.notes.trim().to_string();

            if safeline_site_id.is_empty() {
                return Err("映射里的雷池站点 ID 不能为空".to_string());
            }
            if !seen_site_ids.insert(safeline_site_id.clone()) {
                return Err(format!("雷池站点 {} 存在重复映射", safeline_site_id));
            }
            if local_alias.is_empty() {
                return Err(format!("站点 {} 的本地别名不能为空", safeline_site_id));
            }
            if item.is_primary {
                primary_count += 1;
                if !item.enabled {
                    return Err(format!("主站点 {} 必须保持启用状态", safeline_site_id));
                }
            }

            mappings.push(crate::storage::SafeLineSiteMappingUpsert {
                safeline_site_id,
                safeline_site_name,
                safeline_site_domain,
                local_alias,
                enabled: item.enabled,
                is_primary: item.is_primary,
                notes,
            });
        }

        if primary_count > 1 {
            return Err("同一时间只能设置一个主站点映射".to_string());
        }

        Ok(mappings)
    }
}

impl TryFrom<crate::storage::LocalSiteEntry> for LocalSiteResponse {
    type Error = anyhow::Error;

    fn try_from(value: crate::storage::LocalSiteEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            name: value.name,
            primary_hostname: value.primary_hostname,
            hostnames: parse_json_string_vec(&value.hostnames_json)?,
            listen_ports: parse_json_string_vec(&value.listen_ports_json)?,
            upstreams: parse_json_string_vec(&value.upstreams_json)?,
            enabled: value.enabled,
            tls_enabled: value.tls_enabled,
            local_certificate_id: value.local_certificate_id,
            source: value.source,
            sync_mode: value.sync_mode,
            notes: value.notes,
            last_synced_at: value.last_synced_at,
            created_at: value.created_at,
            updated_at: value.updated_at,
        })
    }
}

impl LocalSiteUpsertRequest {
    pub(super) async fn into_storage_site(
        self,
        store: &crate::storage::SqliteStore,
    ) -> Result<crate::storage::LocalSiteUpsert, String> {
        let name = required_string(self.name, "站点名称不能为空")?;
        let primary_hostname = required_string(self.primary_hostname, "主域名不能为空")?;
        let mut hostnames = normalize_string_list(self.hostnames);
        if !hostnames.iter().any(|item| item == &primary_hostname) {
            hostnames.insert(0, primary_hostname.clone());
        }
        let listen_ports = normalize_string_list(self.listen_ports);
        let upstreams = normalize_string_list(self.upstreams);
        let source = non_empty_string(self.source).unwrap_or_else(|| "manual".to_string());
        let sync_mode = non_empty_string(self.sync_mode).unwrap_or_else(|| "manual".to_string());
        let notes = self.notes.trim().to_string();

        for listen_port in &listen_ports {
            validate_listen_port_token(listen_port)?;
        }
        for upstream in &upstreams {
            crate::core::gateway::normalize_upstream_endpoint(upstream)
                .map_err(|err| format!("上游地址 '{}' 无效: {}", upstream, err))?;
        }

        if let Some(local_certificate_id) = self.local_certificate_id {
            ensure_local_certificate_exists(store, local_certificate_id).await?;
        }

        Ok(crate::storage::LocalSiteUpsert {
            name,
            primary_hostname,
            hostnames,
            listen_ports,
            upstreams,
            enabled: self.enabled,
            tls_enabled: self.tls_enabled,
            local_certificate_id: self.local_certificate_id,
            source,
            sync_mode,
            notes,
            last_synced_at: self.last_synced_at,
        })
    }
}

impl TryFrom<crate::storage::LocalCertificateEntry> for LocalCertificateResponse {
    type Error = anyhow::Error;

    fn try_from(value: crate::storage::LocalCertificateEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            name: value.name,
            domains: parse_json_string_vec(&value.domains_json)?,
            issuer: value.issuer,
            valid_from: value.valid_from,
            valid_to: value.valid_to,
            source_type: value.source_type,
            provider_remote_id: value.provider_remote_id,
            trusted: value.trusted,
            expired: value.expired,
            notes: value.notes,
            last_synced_at: value.last_synced_at,
            created_at: value.created_at,
            updated_at: value.updated_at,
        })
    }
}

impl LocalCertificateUpsertRequest {
    pub(super) fn into_storage_certificate(
        self,
    ) -> Result<
        (
            crate::storage::LocalCertificateUpsert,
            Option<LocalCertificateSecretDraft>,
        ),
        String,
    > {
        let name = required_string(self.name, "证书名称不能为空")?;
        let domains = normalize_string_list(self.domains);
        let issuer = self.issuer.trim().to_string();
        let source_type =
            non_empty_string(self.source_type).unwrap_or_else(|| "manual".to_string());
        let provider_remote_id = self.provider_remote_id.and_then(non_empty_string);
        let notes = self.notes.trim().to_string();
        let certificate_pem = self.certificate_pem.unwrap_or_default().trim().to_string();
        let private_key_pem = self.private_key_pem.unwrap_or_default().trim().to_string();

        if let (Some(valid_from), Some(valid_to)) = (self.valid_from, self.valid_to) {
            if valid_to < valid_from {
                return Err("证书有效期结束时间不能早于开始时间".to_string());
            }
        }

        let secret = match (certificate_pem.is_empty(), private_key_pem.is_empty()) {
            (true, true) => None,
            (false, false) => Some(LocalCertificateSecretDraft {
                certificate_pem,
                private_key_pem,
            }),
            _ => {
                return Err("证书 PEM 与私钥 PEM 需要同时填写，或同时留空".to_string());
            }
        };

        Ok((
            crate::storage::LocalCertificateUpsert {
                name,
                domains,
                issuer,
                valid_from: self.valid_from,
                valid_to: self.valid_to,
                source_type,
                provider_remote_id,
                trusted: self.trusted,
                expired: self.expired,
                notes,
                last_synced_at: self.last_synced_at,
            },
            secret,
        ))
    }
}

impl GeneratedLocalCertificateRequest {
    pub(super) fn into_generated_certificate(
        self,
    ) -> Result<GeneratedLocalCertificateDraft, String> {
        let domains = normalize_string_list(self.domains);
        if domains.is_empty() {
            return Err("至少填写一个域名才能生成证书".to_string());
        }

        let primary_domain = domains[0].clone();
        let name = self
            .name
            .and_then(non_empty_string)
            .unwrap_or_else(|| default_generated_certificate_name(&primary_domain));
        let notes = self
            .notes
            .and_then(non_empty_string)
            .unwrap_or_else(|| "系统设置中生成的随机假证书".to_string());
        let now = unix_timestamp();
        let valid_to = now.saturating_add(3600 * 24 * 365);
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(domains.clone()).map_err(|err| err.to_string())?;

        Ok(GeneratedLocalCertificateDraft {
            certificate: crate::storage::LocalCertificateUpsert {
                name,
                domains,
                issuer: "WAF Auto Generated".to_string(),
                valid_from: Some(now),
                valid_to: Some(valid_to),
                source_type: "generated".to_string(),
                provider_remote_id: None,
                trusted: false,
                expired: false,
                notes,
                last_synced_at: None,
            },
            secret: LocalCertificateSecretDraft {
                certificate_pem: cert.pem(),
                private_key_pem: key_pair.serialize_pem(),
            },
        })
    }
}

impl From<crate::storage::SiteSyncLinkEntry> for SiteSyncLinkResponse {
    fn from(value: crate::storage::SiteSyncLinkEntry) -> Self {
        Self {
            id: value.id,
            local_site_id: value.local_site_id,
            provider: value.provider,
            remote_site_id: value.remote_site_id,
            remote_site_name: value.remote_site_name,
            remote_cert_id: value.remote_cert_id,
            sync_mode: value.sync_mode,
            last_local_hash: value.last_local_hash,
            last_remote_hash: value.last_remote_hash,
            last_error: value.last_error,
            last_synced_at: value.last_synced_at,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

impl SiteSyncLinkUpsertRequest {
    pub(super) async fn into_storage_link(
        self,
        store: &crate::storage::SqliteStore,
    ) -> Result<crate::storage::SiteSyncLinkUpsert, String> {
        if self.local_site_id <= 0 {
            return Err("local_site_id 必须大于 0".to_string());
        }
        ensure_local_site_exists(store, self.local_site_id).await?;

        let provider = required_string(self.provider, "provider 不能为空")?;
        let remote_site_id = required_string(self.remote_site_id, "remote_site_id 不能为空")?;
        let remote_site_name =
            non_empty_string(self.remote_site_name).unwrap_or_else(|| remote_site_id.clone());
        let sync_mode =
            non_empty_string(self.sync_mode).unwrap_or_else(|| "remote_to_local".to_string());

        Ok(crate::storage::SiteSyncLinkUpsert {
            local_site_id: self.local_site_id,
            provider,
            remote_site_id,
            remote_site_name,
            remote_cert_id: self.remote_cert_id.and_then(non_empty_string),
            sync_mode,
            last_local_hash: self.last_local_hash.and_then(non_empty_string),
            last_remote_hash: self.last_remote_hash.and_then(non_empty_string),
            last_error: self.last_error.and_then(non_empty_string),
            last_synced_at: self.last_synced_at,
        })
    }
}

impl From<crate::storage::SafeLineSyncStateEntry> for SafeLineSyncStateResponse {
    fn from(value: crate::storage::SafeLineSyncStateEntry) -> Self {
        Self {
            resource: value.resource,
            last_cursor: value.last_cursor,
            last_success_at: value.last_success_at,
            last_imported_count: value.last_imported_count.max(0) as u32,
            last_skipped_count: value.last_skipped_count.max(0) as u32,
            updated_at: value.updated_at,
        }
    }
}

impl RuleUpsertRequest {
    pub(super) fn into_rule(self) -> Result<Rule, String> {
        let id = self.id.clone();
        self.into_rule_with_id(id)
    }

    pub(super) fn into_rule_with_id(self, id: String) -> Result<Rule, String> {
        let id = id.trim().to_string();
        let name = self.name.trim().to_string();
        let pattern = self.pattern.trim().to_string();
        if id.is_empty() {
            return Err("Rule id cannot be empty".to_string());
        }
        if name.is_empty() {
            return Err("Rule name cannot be empty".to_string());
        }
        if pattern.is_empty() {
            return Err("Rule pattern cannot be empty".to_string());
        }

        Ok(Rule {
            id,
            name,
            enabled: self.enabled,
            layer: crate::config::RuleLayer::parse(&self.layer).map_err(|err| err.to_string())?,
            pattern,
            action: crate::config::RuleAction::parse(&self.action)
                .map_err(|err| err.to_string())?,
            severity: crate::config::Severity::parse(&self.severity)
                .map_err(|err| err.to_string())?,
            plugin_template_id: self
                .plugin_template_id
                .filter(|value| !value.trim().is_empty()),
            response_template: self.response_template.map(Into::into),
        })
    }
}

impl RuleResponseTemplatePayload {
    pub(super) fn from_template(template: RuleResponseTemplate) -> Self {
        Self {
            status_code: template.status_code,
            content_type: template.content_type,
            body_source: match template.body_source {
                RuleResponseBodySource::InlineText => "inline_text".to_string(),
                RuleResponseBodySource::File => "file".to_string(),
            },
            gzip: template.gzip,
            body_text: template.body_text,
            body_file_path: template.body_file_path,
            headers: template
                .headers
                .into_iter()
                .map(RuleResponseHeaderPayload::from)
                .collect(),
        }
    }
}

impl From<RuleResponseTemplatePayload> for RuleResponseTemplate {
    fn from(value: RuleResponseTemplatePayload) -> Self {
        Self {
            status_code: value.status_code,
            content_type: value.content_type.trim().to_string(),
            body_source: parse_rule_response_body_source(&value.body_source),
            gzip: value.gzip,
            body_text: value.body_text,
            body_file_path: value.body_file_path.trim().to_string(),
            headers: value.headers.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<RuleResponseHeader> for RuleResponseHeaderPayload {
    fn from(value: RuleResponseHeader) -> Self {
        Self {
            key: value.key,
            value: value.value,
        }
    }
}

impl From<RuleResponseHeaderPayload> for RuleResponseHeader {
    fn from(value: RuleResponseHeaderPayload) -> Self {
        Self {
            key: value.key.trim().to_string(),
            value: value.value,
        }
    }
}

fn parse_rule_response_body_source(value: &str) -> RuleResponseBodySource {
    match value.trim().to_ascii_lowercase().as_str() {
        "file" => RuleResponseBodySource::File,
        _ => RuleResponseBodySource::InlineText,
    }
}

impl From<Rule> for RuleResponse {
    fn from(rule: Rule) -> Self {
        Self::from_rule(rule)
    }
}

impl From<crate::storage::RuleActionPluginEntry> for RuleActionPluginResponse {
    fn from(value: crate::storage::RuleActionPluginEntry) -> Self {
        Self {
            plugin_id: value.plugin_id,
            name: value.name,
            version: value.version,
            description: value.description,
            enabled: value.enabled,
            installed_at: value.installed_at,
            updated_at: value.updated_at,
        }
    }
}

impl TryFrom<crate::storage::RuleActionTemplateEntry> for RuleActionTemplateResponse {
    type Error = anyhow::Error;

    fn try_from(value: crate::storage::RuleActionTemplateEntry) -> Result<Self, Self::Error> {
        let response_template =
            serde_json::from_str::<RuleResponseTemplate>(&value.response_template_json)?;
        Ok(Self {
            template_id: value.template_id,
            plugin_id: value.plugin_id,
            name: value.name,
            description: value.description,
            layer: value.layer,
            action: value.action,
            pattern: value.pattern,
            severity: value.severity,
            response_template: RuleResponseTemplatePayload::from_template(response_template),
            updated_at: value.updated_at,
        })
    }
}

impl From<crate::storage::SecurityEventEntry> for SecurityEventResponse {
    fn from(event: crate::storage::SecurityEventEntry) -> Self {
        Self {
            id: event.id,
            layer: event.layer,
            provider: event.provider,
            provider_event_id: event.provider_event_id,
            provider_site_id: event.provider_site_id,
            provider_site_name: event.provider_site_name,
            provider_site_domain: event.provider_site_domain,
            action: event.action,
            reason: event.reason,
            source_ip: event.source_ip,
            dest_ip: event.dest_ip,
            source_port: event.source_port,
            dest_port: event.dest_port,
            protocol: event.protocol,
            http_method: event.http_method,
            uri: event.uri,
            http_version: event.http_version,
            created_at: event.created_at,
            handled: event.handled,
            handled_at: event.handled_at,
        }
    }
}

impl From<crate::storage::BlockedIpEntry> for BlockedIpResponse {
    fn from(entry: crate::storage::BlockedIpEntry) -> Self {
        Self {
            id: entry.id,
            provider: entry.provider,
            provider_remote_id: entry.provider_remote_id,
            ip: entry.ip,
            reason: entry.reason,
            blocked_at: entry.blocked_at,
            expires_at: entry.expires_at,
        }
    }
}

impl EventsQueryParams {
    pub(super) fn into_query(self) -> Result<crate::storage::SecurityEventQuery, String> {
        Ok(crate::storage::SecurityEventQuery {
            limit: self.limit.unwrap_or(50),
            offset: self.offset.unwrap_or(0),
            layer: self.layer,
            provider: self.provider,
            provider_site_id: self.provider_site_id,
            source_ip: self.source_ip,
            action: self.action,
            blocked_only: self.blocked_only.unwrap_or(false),
            handled_only: self.handled_only,
            created_from: self.created_from,
            created_to: self.created_to,
            sort_by: parse_event_sort_field(self.sort_by.as_deref())?,
            sort_direction: parse_sort_direction(self.sort_direction.as_deref())?,
        })
    }
}

impl BlockedIpsQueryParams {
    pub(super) fn into_query(self) -> Result<crate::storage::BlockedIpQuery, String> {
        Ok(crate::storage::BlockedIpQuery {
            limit: self.limit.unwrap_or(50),
            offset: self.offset.unwrap_or(0),
            source_scope: parse_blocked_ip_source_scope(self.source_scope.as_deref())?,
            provider: self.provider,
            ip: self.ip,
            keyword: normalize_optional_query_value(self.keyword),
            active_only: self.active_only.unwrap_or(false),
            blocked_from: self.blocked_from,
            blocked_to: self.blocked_to,
            sort_by: parse_blocked_ip_sort_field(self.sort_by.as_deref())?,
            sort_direction: parse_sort_direction(self.sort_direction.as_deref())?,
        })
    }
}

fn parse_blocked_ip_source_scope(
    value: Option<&str>,
) -> Result<crate::storage::BlockedIpSourceScope, String> {
    match value.unwrap_or("all").trim().to_ascii_lowercase().as_str() {
        "all" => Ok(crate::storage::BlockedIpSourceScope::All),
        "local" => Ok(crate::storage::BlockedIpSourceScope::Local),
        "remote" => Ok(crate::storage::BlockedIpSourceScope::Remote),
        other => Err(format!("Unsupported blocked IP source_scope '{}'", other)),
    }
}

fn normalize_optional_query_value(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let normalized = value.trim().to_string();
        (!normalized.is_empty()).then_some(normalized)
    })
}

fn default_generated_certificate_name(primary_domain: &str) -> String {
    let random_suffix: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();
    format!(
        "fake-{}-{}",
        sanitize_certificate_name(primary_domain),
        random_suffix
    )
}

fn sanitize_certificate_name(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' => ch.to_ascii_lowercase(),
            '.' | '-' | '_' => ch,
            _ => '-',
        })
        .collect::<String>();
    let sanitized = sanitized.trim_matches('-').to_string();
    if sanitized.is_empty() {
        "generated-cert".to_string()
    } else {
        sanitized
    }
}

fn normalize_string_list(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();

    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if seen.insert(value.to_string()) {
            normalized.push(value.to_string());
        }
    }

    normalized
}

fn required_string(value: String, message: &str) -> Result<String, String> {
    non_empty_string(value).ok_or_else(|| message.to_string())
}

fn parse_json_string_vec(value: &str) -> Result<Vec<String>, anyhow::Error> {
    Ok(serde_json::from_str::<Vec<String>>(value)?)
}

fn parse_json_value(value: &str) -> Result<serde_json::Value, anyhow::Error> {
    Ok(serde_json::from_str::<serde_json::Value>(value)?)
}

fn validate_listen_port_token(value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("监听端口不能为空".to_string());
    }

    if trimmed.parse::<u16>().is_ok() {
        return Ok(());
    }

    if let Ok(uri) = trimmed.parse::<http::Uri>() {
        if uri.port_u16().is_some() {
            return Ok(());
        }
    }

    match trimmed
        .rsplit(':')
        .next()
        .and_then(|item| item.parse::<u16>().ok())
    {
        Some(_) => Ok(()),
        None => Err(format!("监听端口 '{}' 无效", trimmed)),
    }
}

async fn ensure_local_certificate_exists(
    store: &crate::storage::SqliteStore,
    id: i64,
) -> Result<(), String> {
    let exists = store
        .load_local_certificate(id)
        .await
        .map_err(|err| err.to_string())?
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(format!("本地证书 '{}' 不存在", id))
    }
}

async fn ensure_local_site_exists(
    store: &crate::storage::SqliteStore,
    id: i64,
) -> Result<(), String> {
    let exists = store
        .load_local_site(id)
        .await
        .map_err(|err| err.to_string())?
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(format!("本地站点 '{}' 不存在", id))
    }
}
