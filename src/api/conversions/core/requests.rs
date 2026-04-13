use super::helpers::{
    normalize_https_listen_addr_input, parse_safeline_intercept_action,
    parse_safeline_intercept_match_mode, parse_source_ip_strategy, parse_upstream_failure_mode,
};
use super::*;

impl HeaderOperationPayload {
    pub(crate) fn into_config(self) -> Result<HeaderOperation, String> {
        let scope = match self.scope.trim().to_ascii_lowercase().as_str() {
            "request" => HeaderOperationScope::Request,
            "response" => HeaderOperationScope::Response,
            other => {
                return Err(format!(
                    "Header 操作范围仅支持 request/response，收到 '{}'",
                    other
                ))
            }
        };
        let action = match self.action.trim().to_ascii_lowercase().as_str() {
            "set" => HeaderOperationAction::Set,
            "add" => HeaderOperationAction::Add,
            "remove" => HeaderOperationAction::Remove,
            other => {
                return Err(format!(
                    "Header 操作仅支持 set/add/remove，收到 '{}'",
                    other
                ))
            }
        };

        Ok(HeaderOperation {
            scope,
            action,
            header: self.header.trim().to_ascii_lowercase(),
            value: self.value.trim().to_string(),
        })
    }
}

impl L4ConfigUpdateRequest {
    pub(crate) fn into_config(self, mut current: Config) -> Config {
        current.l4_config = L4Config {
            ddos_protection_enabled: self.ddos_protection_enabled,
            advanced_ddos_enabled: self.advanced_ddos_enabled,
            connection_rate_limit: self.connection_rate_limit,
            syn_flood_threshold: self.syn_flood_threshold,
            max_tracked_ips: self.max_tracked_ips,
            max_blocked_ips: self.max_blocked_ips,
            state_ttl_secs: self.state_ttl_secs,
            bloom_filter_scale: self.bloom_filter_scale,
            behavior_event_channel_capacity: self.behavior_event_channel_capacity,
            behavior_drop_critical_threshold: self.behavior_drop_critical_threshold,
            behavior_fallback_ratio_percent: self.behavior_fallback_ratio_percent,
            behavior_overload_blocked_connections_threshold: self
                .behavior_overload_blocked_connections_threshold,
            behavior_overload_active_connections_threshold: self
                .behavior_overload_active_connections_threshold,
            behavior_normal_connection_budget_per_minute: self
                .behavior_normal_connection_budget_per_minute,
            behavior_suspicious_connection_budget_per_minute: self
                .behavior_suspicious_connection_budget_per_minute,
            behavior_high_risk_connection_budget_per_minute: self
                .behavior_high_risk_connection_budget_per_minute,
            behavior_high_overload_budget_scale_percent: self
                .behavior_high_overload_budget_scale_percent,
            behavior_critical_overload_budget_scale_percent: self
                .behavior_critical_overload_budget_scale_percent,
            behavior_high_overload_delay_ms: self.behavior_high_overload_delay_ms,
            behavior_critical_overload_delay_ms: self.behavior_critical_overload_delay_ms,
            behavior_soft_delay_threshold_percent: self.behavior_soft_delay_threshold_percent,
            behavior_hard_delay_threshold_percent: self.behavior_hard_delay_threshold_percent,
            behavior_soft_delay_ms: self.behavior_soft_delay_ms,
            behavior_hard_delay_ms: self.behavior_hard_delay_ms,
            behavior_reject_threshold_percent: self.behavior_reject_threshold_percent,
            behavior_critical_reject_threshold_percent: self
                .behavior_critical_reject_threshold_percent,
            ..current.l4_config.clone()
        };

        current.normalized()
    }
}

impl L7ConfigUpdateRequest {
    pub(crate) fn into_config(self, mut current: Config) -> Result<Config, String> {
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

        let http3_listen_addr = current.gateway_config.https_listen_addr.trim().to_string();
        if self.http3_enabled && http3_listen_addr.is_empty() {
            return Err("启用 HTTP/3 前需要先配置 HTTPS 全局入口端口".to_string());
        }

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
        current.l7_config.upstream_failure_mode =
            parse_upstream_failure_mode(&self.upstream_failure_mode)?;
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
        if let Some(cc_defense) = self.cc_defense {
            current.l7_config.cc_defense = cc_defense.into_config();
        }
        if let Some(safeline_intercept) = self.safeline_intercept {
            current.l7_config.safeline_intercept = safeline_intercept.into_config()?;
        }

        Ok(current.normalized())
    }
}

impl CcDefenseConfigRequest {
    pub(crate) fn into_config(self) -> crate::config::l7::CcDefenseConfig {
        crate::config::l7::CcDefenseConfig {
            enabled: self.enabled,
            request_window_secs: self.request_window_secs,
            ip_challenge_threshold: self.ip_challenge_threshold,
            ip_block_threshold: self.ip_block_threshold,
            host_challenge_threshold: self.host_challenge_threshold,
            host_block_threshold: self.host_block_threshold,
            route_challenge_threshold: self.route_challenge_threshold,
            route_block_threshold: self.route_block_threshold,
            hot_path_challenge_threshold: self.hot_path_challenge_threshold,
            hot_path_block_threshold: self.hot_path_block_threshold,
            delay_threshold_percent: self.delay_threshold_percent,
            delay_ms: self.delay_ms,
            challenge_ttl_secs: self.challenge_ttl_secs,
            challenge_cookie_name: self.challenge_cookie_name,
        }
    }
}

impl SafeLineInterceptConfigRequest {
    pub(crate) fn into_config(self) -> Result<crate::config::l7::SafeLineInterceptConfig, String> {
        let config = crate::config::l7::SafeLineInterceptConfig {
            enabled: self.enabled,
            action: parse_safeline_intercept_action(&self.action)?,
            match_mode: parse_safeline_intercept_match_mode(&self.match_mode)?,
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
    pub(crate) async fn into_config(
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
        let https_listen_addr = normalize_https_listen_addr_input(&self.https_listen_addr)?;

        if let (Some(store), Some(default_certificate_id)) = (store, self.default_certificate_id) {
            ensure_local_certificate_exists(store, default_certificate_id).await?;
        }

        current.console_settings.gateway_name = self.gateway_name;
        current.console_settings.auto_refresh_seconds = self.auto_refresh_seconds;
        current.gateway_config = GatewayConfig {
            https_listen_addr,
            default_certificate_id: self.default_certificate_id,
            ..current.gateway_config
        };
        current.tcp_upstream_addr = non_empty_string(self.upstream_endpoint);
        current.api_bind = self.api_endpoint.trim().to_string();
        current.sqlite_enabled = true;
        current.console_settings.notification_level = self.notification_level;
        current.console_settings.retain_days = self.retain_days;
        current.console_settings.notes = self.notes;
        current.integrations.safeline = self
            .safeline
            .into_config(&current.integrations.safeline);

        Ok(current.normalized())
    }
}

impl GlobalSettingsUpdateRequest {
    pub(crate) fn into_config(self, mut current: Config) -> Result<Config, String> {
        let header_operations = self
            .header_operations
            .into_iter()
            .map(HeaderOperationPayload::into_config)
            .collect::<Result<Vec<_>, _>>()?;

        current.gateway_config.enable_http1_0 = self.enable_http1_0;
        current.gateway_config.source_ip_strategy =
            parse_source_ip_strategy(&self.source_ip_strategy)?;
        current.gateway_config.custom_source_ip_header = self.custom_source_ip_header;
        current.l7_config.trusted_proxy_cidrs = self.trusted_proxy_cidrs;
        current.gateway_config.http_to_https_redirect = self.http_to_https_redirect;
        current.gateway_config.enable_hsts = self.enable_hsts;
        current.gateway_config.rewrite_host_enabled = self.rewrite_host_enabled;
        current.gateway_config.rewrite_host_value = self.rewrite_host_value;
        current.gateway_config.add_x_forwarded_headers = self.add_x_forwarded_headers;
        current.gateway_config.rewrite_x_forwarded_for = self.rewrite_x_forwarded_for;
        current.gateway_config.support_gzip = self.support_gzip;
        current.gateway_config.support_brotli = self.support_brotli;
        current.gateway_config.support_sse = self.support_sse;
        current.gateway_config.enable_ntlm = self.enable_ntlm;
        current.gateway_config.fallback_self_signed_certificate =
            self.fallback_self_signed_certificate;
        current.gateway_config.ssl_protocols = self.ssl_protocols;
        current.gateway_config.ssl_ciphers = self.ssl_ciphers;
        current.gateway_config.header_operations = header_operations;
        current.l7_config.http2_config.enabled = self.http2_enabled;
        current.http3_config.enabled = self.http3_enabled;

        Ok(current.normalized())
    }
}

impl SafeLineSettingsRequest {
    pub(crate) fn into_config(self, previous: &SafeLineConfig) -> SafeLineConfig {
        let mut config = SafeLineConfig {
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
        };

        let was_configured = safeline_is_configured(previous);
        let is_configured = safeline_is_configured(&config);
        let auto_sync_all_disabled = !config.auto_sync_events
            && !config.auto_sync_blocked_ips_push
            && !config.auto_sync_blocked_ips_pull;

        if !was_configured && is_configured && auto_sync_all_disabled {
            config.auto_sync_events = true;
            config.auto_sync_blocked_ips_push = true;
            config.auto_sync_blocked_ips_pull = true;
        }

        config
    }
}

fn safeline_is_configured(config: &SafeLineConfig) -> bool {
    let has_base_url = !config.base_url.trim().is_empty();
    let has_token = !config.api_token.trim().is_empty();
    let has_user_password =
        !config.username.trim().is_empty() && !config.password.trim().is_empty();

    has_base_url && (has_token || has_user_password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safeline_first_time_configuration_enables_auto_sync_defaults() {
        let request = SafeLineSettingsRequest {
            auto_sync_events: false,
            auto_sync_blocked_ips_push: false,
            auto_sync_blocked_ips_pull: false,
            auto_sync_interval_secs: 300,
            base_url: "https://safeline.example.com".to_string(),
            api_token: "token".to_string(),
            username: String::new(),
            password: String::new(),
            verify_tls: false,
        };

        let config = request.into_config(&SafeLineConfig::default());

        assert!(config.auto_sync_events);
        assert!(config.auto_sync_blocked_ips_push);
        assert!(config.auto_sync_blocked_ips_pull);
    }

    #[test]
    fn safeline_existing_configuration_respects_manual_auto_sync_disable() {
        let request = SafeLineSettingsRequest {
            auto_sync_events: false,
            auto_sync_blocked_ips_push: false,
            auto_sync_blocked_ips_pull: false,
            auto_sync_interval_secs: 300,
            base_url: "https://safeline.example.com".to_string(),
            api_token: "token".to_string(),
            username: String::new(),
            password: String::new(),
            verify_tls: false,
        };

        let previous = SafeLineConfig {
            base_url: "https://safeline.example.com".to_string(),
            api_token: "token".to_string(),
            ..SafeLineConfig::default()
        };
        let config = request.into_config(&previous);

        assert!(!config.auto_sync_events);
        assert!(!config.auto_sync_blocked_ips_push);
        assert!(!config.auto_sync_blocked_ips_pull);
    }
}

impl SafeLineTestRequest {
    pub(crate) fn into_config(self) -> SafeLineConfig {
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
