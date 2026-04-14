use super::helpers::{
    display_https_listen_port, safeline_intercept_action_label,
    safeline_intercept_match_mode_label, source_ip_strategy_label, upstream_failure_mode_label,
};
use super::*;

impl RuleResponse {
    pub(crate) fn from_rule(rule: Rule) -> Self {
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
    pub(crate) fn from_config(config: &Config) -> Self {
        Self {
            gateway_name: config.console_settings.gateway_name.clone(),
            drop_unmatched_requests: config.console_settings.drop_unmatched_requests,
            https_listen_addr: display_https_listen_port(&config.gateway_config.https_listen_addr),
            default_certificate_id: config.gateway_config.default_certificate_id,
            api_endpoint: config.api_bind.clone(),
            notes: config.console_settings.notes.clone(),
            safeline: SafeLineSettingsResponse::from_config(&config.integrations.safeline),
        }
    }
}

impl L4ConfigResponse {
    pub(crate) fn from_config(config: &Config, runtime_enabled: bool) -> Self {
        Self {
            ddos_protection_enabled: config.l4_config.ddos_protection_enabled,
            advanced_ddos_enabled: config.l4_config.advanced_ddos_enabled,
            connection_rate_limit: config.l4_config.connection_rate_limit,
            syn_flood_threshold: config.l4_config.syn_flood_threshold,
            max_tracked_ips: config.l4_config.max_tracked_ips,
            max_blocked_ips: config.l4_config.max_blocked_ips,
            state_ttl_secs: config.l4_config.state_ttl_secs,
            bloom_filter_scale: config.l4_config.bloom_filter_scale,
            behavior_event_channel_capacity: config.l4_config.behavior_event_channel_capacity,
            behavior_drop_critical_threshold: config.l4_config.behavior_drop_critical_threshold,
            behavior_fallback_ratio_percent: config.l4_config.behavior_fallback_ratio_percent,
            behavior_overload_blocked_connections_threshold: config
                .l4_config
                .behavior_overload_blocked_connections_threshold,
            behavior_overload_active_connections_threshold: config
                .l4_config
                .behavior_overload_active_connections_threshold,
            behavior_normal_connection_budget_per_minute: config
                .l4_config
                .behavior_normal_connection_budget_per_minute,
            behavior_suspicious_connection_budget_per_minute: config
                .l4_config
                .behavior_suspicious_connection_budget_per_minute,
            behavior_high_risk_connection_budget_per_minute: config
                .l4_config
                .behavior_high_risk_connection_budget_per_minute,
            behavior_high_overload_budget_scale_percent: config
                .l4_config
                .behavior_high_overload_budget_scale_percent,
            behavior_critical_overload_budget_scale_percent: config
                .l4_config
                .behavior_critical_overload_budget_scale_percent,
            behavior_high_overload_delay_ms: config.l4_config.behavior_high_overload_delay_ms,
            behavior_critical_overload_delay_ms: config
                .l4_config
                .behavior_critical_overload_delay_ms,
            behavior_soft_delay_threshold_percent: config
                .l4_config
                .behavior_soft_delay_threshold_percent,
            behavior_hard_delay_threshold_percent: config
                .l4_config
                .behavior_hard_delay_threshold_percent,
            behavior_soft_delay_ms: config.l4_config.behavior_soft_delay_ms,
            behavior_hard_delay_ms: config.l4_config.behavior_hard_delay_ms,
            behavior_reject_threshold_percent: config.l4_config.behavior_reject_threshold_percent,
            behavior_critical_reject_threshold_percent: config
                .l4_config
                .behavior_critical_reject_threshold_percent,
            runtime_enabled,
            bloom_enabled: config.bloom_enabled,
            bloom_false_positive_verification: config.l4_bloom_false_positive_verification,
            runtime_profile: runtime_profile_label(config.runtime_profile).to_string(),
        }
    }
}

impl L7ConfigResponse {
    pub(crate) fn from_config(config: &Config, runtime_enabled: bool) -> Self {
        Self {
            max_request_size: config.l7_config.max_request_size,
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
            upstream_failure_mode: upstream_failure_mode_label(
                config.l7_config.upstream_failure_mode,
            )
            .to_string(),
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
            cc_defense: CcDefenseConfigResponse::from_config(&config.l7_config.cc_defense),
            safeline_intercept: SafeLineInterceptConfigResponse::from_config(
                &config.l7_config.safeline_intercept,
            ),
        }
    }
}

impl CcDefenseConfigResponse {
    pub(crate) fn from_config(config: &crate::config::l7::CcDefenseConfig) -> Self {
        Self {
            enabled: config.enabled,
            request_window_secs: config.request_window_secs,
            ip_challenge_threshold: config.ip_challenge_threshold,
            ip_block_threshold: config.ip_block_threshold,
            host_challenge_threshold: config.host_challenge_threshold,
            host_block_threshold: config.host_block_threshold,
            route_challenge_threshold: config.route_challenge_threshold,
            route_block_threshold: config.route_block_threshold,
            hot_path_challenge_threshold: config.hot_path_challenge_threshold,
            hot_path_block_threshold: config.hot_path_block_threshold,
            delay_threshold_percent: config.delay_threshold_percent,
            delay_ms: config.delay_ms,
            challenge_ttl_secs: config.challenge_ttl_secs,
            challenge_cookie_name: config.challenge_cookie_name.clone(),
            static_request_weight_percent: config.static_request_weight_percent,
            page_subresource_weight_percent: config.page_subresource_weight_percent,
            page_load_grace_secs: config.page_load_grace_secs,
        }
    }
}

impl SafeLineInterceptConfigResponse {
    pub(crate) fn from_config(config: &crate::config::l7::SafeLineInterceptConfig) -> Self {
        Self {
            enabled: config.enabled,
            action: safeline_intercept_action_label(config.action).to_string(),
            match_mode: safeline_intercept_match_mode_label(config.match_mode).to_string(),
            max_body_bytes: config.max_body_bytes,
            block_duration_secs: config.block_duration_secs,
            response_template: RuleResponseTemplatePayload::from_template(
                config.response_template.clone(),
            ),
        }
    }
}

impl SafeLineSettingsResponse {
    pub(crate) fn from_config(config: &SafeLineConfig) -> Self {
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

impl HeaderOperationPayload {
    pub(crate) fn from_config(config: &HeaderOperation) -> Self {
        Self {
            scope: match config.scope {
                HeaderOperationScope::Request => "request".to_string(),
                HeaderOperationScope::Response => "response".to_string(),
            },
            action: match config.action {
                HeaderOperationAction::Set => "set".to_string(),
                HeaderOperationAction::Add => "add".to_string(),
                HeaderOperationAction::Remove => "remove".to_string(),
            },
            header: config.header.clone(),
            value: config.value.clone(),
        }
    }
}

impl GlobalSettingsResponse {
    pub(crate) fn from_config(config: &Config) -> Self {
        Self {
            enable_http1_0: config.gateway_config.enable_http1_0,
            http2_enabled: config.l7_config.http2_config.enabled,
            http3_enabled: config.http3_config.enabled,
            source_ip_strategy: source_ip_strategy_label(config.gateway_config.source_ip_strategy)
                .to_string(),
            custom_source_ip_header: config.gateway_config.custom_source_ip_header.clone(),
            trusted_proxy_cidrs: config.l7_config.trusted_proxy_cidrs.clone(),
            http_to_https_redirect: config.gateway_config.http_to_https_redirect,
            enable_hsts: config.gateway_config.enable_hsts,
            rewrite_host_enabled: config.gateway_config.rewrite_host_enabled,
            rewrite_host_value: config.gateway_config.rewrite_host_value.clone(),
            add_x_forwarded_headers: config.gateway_config.add_x_forwarded_headers,
            rewrite_x_forwarded_for: config.gateway_config.rewrite_x_forwarded_for,
            support_gzip: config.gateway_config.support_gzip,
            support_brotli: config.gateway_config.support_brotli,
            support_sse: config.gateway_config.support_sse,
            enable_ntlm: config.gateway_config.enable_ntlm,
            fallback_self_signed_certificate: config
                .gateway_config
                .fallback_self_signed_certificate,
            ssl_protocols: config.gateway_config.ssl_protocols.clone(),
            ssl_ciphers: config.gateway_config.ssl_ciphers.clone(),
            header_operations: config
                .gateway_config
                .header_operations
                .iter()
                .map(HeaderOperationPayload::from_config)
                .collect(),
        }
    }
}
