use super::helpers::{
    adaptive_protection_goal_label, adaptive_protection_mode_label, auto_tuning_intent_label,
    auto_tuning_mode_label, display_https_listen_port, safeline_intercept_action_label,
    safeline_intercept_match_mode_label, source_ip_strategy_label,
    trusted_cdn_sync_interval_unit_label, trusted_cdn_sync_status_label,
    upstream_failure_mode_label,
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
            cdn_525_diagnostic_mode: config.console_settings.cdn_525_diagnostic_mode,
            adaptive_protection: AdaptiveProtectionConfigResponse::from_config(
                &config.adaptive_protection,
            ),
            https_listen_addr: display_https_listen_port(&config.gateway_config.https_listen_addr),
            default_certificate_id: config.gateway_config.default_certificate_id,
            api_endpoint: config.api_bind.clone(),
            notes: config.console_settings.notes.clone(),
            safeline: SafeLineSettingsResponse::from_config(&config.integrations.safeline),
        }
    }
}

impl L4ConfigResponse {
    pub(crate) fn from_config(
        config: &Config,
        runtime_enabled: bool,
        adaptive_runtime: &crate::core::AdaptiveProtectionRuntimeSnapshot,
    ) -> Self {
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
            adaptive_runtime: AdaptiveProtectionRuntimeResponse::from_snapshot(adaptive_runtime),
            trusted_cdn: TrustedCdnConfigResponse {
                manual_cidrs: config.l4_config.trusted_cdn.manual_cidrs.clone(),
                effective_cidrs: config.l4_config.trusted_cdn.effective_cidrs(),
                sync_interval_value: config.l4_config.trusted_cdn.sync_interval_value,
                sync_interval_unit: trusted_cdn_sync_interval_unit_label(
                    config.l4_config.trusted_cdn.sync_interval_unit,
                )
                .to_string(),
                edgeone_overseas: TrustedCdnProviderResponse {
                    enabled: config.l4_config.trusted_cdn.edgeone_overseas.enabled,
                    synced_cidrs: config
                        .l4_config
                        .trusted_cdn
                        .edgeone_overseas
                        .synced_cidrs
                        .clone(),
                    last_synced_at: config.l4_config.trusted_cdn.edgeone_overseas.last_synced_at,
                    last_sync_status: trusted_cdn_sync_status_label(
                        config
                            .l4_config
                            .trusted_cdn
                            .edgeone_overseas
                            .last_sync_status,
                    )
                    .to_string(),
                    last_sync_message: config
                        .l4_config
                        .trusted_cdn
                        .edgeone_overseas
                        .last_sync_message
                        .clone(),
                },
                aliyun_esa: TrustedCdnAliyunEsaResponse {
                    enabled: config.l4_config.trusted_cdn.aliyun_esa.enabled,
                    site_id: config.l4_config.trusted_cdn.aliyun_esa.site_id.clone(),
                    access_key_id: config
                        .l4_config
                        .trusted_cdn
                        .aliyun_esa
                        .access_key_id
                        .clone(),
                    access_key_secret: config
                        .l4_config
                        .trusted_cdn
                        .aliyun_esa
                        .access_key_secret
                        .clone(),
                    endpoint: config.l4_config.trusted_cdn.aliyun_esa.endpoint.clone(),
                    synced_cidrs: config.l4_config.trusted_cdn.aliyun_esa.synced_cidrs.clone(),
                    last_synced_at: config.l4_config.trusted_cdn.aliyun_esa.last_synced_at,
                    last_sync_status: trusted_cdn_sync_status_label(
                        config.l4_config.trusted_cdn.aliyun_esa.last_sync_status,
                    )
                    .to_string(),
                    last_sync_message: config
                        .l4_config
                        .trusted_cdn
                        .aliyun_esa
                        .last_sync_message
                        .clone(),
                },
            },
        }
    }
}

impl L7ConfigResponse {
    pub(crate) fn from_config(
        config: &Config,
        runtime_enabled: bool,
        adaptive_runtime: &crate::core::AdaptiveProtectionRuntimeSnapshot,
    ) -> Self {
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
            adaptive_runtime: AdaptiveProtectionRuntimeResponse::from_snapshot(adaptive_runtime),
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
            auto_tuning: AutoTuningConfigResponse::from_config(&config.auto_tuning),
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
            hard_route_block_multiplier: config.hard_route_block_multiplier,
            hard_host_block_multiplier: config.hard_host_block_multiplier,
            hard_ip_block_multiplier: config.hard_ip_block_multiplier,
            hard_hot_path_block_multiplier: config.hard_hot_path_block_multiplier,
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

impl AdaptiveProtectionConfigResponse {
    pub(crate) fn from_config(config: &crate::config::AdaptiveProtectionConfig) -> Self {
        Self {
            enabled: config.enabled,
            mode: adaptive_protection_mode_label(config.mode).to_string(),
            goal: adaptive_protection_goal_label(config.goal).to_string(),
            cdn_fronted: config.cdn_fronted,
            allow_emergency_reject: config.allow_emergency_reject,
        }
    }
}

impl AdaptiveProtectionRuntimeResponse {
    pub(crate) fn from_snapshot(snapshot: &crate::core::AdaptiveProtectionRuntimeSnapshot) -> Self {
        Self {
            enabled: snapshot.enabled,
            mode: snapshot.mode.clone(),
            goal: snapshot.goal.clone(),
            system_pressure: snapshot.system_pressure.clone(),
            reasons: snapshot.reasons.clone(),
            l4: AdaptiveProtectionL4RuntimeResponse {
                normal_connection_budget_per_minute: snapshot
                    .l4
                    .normal_connection_budget_per_minute,
                suspicious_connection_budget_per_minute: snapshot
                    .l4
                    .suspicious_connection_budget_per_minute,
                high_risk_connection_budget_per_minute: snapshot
                    .l4
                    .high_risk_connection_budget_per_minute,
                soft_delay_ms: snapshot.l4.soft_delay_ms,
                hard_delay_ms: snapshot.l4.hard_delay_ms,
                high_overload_delay_ms: snapshot.l4.high_overload_delay_ms,
                critical_overload_delay_ms: snapshot.l4.critical_overload_delay_ms,
                reject_threshold_percent: snapshot.l4.reject_threshold_percent,
                critical_reject_threshold_percent: snapshot.l4.critical_reject_threshold_percent,
                emergency_reject_enabled: snapshot.l4.emergency_reject_enabled,
            },
            l7: AdaptiveProtectionL7RuntimeResponse {
                request_window_secs: snapshot.l7.request_window_secs,
                delay_ms: snapshot.l7.delay_ms,
                route_challenge_threshold: snapshot.l7.route_challenge_threshold,
                route_block_threshold: snapshot.l7.route_block_threshold,
                ip_challenge_threshold: snapshot.l7.ip_challenge_threshold,
                ip_block_threshold: snapshot.l7.ip_block_threshold,
                challenge_enabled: snapshot.l7.challenge_enabled,
            },
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

impl AutoTuningConfigResponse {
    pub(crate) fn from_config(config: &crate::config::AutoTuningConfig) -> Self {
        Self {
            mode: auto_tuning_mode_label(config.mode).to_string(),
            intent: auto_tuning_intent_label(config.intent).to_string(),
            runtime_adjust_enabled: config.runtime_adjust_enabled,
            bootstrap_secs: config.bootstrap_secs,
            control_interval_secs: config.control_interval_secs,
            cooldown_secs: config.cooldown_secs,
            max_step_percent: config.max_step_percent,
            rollback_window_minutes: config.rollback_window_minutes,
            pinned_fields: config.pinned_fields.clone(),
            slo: AutoSloTargetsResponse {
                tls_handshake_timeout_rate_percent: config.slo.tls_handshake_timeout_rate_percent,
                bucket_reject_rate_percent: config.slo.bucket_reject_rate_percent,
                p95_proxy_latency_ms: config.slo.p95_proxy_latency_ms,
            },
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
