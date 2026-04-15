use super::helpers::{
    normalize_https_listen_addr_input, parse_adaptive_protection_goal,
    parse_adaptive_protection_mode, parse_auto_tuning_intent, parse_auto_tuning_mode,
    parse_safeline_intercept_action, parse_safeline_intercept_match_mode, parse_source_ip_strategy,
    parse_trusted_cdn_sync_interval_unit, parse_upstream_failure_mode,
    parse_upstream_protocol_policy,
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
    pub(crate) fn into_config(
        self,
        mut current: Config,
        allow_compatibility_updates: bool,
    ) -> Config {
        let adaptive_managed_fields =
            current.adaptive_protection.enabled && !allow_compatibility_updates;
        let previous_trusted_cdn = current.l4_config.trusted_cdn.clone();
        let previous_l4 = current.l4_config.clone();
        let previous_edgeone = previous_trusted_cdn.edgeone_overseas;
        let previous_aliyun_esa = previous_trusted_cdn.aliyun_esa;
        current.l4_config = L4Config {
            ddos_protection_enabled: self.ddos_protection_enabled,
            advanced_ddos_enabled: self.advanced_ddos_enabled,
            connection_rate_limit: self.connection_rate_limit,
            syn_flood_threshold: self.syn_flood_threshold,
            max_tracked_ips: self.max_tracked_ips,
            max_blocked_ips: self.max_blocked_ips,
            state_ttl_secs: self.state_ttl_secs,
            bloom_filter_scale: self.bloom_filter_scale,
            behavior_event_channel_capacity: if adaptive_managed_fields {
                previous_l4.behavior_event_channel_capacity
            } else {
                self.behavior_event_channel_capacity
            },
            behavior_drop_critical_threshold: if adaptive_managed_fields {
                previous_l4.behavior_drop_critical_threshold
            } else {
                self.behavior_drop_critical_threshold
            },
            behavior_fallback_ratio_percent: if adaptive_managed_fields {
                previous_l4.behavior_fallback_ratio_percent
            } else {
                self.behavior_fallback_ratio_percent
            },
            behavior_overload_blocked_connections_threshold: if adaptive_managed_fields {
                previous_l4.behavior_overload_blocked_connections_threshold
            } else {
                self.behavior_overload_blocked_connections_threshold
            },
            behavior_overload_active_connections_threshold: if adaptive_managed_fields {
                previous_l4.behavior_overload_active_connections_threshold
            } else {
                self.behavior_overload_active_connections_threshold
            },
            behavior_normal_connection_budget_per_minute: if adaptive_managed_fields {
                previous_l4.behavior_normal_connection_budget_per_minute
            } else {
                self.behavior_normal_connection_budget_per_minute
            },
            behavior_suspicious_connection_budget_per_minute: if adaptive_managed_fields {
                previous_l4.behavior_suspicious_connection_budget_per_minute
            } else {
                self.behavior_suspicious_connection_budget_per_minute
            },
            behavior_high_risk_connection_budget_per_minute: if adaptive_managed_fields {
                previous_l4.behavior_high_risk_connection_budget_per_minute
            } else {
                self.behavior_high_risk_connection_budget_per_minute
            },
            behavior_high_overload_budget_scale_percent: if adaptive_managed_fields {
                previous_l4.behavior_high_overload_budget_scale_percent
            } else {
                self.behavior_high_overload_budget_scale_percent
            },
            behavior_critical_overload_budget_scale_percent: if adaptive_managed_fields {
                previous_l4.behavior_critical_overload_budget_scale_percent
            } else {
                self.behavior_critical_overload_budget_scale_percent
            },
            behavior_high_overload_delay_ms: if adaptive_managed_fields {
                previous_l4.behavior_high_overload_delay_ms
            } else {
                self.behavior_high_overload_delay_ms
            },
            behavior_critical_overload_delay_ms: if adaptive_managed_fields {
                previous_l4.behavior_critical_overload_delay_ms
            } else {
                self.behavior_critical_overload_delay_ms
            },
            behavior_soft_delay_threshold_percent: if adaptive_managed_fields {
                previous_l4.behavior_soft_delay_threshold_percent
            } else {
                self.behavior_soft_delay_threshold_percent
            },
            behavior_hard_delay_threshold_percent: if adaptive_managed_fields {
                previous_l4.behavior_hard_delay_threshold_percent
            } else {
                self.behavior_hard_delay_threshold_percent
            },
            behavior_soft_delay_ms: if adaptive_managed_fields {
                previous_l4.behavior_soft_delay_ms
            } else {
                self.behavior_soft_delay_ms
            },
            behavior_hard_delay_ms: if adaptive_managed_fields {
                previous_l4.behavior_hard_delay_ms
            } else {
                self.behavior_hard_delay_ms
            },
            behavior_reject_threshold_percent: if adaptive_managed_fields {
                previous_l4.behavior_reject_threshold_percent
            } else {
                self.behavior_reject_threshold_percent
            },
            behavior_critical_reject_threshold_percent: if adaptive_managed_fields {
                previous_l4.behavior_critical_reject_threshold_percent
            } else {
                self.behavior_critical_reject_threshold_percent
            },
            trusted_cdn: crate::config::l4::TrustedCdnConfig {
                manual_cidrs: self.trusted_cdn.manual_cidrs,
                sync_interval_value: self.trusted_cdn.sync_interval_value,
                sync_interval_unit: parse_trusted_cdn_sync_interval_unit(
                    &self.trusted_cdn.sync_interval_unit,
                )
                .unwrap_or_default(),
                edgeone_overseas: crate::config::l4::TrustedCdnEdgeOneConfig {
                    enabled: self.trusted_cdn.edgeone_overseas.enabled,
                    synced_cidrs: previous_edgeone.synced_cidrs,
                    last_synced_at: previous_edgeone.last_synced_at,
                    last_sync_status: previous_edgeone.last_sync_status,
                    last_sync_message: previous_edgeone.last_sync_message,
                },
                aliyun_esa: crate::config::l4::TrustedCdnAliyunEsaConfig {
                    enabled: self.trusted_cdn.aliyun_esa.enabled,
                    site_id: self.trusted_cdn.aliyun_esa.site_id,
                    access_key_id: self.trusted_cdn.aliyun_esa.access_key_id,
                    access_key_secret: self.trusted_cdn.aliyun_esa.access_key_secret,
                    endpoint: self.trusted_cdn.aliyun_esa.endpoint,
                    synced_cidrs: previous_aliyun_esa.synced_cidrs,
                    last_synced_at: previous_aliyun_esa.last_synced_at,
                    last_sync_status: previous_aliyun_esa.last_sync_status,
                    last_sync_message: previous_aliyun_esa.last_sync_message,
                },
            },
        };

        current.normalized()
    }
}

impl L7ConfigUpdateRequest {
    pub(crate) fn into_config(
        self,
        mut current: Config,
        allow_compatibility_updates: bool,
    ) -> Result<Config, String> {
        let adaptive_managed_fields =
            current.adaptive_protection.enabled && !allow_compatibility_updates;
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
        current.l7_config.upstream_protocol_policy =
            parse_upstream_protocol_policy(&self.upstream_protocol_policy)?;
        current.l7_config.upstream_http1_strict_mode = self.upstream_http1_strict_mode;
        current.l7_config.upstream_http1_allow_connection_reuse =
            self.upstream_http1_allow_connection_reuse;
        current.l7_config.reject_ambiguous_http1_requests = self.reject_ambiguous_http1_requests;
        current.l7_config.reject_http1_transfer_encoding_requests =
            self.reject_http1_transfer_encoding_requests;
        current.l7_config.reject_body_on_safe_http_methods = self.reject_body_on_safe_http_methods;
        current.l7_config.reject_expect_100_continue = self.reject_expect_100_continue;
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
            if adaptive_managed_fields {
                log::debug!(
                    "Ignoring manual L7 CC threshold update because adaptive protection is enabled"
                );
            } else {
                current.l7_config.cc_defense = cc_defense.into_config();
            }
        }
        current.l7_config.slow_attack_defense = self.slow_attack_defense.into_config();
        if let Some(safeline_intercept) = self.safeline_intercept {
            current.l7_config.safeline_intercept = safeline_intercept.into_config()?;
        }
        if let Some(auto_tuning) = self.auto_tuning {
            current.auto_tuning = auto_tuning.into_config()?;
        }

        Ok(current.normalized())
    }
}

impl CcDefenseConfigRequest {
    pub(crate) fn into_config(self) -> crate::config::l7::CcDefenseConfig {
        let defaults = crate::config::l7::CcDefenseConfig::default();
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
            static_request_weight_percent: self
                .static_request_weight_percent
                .unwrap_or(defaults.static_request_weight_percent),
            page_subresource_weight_percent: self
                .page_subresource_weight_percent
                .unwrap_or(defaults.page_subresource_weight_percent),
            page_load_grace_secs: self
                .page_load_grace_secs
                .unwrap_or(defaults.page_load_grace_secs),
            hard_route_block_multiplier: self
                .hard_route_block_multiplier
                .unwrap_or(defaults.hard_route_block_multiplier),
            hard_host_block_multiplier: self
                .hard_host_block_multiplier
                .unwrap_or(defaults.hard_host_block_multiplier),
            hard_ip_block_multiplier: self
                .hard_ip_block_multiplier
                .unwrap_or(defaults.hard_ip_block_multiplier),
            hard_hot_path_block_multiplier: self
                .hard_hot_path_block_multiplier
                .unwrap_or(defaults.hard_hot_path_block_multiplier),
        }
    }
}

impl SlowAttackDefenseConfigRequest {
    pub(crate) fn into_config(self) -> crate::config::l7::SlowAttackDefenseConfig {
        crate::config::l7::SlowAttackDefenseConfig {
            enabled: self.enabled,
            header_min_bytes_per_sec: self.header_min_bytes_per_sec,
            body_min_bytes_per_sec: self.body_min_bytes_per_sec,
            idle_keepalive_timeout_ms: self.idle_keepalive_timeout_ms,
            event_window_secs: self.event_window_secs,
            max_events_per_window: self.max_events_per_window,
            block_duration_secs: self.block_duration_secs,
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

impl AutoTuningConfigRequest {
    pub(crate) fn into_config(self) -> Result<crate::config::AutoTuningConfig, String> {
        Ok(crate::config::AutoTuningConfig {
            mode: parse_auto_tuning_mode(&self.mode)?,
            intent: parse_auto_tuning_intent(&self.intent)?,
            runtime_adjust_enabled: self.runtime_adjust_enabled,
            bootstrap_secs: self.bootstrap_secs,
            control_interval_secs: self.control_interval_secs,
            cooldown_secs: self.cooldown_secs,
            max_step_percent: self.max_step_percent,
            rollback_window_minutes: self.rollback_window_minutes,
            pinned_fields: self.pinned_fields,
            slo: crate::config::AutoSloTargets {
                tls_handshake_timeout_rate_percent: self.slo.tls_handshake_timeout_rate_percent,
                bucket_reject_rate_percent: self.slo.bucket_reject_rate_percent,
                p95_proxy_latency_ms: self.slo.p95_proxy_latency_ms,
            },
        })
    }
}

impl AdaptiveProtectionConfigRequest {
    pub(crate) fn into_config(self) -> Result<crate::config::AdaptiveProtectionConfig, String> {
        Ok(crate::config::AdaptiveProtectionConfig {
            enabled: self.enabled,
            mode: parse_adaptive_protection_mode(&self.mode)?,
            goal: parse_adaptive_protection_goal(&self.goal)?,
            cdn_fronted: self.cdn_fronted,
            allow_emergency_reject: self.allow_emergency_reject,
        })
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
        current.console_settings.drop_unmatched_requests = self.drop_unmatched_requests;
        current.console_settings.cdn_525_diagnostic_mode = self.cdn_525_diagnostic_mode;
        current.console_settings.client_identity_debug_enabled = self.client_identity_debug_enabled;
        current.adaptive_protection = self.adaptive_protection.into_config()?;
        current.gateway_config = GatewayConfig {
            https_listen_addr,
            default_certificate_id: self.default_certificate_id,
            ..current.gateway_config
        };
        current.tcp_upstream_addr = None;
        current.api_bind = self.api_endpoint.trim().to_string();
        current.sqlite_enabled = true;
        current.console_settings.notes = self.notes;
        current.integrations.safeline = self.safeline.into_config(&current.integrations.safeline);

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
        current.gateway_config.custom_source_ip_header_auth_enabled =
            self.custom_source_ip_header_auth_enabled;
        current.gateway_config.custom_source_ip_header_auth_header =
            self.custom_source_ip_header_auth_header;
        current.gateway_config.custom_source_ip_header_auth_secret =
            self.custom_source_ip_header_auth_secret;
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
        current.integrations.ai_audit = self.ai_audit.into_config()?;

        Ok(current.normalized())
    }
}

impl AiAuditSettingsRequest {
    pub(crate) fn into_config(self) -> Result<crate::config::AiAuditConfig, String> {
        let provider = match self.provider.trim().to_ascii_lowercase().as_str() {
            "" | "local_rules" => crate::config::AiAuditProviderConfig::LocalRules,
            "stub_model" => crate::config::AiAuditProviderConfig::StubModel,
            "openai_compatible" => crate::config::AiAuditProviderConfig::OpenAiCompatible,
            "xiaomi_mimo" => crate::config::AiAuditProviderConfig::XiaomiMimo,
            other => {
                return Err(format!(
                    "AI 审计 provider 仅支持 local_rules/stub_model/openai_compatible/xiaomi_mimo，收到 '{}'",
                    other
                ))
            }
        };

        Ok(crate::config::AiAuditConfig {
            enabled: self.enabled,
            provider,
            model: self.model,
            base_url: self.base_url,
            api_key: self.api_key,
            timeout_ms: self.timeout_ms,
            fallback_to_rules: self.fallback_to_rules,
            event_sample_limit: self.event_sample_limit,
            recent_event_limit: self.recent_event_limit,
            include_raw_event_samples: self.include_raw_event_samples,
            auto_apply_temp_policies: self.auto_apply_temp_policies,
            temp_policy_ttl_secs: self.temp_policy_ttl_secs,
            temp_block_ttl_secs: self.temp_block_ttl_secs,
            auto_apply_min_confidence: self.auto_apply_min_confidence,
            max_active_temp_policies: self.max_active_temp_policies,
            allow_auto_temp_block: self.allow_auto_temp_block,
            allow_auto_extend_effective_policies: self.allow_auto_extend_effective_policies,
            auto_revoke_warmup_secs: self.auto_revoke_warmup_secs,
            auto_audit_enabled: self.auto_audit_enabled,
            auto_audit_interval_secs: self.auto_audit_interval_secs,
            auto_audit_cooldown_secs: self.auto_audit_cooldown_secs,
            auto_audit_on_pressure_high: self.auto_audit_on_pressure_high,
            auto_audit_on_attack_mode: self.auto_audit_on_attack_mode,
            auto_audit_on_hotspot_shift: self.auto_audit_on_hotspot_shift,
            auto_audit_force_local_rules_under_attack: self
                .auto_audit_force_local_rules_under_attack,
        })
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
#[allow(clippy::items_after_test_module)]
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

    #[test]
    fn l4_update_preserves_runtime_managed_fields_when_adaptive_enabled() {
        let current = Config {
            adaptive_protection: crate::config::AdaptiveProtectionConfig {
                enabled: true,
                ..crate::config::AdaptiveProtectionConfig::default()
            },
            l4_config: L4Config {
                behavior_soft_delay_ms: 25,
                behavior_hard_delay_ms: 60,
                behavior_normal_connection_budget_per_minute: 120,
                ..L4Config::default()
            },
            ..Config::default()
        };

        let next = L4ConfigUpdateRequest {
            ddos_protection_enabled: true,
            advanced_ddos_enabled: true,
            connection_rate_limit: 999,
            syn_flood_threshold: 888,
            max_tracked_ips: 777,
            max_blocked_ips: 666,
            state_ttl_secs: 555,
            bloom_filter_scale: 1.2,
            behavior_event_channel_capacity: 1234,
            behavior_drop_critical_threshold: 222,
            behavior_fallback_ratio_percent: 33,
            behavior_overload_blocked_connections_threshold: 444,
            behavior_overload_active_connections_threshold: 555,
            behavior_normal_connection_budget_per_minute: 9999,
            behavior_suspicious_connection_budget_per_minute: 8888,
            behavior_high_risk_connection_budget_per_minute: 7777,
            behavior_high_overload_budget_scale_percent: 44,
            behavior_critical_overload_budget_scale_percent: 22,
            behavior_high_overload_delay_ms: 111,
            behavior_critical_overload_delay_ms: 222,
            behavior_soft_delay_threshold_percent: 333,
            behavior_hard_delay_threshold_percent: 444,
            behavior_soft_delay_ms: 999,
            behavior_hard_delay_ms: 888,
            behavior_reject_threshold_percent: 777,
            behavior_critical_reject_threshold_percent: 666,
            trusted_cdn: TrustedCdnConfigRequest::default(),
        }
        .into_config(current, false);

        assert_eq!(next.l4_config.connection_rate_limit, 999);
        assert_eq!(next.l4_config.behavior_soft_delay_ms, 25);
        assert_eq!(next.l4_config.behavior_hard_delay_ms, 60);
        assert_eq!(
            next.l4_config.behavior_normal_connection_budget_per_minute,
            120
        );
    }

    #[test]
    fn l7_update_preserves_cc_defense_when_adaptive_enabled() {
        let current = Config {
            adaptive_protection: crate::config::AdaptiveProtectionConfig {
                enabled: true,
                ..crate::config::AdaptiveProtectionConfig::default()
            },
            l7_config: crate::config::L7Config {
                cc_defense: crate::config::l7::CcDefenseConfig {
                    ip_challenge_threshold: 60,
                    delay_ms: 150,
                    ..crate::config::l7::CcDefenseConfig::default()
                },
                ..crate::config::L7Config::default()
            },
            ..Config::default()
        };

        let next = L7ConfigUpdateRequest {
            max_request_size: 8192,
            trusted_proxy_cidrs: vec![],
            first_byte_timeout_ms: 2000,
            read_idle_timeout_ms: 5000,
            tls_handshake_timeout_ms: 3000,
            proxy_connect_timeout_ms: 1500,
            proxy_write_timeout_ms: 3000,
            proxy_read_timeout_ms: 10000,
            upstream_healthcheck_enabled: true,
            upstream_healthcheck_interval_secs: 5,
            upstream_healthcheck_timeout_ms: 1000,
            upstream_failure_mode: "fail_open".to_string(),
            upstream_protocol_policy: "http2_preferred".to_string(),
            upstream_http1_strict_mode: true,
            upstream_http1_allow_connection_reuse: false,
            reject_ambiguous_http1_requests: true,
            reject_http1_transfer_encoding_requests: true,
            reject_body_on_safe_http_methods: true,
            reject_expect_100_continue: true,
            bloom_filter_scale: 1.0,
            http2_enabled: true,
            http2_max_concurrent_streams: 100,
            http2_max_frame_size: 16384,
            http2_enable_priorities: true,
            http2_initial_window_size: 65535,
            bloom_enabled: true,
            bloom_false_positive_verification: true,
            runtime_profile: "standard".to_string(),
            listen_addrs: vec!["127.0.0.1:8080".to_string()],
            upstream_endpoint: String::new(),
            http3_enabled: false,
            http3_max_concurrent_streams: 100,
            http3_idle_timeout_secs: 300,
            http3_mtu: 1350,
            http3_max_frame_size: 65536,
            http3_enable_connection_migration: true,
            http3_qpack_table_size: 4096,
            http3_certificate_path: String::new(),
            http3_private_key_path: String::new(),
            http3_enable_tls13: true,
            cc_defense: Some(CcDefenseConfigRequest {
                enabled: true,
                request_window_secs: 10,
                ip_challenge_threshold: 999,
                ip_block_threshold: 1000,
                host_challenge_threshold: 200,
                host_block_threshold: 400,
                route_challenge_threshold: 100,
                route_block_threshold: 200,
                hot_path_challenge_threshold: 800,
                hot_path_block_threshold: 1600,
                delay_threshold_percent: 70,
                delay_ms: 999,
                challenge_ttl_secs: 1800,
                challenge_cookie_name: "rwaf_cc".to_string(),
                static_request_weight_percent: None,
                page_subresource_weight_percent: None,
                page_load_grace_secs: None,
                hard_route_block_multiplier: None,
                hard_host_block_multiplier: None,
                hard_ip_block_multiplier: None,
                hard_hot_path_block_multiplier: None,
            }),
            slow_attack_defense: SlowAttackDefenseConfigRequest {
                enabled: true,
                header_min_bytes_per_sec: 64,
                body_min_bytes_per_sec: 256,
                idle_keepalive_timeout_ms: 5000,
                event_window_secs: 300,
                max_events_per_window: 6,
                block_duration_secs: 900,
            },
            safeline_intercept: None,
            auto_tuning: None,
        }
        .into_config(current, false)
        .expect("l7 update should succeed");

        assert_eq!(next.l7_config.cc_defense.ip_challenge_threshold, 60);
        assert_eq!(next.l7_config.cc_defense.delay_ms, 150);
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
