use super::helpers::{
    normalize_https_listen_addr_input, parse_safeline_intercept_action,
    parse_safeline_intercept_match_mode, parse_source_ip_strategy, parse_upstream_failure_mode,
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
        _allow_compatibility_updates: bool,
    ) -> Config {
        let previous_l4 = current.l4_config.clone();
        current.l4_config = L4Config {
            ddos_protection_enabled: true,
            advanced_ddos_enabled: previous_l4.advanced_ddos_enabled,
            connection_rate_limit: previous_l4.connection_rate_limit,
            syn_flood_threshold: previous_l4.syn_flood_threshold,
            max_tracked_ips: previous_l4.max_tracked_ips,
            max_blocked_ips: previous_l4.max_blocked_ips,
            state_ttl_secs: previous_l4.state_ttl_secs,
            bloom_filter_scale: previous_l4.bloom_filter_scale,
            behavior_event_channel_capacity: previous_l4.behavior_event_channel_capacity,
            behavior_drop_critical_threshold: previous_l4.behavior_drop_critical_threshold,
            behavior_fallback_ratio_percent: previous_l4.behavior_fallback_ratio_percent,
            behavior_overload_blocked_connections_threshold: previous_l4
                .behavior_overload_blocked_connections_threshold,
            behavior_overload_active_connections_threshold: previous_l4
                .behavior_overload_active_connections_threshold,
            behavior_normal_connection_budget_per_minute: previous_l4
                .behavior_normal_connection_budget_per_minute,
            behavior_suspicious_connection_budget_per_minute: previous_l4
                .behavior_suspicious_connection_budget_per_minute,
            behavior_high_risk_connection_budget_per_minute: previous_l4
                .behavior_high_risk_connection_budget_per_minute,
            behavior_high_overload_budget_scale_percent: previous_l4
                .behavior_high_overload_budget_scale_percent,
            behavior_critical_overload_budget_scale_percent: previous_l4
                .behavior_critical_overload_budget_scale_percent,
            behavior_high_overload_delay_ms: previous_l4.behavior_high_overload_delay_ms,
            behavior_critical_overload_delay_ms: previous_l4.behavior_critical_overload_delay_ms,
            behavior_soft_delay_threshold_percent: previous_l4
                .behavior_soft_delay_threshold_percent,
            behavior_hard_delay_threshold_percent: previous_l4
                .behavior_hard_delay_threshold_percent,
            behavior_soft_delay_ms: previous_l4.behavior_soft_delay_ms,
            behavior_hard_delay_ms: previous_l4.behavior_hard_delay_ms,
            behavior_reject_threshold_percent: previous_l4.behavior_reject_threshold_percent,
            behavior_critical_reject_threshold_percent: previous_l4
                .behavior_critical_reject_threshold_percent,
            trusted_cdn: previous_l4.trusted_cdn,
        };

        current.normalized()
    }
}

impl L7ConfigUpdateRequest {
    pub(crate) fn into_config(
        self,
        mut current: Config,
        _allow_compatibility_updates: bool,
    ) -> Result<Config, String> {
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

        let previous_http3 = current.http3_config.clone();
        let http3_config = Http3Config {
            enabled: self.http3_enabled,
            listen_addr: http3_listen_addr,
            max_concurrent_streams: previous_http3.max_concurrent_streams,
            idle_timeout_secs: previous_http3.idle_timeout_secs,
            mtu: previous_http3.mtu,
            max_frame_size: previous_http3.max_frame_size,
            enable_connection_migration: previous_http3.enable_connection_migration,
            qpack_table_size: previous_http3.qpack_table_size,
            certificate_path: non_empty_string(self.http3_certificate_path),
            private_key_path: non_empty_string(self.http3_private_key_path),
            enable_tls13: self.http3_enable_tls13,
        };
        http3_config.validate()?;

        current.l7_config.upstream_healthcheck_enabled = self.upstream_healthcheck_enabled;
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
        current.l7_config.http2_config.enabled = self.http2_enabled;
        current.bloom_enabled = self.bloom_enabled;
        current.listen_addrs = listen_addrs;
        current.tcp_upstream_addr = non_empty_string(upstream_endpoint);
        current.http3_config = http3_config;
        current.l7_config.ip_access = self.ip_access.into_config()?;

        Ok(current.normalized())
    }
}

impl IpAccessConfigPayload {
    pub(crate) fn into_config(self) -> Result<crate::config::l7::IpAccessConfig, String> {
        Ok(crate::config::l7::IpAccessConfig {
            enabled: self.enabled,
            mode: parse_ip_access_mode(&self.mode)?,
            default_action: parse_ip_access_action(&self.default_action)?,
            overseas_action: parse_ip_access_action(&self.overseas_action)?,
            unknown_geo_action: parse_ip_access_action(&self.unknown_geo_action)?,
            allow_private_ips: self.allow_private_ips,
            allow_server_public_ip: self.allow_server_public_ip,
            domestic_country_codes: self.domestic_country_codes,
            allow_cidrs: self.allow_cidrs,
            block_cidrs: self.block_cidrs,
            domestic_cidrs: self.domestic_cidrs,
            bot_policy: crate::config::l7::IpAccessBotPolicy {
                allow_verified_search_bots: self.bot_policy.allow_verified_search_bots,
                allow_claimed_search_bots: self.bot_policy.allow_claimed_search_bots,
                allow_ai_bots: self.bot_policy.allow_ai_bots,
                claimed_search_bot_action: parse_ip_access_action(
                    &self.bot_policy.claimed_search_bot_action,
                )?,
                suspect_bot_action: parse_ip_access_action(&self.bot_policy.suspect_bot_action)?,
            },
            geo_headers: crate::config::l7::IpAccessGeoHeaderConfig {
                enabled: self.geo_headers.enabled,
                trust_only_from_proxy: self.geo_headers.trust_only_from_proxy,
                country_headers: self.geo_headers.country_headers,
                region_headers: self.geo_headers.region_headers,
                city_headers: self.geo_headers.city_headers,
            },
        })
    }
}

fn parse_ip_access_mode(value: &str) -> Result<crate::config::l7::IpAccessMode, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "monitor" => Ok(crate::config::l7::IpAccessMode::Monitor),
        "" | "domestic_only" => Ok(crate::config::l7::IpAccessMode::DomesticOnly),
        "custom" => Ok(crate::config::l7::IpAccessMode::Custom),
        other => Err(format!(
            "IP 地域访问模式仅支持 monitor/domestic_only/custom，收到 '{}'",
            other
        )),
    }
}

fn parse_ip_access_action(value: &str) -> Result<crate::config::l7::IpAccessAction, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "allow" => Ok(crate::config::l7::IpAccessAction::Allow),
        "challenge" => Ok(crate::config::l7::IpAccessAction::Challenge),
        "block" => Ok(crate::config::l7::IpAccessAction::Block),
        "alert" => Ok(crate::config::l7::IpAccessAction::Alert),
        other => Err(format!(
            "IP 地域访问动作仅支持 allow/challenge/block/alert，收到 '{}'",
            other
        )),
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

impl AdaptiveProtectionConfigRequest {
    pub(crate) fn into_config(self) -> Result<crate::config::AdaptiveProtectionConfig, String> {
        Ok(crate::config::AdaptiveProtectionConfig {
            enabled: true,
            mode: crate::config::AdaptiveProtectionMode::Balanced,
            goal: crate::config::AdaptiveProtectionGoal::Balanced,
            cdn_fronted: true,
            allow_emergency_reject: false,
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
        current.bot_detection = crate::config::BotDetectionConfig {
            enabled: self.bot_detection.enabled,
            crawlers: self
                .bot_detection
                .crawlers
                .into_iter()
                .map(|crawler| crate::config::BotCrawlerConfig {
                    enabled: crawler.enabled,
                    name: crawler.name,
                    provider: crawler.provider,
                    category: crawler.category,
                    policy: crawler.policy,
                    tokens: crawler.tokens,
                })
                .collect(),
            providers: self
                .bot_detection
                .providers
                .into_iter()
                .map(|provider| crate::config::BotProviderConfig {
                    enabled: provider.enabled,
                    id: provider.id,
                    urls: provider.urls,
                    mirror_urls: provider.mirror_urls,
                    format: provider.format,
                    reverse_dns_enabled: provider.reverse_dns_enabled,
                    reverse_dns_suffixes: provider.reverse_dns_suffixes,
                })
                .collect(),
        };

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
            auto_defense_enabled: self.auto_defense_enabled,
            auto_defense_auto_apply: self.auto_defense_auto_apply,
            auto_defense_min_confidence: self.auto_defense_min_confidence,
            auto_defense_max_apply_per_tick: self.auto_defense_max_apply_per_tick,
            auto_defense_trigger_cooldown_secs: self.auto_defense_trigger_cooldown_secs,
            auto_defense_fallback_interval_secs: self.auto_defense_fallback_interval_secs,
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
            auto_sync_interval_secs: previous.auto_sync_interval_secs,
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

        let next = L4ConfigUpdateRequest {}.into_config(current, false);

        assert_eq!(next.l4_config.connection_rate_limit, 100);
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
                http2_config: crate::config::l7::Http2Config {
                    max_concurrent_streams: 42,
                    max_frame_size: 32_768,
                    enable_priorities: false,
                    initial_window_size: 32_000,
                    ..crate::config::l7::Http2Config::default()
                },
                ..crate::config::L7Config::default()
            },
            http3_config: crate::config::Http3Config {
                max_concurrent_streams: 24,
                mtu: 1200,
                ..crate::config::Http3Config::default()
            },
            ..Config::default()
        };

        let next = L7ConfigUpdateRequest {
            upstream_healthcheck_enabled: true,
            upstream_failure_mode: "fail_open".to_string(),
            upstream_protocol_policy: "http2_preferred".to_string(),
            upstream_http1_strict_mode: true,
            upstream_http1_allow_connection_reuse: false,
            reject_ambiguous_http1_requests: true,
            reject_http1_transfer_encoding_requests: true,
            reject_body_on_safe_http_methods: true,
            reject_expect_100_continue: true,
            http2_enabled: true,
            bloom_enabled: true,
            listen_addrs: vec!["127.0.0.1:8080".to_string()],
            upstream_endpoint: String::new(),
            http3_enabled: false,
            http3_certificate_path: String::new(),
            http3_private_key_path: String::new(),
            http3_enable_tls13: true,
            ip_access: IpAccessConfigPayload::default(),
        }
        .into_config(current, false)
        .expect("l7 update should succeed");

        assert_eq!(next.l7_config.cc_defense.ip_challenge_threshold, 60);
        assert_eq!(next.l7_config.cc_defense.delay_ms, 150);
        assert_eq!(next.l7_config.http2_config.max_concurrent_streams, 42);
        assert_eq!(next.l7_config.http2_config.max_frame_size, 32_768);
        assert!(!next.l7_config.http2_config.enable_priorities);
        assert_eq!(next.http3_config.max_concurrent_streams, 24);
        assert_eq!(next.http3_config.mtu, 1200);
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
