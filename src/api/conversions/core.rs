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
            https_listen_addr: display_https_listen_port(&config.gateway_config.https_listen_addr),
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
                crate::config::l7::SafeLineInterceptMatchMode::Strict => "strict".to_string(),
                crate::config::l7::SafeLineInterceptMatchMode::Relaxed => "relaxed".to_string(),
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

impl HeaderOperationPayload {
    pub(super) fn from_config(config: &HeaderOperation) -> Self {
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

    pub(super) fn into_config(self) -> Result<HeaderOperation, String> {
        let scope = match self.scope.trim().to_ascii_lowercase().as_str() {
            "request" => HeaderOperationScope::Request,
            "response" => HeaderOperationScope::Response,
            other => return Err(format!("Header 操作范围仅支持 request/response，收到 '{}'", other)),
        };
        let action = match self.action.trim().to_ascii_lowercase().as_str() {
            "set" => HeaderOperationAction::Set,
            "add" => HeaderOperationAction::Add,
            "remove" => HeaderOperationAction::Remove,
            other => return Err(format!("Header 操作仅支持 set/add/remove，收到 '{}'", other)),
        };

        Ok(HeaderOperation {
            scope,
            action,
            header: self.header.trim().to_ascii_lowercase(),
            value: self.value.trim().to_string(),
        })
    }
}

impl GlobalSettingsResponse {
    pub(super) fn from_config(config: &Config) -> Self {
        let http_port = config
            .listen_addrs
            .iter()
            .find(|addr| !addr.starts_with('['))
            .map(|addr| display_https_listen_port(addr))
            .or_else(|| config.listen_addrs.first().map(|addr| display_https_listen_port(addr)))
            .unwrap_or_default();

        Self {
            http_port,
            https_port: display_https_listen_port(&config.gateway_config.https_listen_addr),
            listen_ipv6: config.gateway_config.listen_ipv6,
            enable_http1_0: config.gateway_config.enable_http1_0,
            http2_enabled: config.l7_config.http2_config.enabled,
            source_ip_strategy: match config.gateway_config.source_ip_strategy {
                SourceIpStrategy::Connection => "connection".to_string(),
                SourceIpStrategy::XForwardedForFirst => "x_forwarded_for_first".to_string(),
                SourceIpStrategy::XForwardedForLast => "x_forwarded_for_last".to_string(),
                SourceIpStrategy::XForwardedForLastButOne => {
                    "x_forwarded_for_last_but_one".to_string()
                }
                SourceIpStrategy::XForwardedForLastButTwo => {
                    "x_forwarded_for_last_but_two".to_string()
                }
                SourceIpStrategy::XForwardedForAny => "x_forwarded_for_any".to_string(),
                SourceIpStrategy::Header => "header".to_string(),
                SourceIpStrategy::ProxyProtocol => "proxy_protocol".to_string(),
            },
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
            fallback_self_signed_certificate: config.gateway_config.fallback_self_signed_certificate,
            ssl_protocols: config.gateway_config.ssl_protocols.clone(),
            ssl_ciphers: config.gateway_config.ssl_ciphers.clone(),
            header_operations: config
                .gateway_config
                .header_operations
                .iter()
                .map(HeaderOperationPayload::from_config)
                .collect(),
            group_management_enabled: config.gateway_config.group_management_enabled,
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
            "replace_and_block_ip" => crate::config::l7::SafeLineInterceptAction::ReplaceAndBlockIp,
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
        current.integrations.safeline = self.safeline.into_config();

        Ok(current.normalized())
    }
}

impl GlobalSettingsUpdateRequest {
    pub(super) fn into_config(self, mut current: Config) -> Result<Config, String> {
        let http_listen_addr = normalize_https_listen_addr_input(&self.http_port)?;
        if http_listen_addr.is_empty() {
            return Err("HTTP 入口端口不能为空".to_string());
        }
        let https_listen_addr = normalize_https_listen_addr_input(&self.https_port)?;
        let mut listen_addrs = vec![http_listen_addr];
        if self.listen_ipv6 {
            let port = listen_addrs[0]
                .parse::<SocketAddr>()
                .map_err(|err| format!("HTTP 入口地址无效: {}", err))?
                .port();
            listen_addrs.push(format!("[::]:{port}"));
        }

        let source_ip_strategy = match self.source_ip_strategy.trim().to_ascii_lowercase().as_str() {
            "connection" => SourceIpStrategy::Connection,
            "x_forwarded_for_first" => SourceIpStrategy::XForwardedForFirst,
            "x_forwarded_for_last" => SourceIpStrategy::XForwardedForLast,
            "x_forwarded_for_last_but_one" => SourceIpStrategy::XForwardedForLastButOne,
            "x_forwarded_for_last_but_two" => SourceIpStrategy::XForwardedForLastButTwo,
            "x_forwarded_for_any" => SourceIpStrategy::XForwardedForAny,
            "header" => SourceIpStrategy::Header,
            "proxy_protocol" => SourceIpStrategy::ProxyProtocol,
            other => return Err(format!("源 IP 获取方式不支持 '{}'", other)),
        };

        let header_operations = self
            .header_operations
            .into_iter()
            .map(HeaderOperationPayload::into_config)
            .collect::<Result<Vec<_>, _>>()?;

        current.listen_addrs = listen_addrs;
        current.gateway_config.https_listen_addr = https_listen_addr;
        current.gateway_config.listen_ipv6 = self.listen_ipv6;
        current.gateway_config.enable_http1_0 = self.enable_http1_0;
        current.gateway_config.source_ip_strategy = source_ip_strategy;
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
        current.gateway_config.fallback_self_signed_certificate = self.fallback_self_signed_certificate;
        current.gateway_config.ssl_protocols = self.ssl_protocols;
        current.gateway_config.ssl_ciphers = self.ssl_ciphers;
        current.gateway_config.header_operations = header_operations;
        current.gateway_config.group_management_enabled = self.group_management_enabled;
        current.l7_config.http2_config.enabled = self.http2_enabled;

        Ok(current.normalized())
    }
}

fn display_https_listen_port(value: &str) -> String {
    value
        .trim()
        .parse::<SocketAddr>()
        .map(|addr| addr.port().to_string())
        .unwrap_or_else(|_| value.trim().to_string())
}

fn normalize_https_listen_addr_input(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }

    if let Ok(port) = trimmed.parse::<u16>() {
        if port == 0 {
            return Err("HTTPS 入口端口不能为 0".to_string());
        }
        return Ok(format!("0.0.0.0:{port}"));
    }

    let addr = trimmed
        .parse::<SocketAddr>()
        .map_err(|err| format!("HTTPS 入口 '{}' 无效: {}", trimmed, err))?;
    if addr.port() == 0 {
        return Err("HTTPS 入口端口不能为 0".to_string());
    }

    Ok(format!("0.0.0.0:{}", addr.port()))
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

