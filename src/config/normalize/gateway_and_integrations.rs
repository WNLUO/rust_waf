use super::super::*;

pub(super) fn normalize_l7_settings(config: &mut Config) {
    config.l7_config.real_ip_headers = config
        .l7_config
        .real_ip_headers
        .iter()
        .map(|header| header.trim().to_ascii_lowercase())
        .filter(|header| !header.is_empty())
        .collect();
    if config.l7_config.real_ip_headers.is_empty() {
        config.l7_config.real_ip_headers = l7::default_real_ip_headers();
    }

    config.l7_config.trusted_proxy_cidrs = config
        .l7_config
        .trusted_proxy_cidrs
        .iter()
        .map(|cidr| cidr.trim().to_string())
        .filter(|cidr| !cidr.is_empty())
        .collect();
    config.l4_config.trusted_cdn.manual_cidrs =
        normalize_cidr_list(&config.l4_config.trusted_cdn.manual_cidrs);
    config.l4_config.trusted_cdn.edgeone_overseas.synced_cidrs =
        normalize_cidr_list(&config.l4_config.trusted_cdn.edgeone_overseas.synced_cidrs);
    config
        .l4_config
        .trusted_cdn
        .edgeone_overseas
        .last_sync_message = config
        .l4_config
        .trusted_cdn
        .edgeone_overseas
        .last_sync_message
        .trim()
        .to_string();
    config.l4_config.trusted_cdn.aliyun_esa.site_id = config
        .l4_config
        .trusted_cdn
        .aliyun_esa
        .site_id
        .trim()
        .to_string();
    config.l4_config.trusted_cdn.aliyun_esa.access_key_id = config
        .l4_config
        .trusted_cdn
        .aliyun_esa
        .access_key_id
        .trim()
        .to_string();
    config.l4_config.trusted_cdn.aliyun_esa.access_key_secret = config
        .l4_config
        .trusted_cdn
        .aliyun_esa
        .access_key_secret
        .trim()
        .to_string();
    config.l4_config.trusted_cdn.aliyun_esa.endpoint = config
        .l4_config
        .trusted_cdn
        .aliyun_esa
        .endpoint
        .trim()
        .to_string();
    if config.l4_config.trusted_cdn.aliyun_esa.endpoint.is_empty() {
        config.l4_config.trusted_cdn.aliyun_esa.endpoint =
            crate::config::l4::TrustedCdnAliyunEsaConfig::default().endpoint;
    }
    config.l4_config.trusted_cdn.aliyun_esa.synced_cidrs =
        normalize_cidr_list(&config.l4_config.trusted_cdn.aliyun_esa.synced_cidrs);
    config.l4_config.trusted_cdn.aliyun_esa.last_sync_message = config
        .l4_config
        .trusted_cdn
        .aliyun_esa
        .last_sync_message
        .trim()
        .to_string();
    config.l4_config.trusted_cdn.sync_interval_value = config
        .l4_config
        .trusted_cdn
        .sync_interval_value
        .clamp(1, 365);
    config.l7_config.cc_defense.request_window_secs =
        clamp_u64(config.l7_config.cc_defense.request_window_secs, 3, 120, 10);
    config.l7_config.cc_defense.ip_challenge_threshold = config
        .l7_config
        .cc_defense
        .ip_challenge_threshold
        .clamp(10, 10_000);
    config.l7_config.cc_defense.ip_block_threshold =
        config.l7_config.cc_defense.ip_block_threshold.clamp(
            cc_block_floor(config.l7_config.cc_defense.ip_challenge_threshold, 10),
            20_000,
        );
    config.l7_config.cc_defense.host_challenge_threshold = config
        .l7_config
        .cc_defense
        .host_challenge_threshold
        .clamp(5, config.l7_config.cc_defense.ip_challenge_threshold.max(5));
    config.l7_config.cc_defense.host_block_threshold =
        config.l7_config.cc_defense.host_block_threshold.clamp(
            cc_block_floor(config.l7_config.cc_defense.host_challenge_threshold, 5),
            config.l7_config.cc_defense.ip_block_threshold.max(5),
        );
    config.l7_config.cc_defense.route_challenge_threshold =
        config.l7_config.cc_defense.route_challenge_threshold.clamp(
            3,
            config.l7_config.cc_defense.host_challenge_threshold.max(3),
        );
    config.l7_config.cc_defense.route_block_threshold =
        config.l7_config.cc_defense.route_block_threshold.clamp(
            cc_block_floor(config.l7_config.cc_defense.route_challenge_threshold, 3),
            config.l7_config.cc_defense.host_block_threshold.max(3),
        );
    config.l7_config.cc_defense.hot_path_challenge_threshold = config
        .l7_config
        .cc_defense
        .hot_path_challenge_threshold
        .clamp(32, 200_000);
    config.l7_config.cc_defense.hot_path_block_threshold =
        config.l7_config.cc_defense.hot_path_block_threshold.clamp(
            cc_block_floor(config.l7_config.cc_defense.hot_path_challenge_threshold, 32),
            400_000,
        );
    config.l7_config.cc_defense.delay_threshold_percent = config
        .l7_config
        .cc_defense
        .delay_threshold_percent
        .clamp(25, 95);
    config.l7_config.cc_defense.delay_ms =
        clamp_u64(config.l7_config.cc_defense.delay_ms, 0, 5_000, 150);
    config.l7_config.cc_defense.challenge_ttl_secs = clamp_u64(
        config.l7_config.cc_defense.challenge_ttl_secs,
        30,
        86_400,
        1_800,
    );
    config.l7_config.cc_defense.challenge_cookie_name = config
        .l7_config
        .cc_defense
        .challenge_cookie_name
        .trim()
        .to_ascii_lowercase();
    if config.l7_config.cc_defense.challenge_cookie_name.is_empty() {
        config.l7_config.cc_defense.challenge_cookie_name = "rwaf_cc".to_string();
    }
    config.l7_config.cc_defense.static_request_weight_percent = config
        .l7_config
        .cc_defense
        .static_request_weight_percent
        .clamp(5, 100);
    config.l7_config.cc_defense.page_subresource_weight_percent = config
        .l7_config
        .cc_defense
        .page_subresource_weight_percent
        .clamp(1, config.l7_config.cc_defense.static_request_weight_percent);
    config.l7_config.cc_defense.page_load_grace_secs =
        clamp_u64(config.l7_config.cc_defense.page_load_grace_secs, 1, 15, 3);
    config.l7_config.cc_defense.hard_route_block_multiplier = config
        .l7_config
        .cc_defense
        .hard_route_block_multiplier
        .clamp(1, 20);
    config.l7_config.cc_defense.hard_host_block_multiplier = config
        .l7_config
        .cc_defense
        .hard_host_block_multiplier
        .clamp(1, 20);
    config.l7_config.cc_defense.hard_ip_block_multiplier = config
        .l7_config
        .cc_defense
        .hard_ip_block_multiplier
        .clamp(1, 20);
    config.l7_config.cc_defense.hard_hot_path_block_multiplier = config
        .l7_config
        .cc_defense
        .hard_hot_path_block_multiplier
        .clamp(1, 20);
    config
        .l7_config
        .slow_attack_defense
        .header_min_bytes_per_sec = config
        .l7_config
        .slow_attack_defense
        .header_min_bytes_per_sec
        .clamp(16, 64 * 1024);
    config.l7_config.slow_attack_defense.body_min_bytes_per_sec = config
        .l7_config
        .slow_attack_defense
        .body_min_bytes_per_sec
        .clamp(16, 256 * 1024);
    config
        .l7_config
        .slow_attack_defense
        .idle_keepalive_timeout_ms = clamp_u64(
        config
            .l7_config
            .slow_attack_defense
            .idle_keepalive_timeout_ms,
        1_000,
        120_000,
        15_000,
    );
    config.l7_config.slow_attack_defense.event_window_secs = clamp_u64(
        config.l7_config.slow_attack_defense.event_window_secs,
        30,
        86_400,
        300,
    );
    config.l7_config.slow_attack_defense.max_events_per_window = config
        .l7_config
        .slow_attack_defense
        .max_events_per_window
        .clamp(1, 1_000);
    config.l7_config.slow_attack_defense.block_duration_secs = clamp_u64(
        config.l7_config.slow_attack_defense.block_duration_secs,
        30,
        86_400,
        900,
    );

    if config.l7_config.upstream_http1_strict_mode {
        config.l7_config.upstream_http1_allow_connection_reuse = false;
    }

    config.l7_config.safeline_intercept.max_body_bytes = clamp_or_default(
        config.l7_config.safeline_intercept.max_body_bytes,
        32 * 1024,
    )
    .min(512 * 1024);
    config.l7_config.safeline_intercept.block_duration_secs = clamp_u64(
        config.l7_config.safeline_intercept.block_duration_secs,
        30,
        86_400,
        600,
    );
    config
        .l7_config
        .safeline_intercept
        .response_template
        .content_type = config
        .l7_config
        .safeline_intercept
        .response_template
        .content_type
        .trim()
        .to_string();
    if config
        .l7_config
        .safeline_intercept
        .response_template
        .content_type
        .is_empty()
    {
        config
            .l7_config
            .safeline_intercept
            .response_template
            .content_type = default_rule_response_content_type();
    }
}

fn cc_block_floor(challenge_threshold: u32, minimum: u32) -> u32 {
    challenge_threshold
        .max(minimum)
        .saturating_mul(2)
        .max(minimum)
}

fn normalize_cidr_list(values: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for cidr in values
        .iter()
        .map(|cidr| cidr.trim())
        .filter(|cidr| !cidr.is_empty())
    {
        if !normalized.iter().any(|item| item == cidr) {
            normalized.push(cidr.to_string());
        }
    }
    normalized
}

pub(super) fn normalize_console_and_gateway(config: &mut Config) {
    config.console_settings.gateway_name = config.console_settings.gateway_name.trim().to_string();
    if config.console_settings.gateway_name.is_empty() {
        config.console_settings.gateway_name = default_gateway_name();
    }
    config.console_settings.notes = config.console_settings.notes.trim().to_string();

    config.gateway_config.https_listen_addr =
        match normalize_https_listen_addr(&config.gateway_config.https_listen_addr) {
            Ok(addr) => addr,
            Err(err) => {
                log::warn!("{}", err);
                String::new()
            }
        };
    if config.gateway_config.default_certificate_id == Some(0) {
        config.gateway_config.default_certificate_id = None;
    }
    config.gateway_config.custom_source_ip_header = config
        .gateway_config
        .custom_source_ip_header
        .trim()
        .to_ascii_lowercase();
    config.gateway_config.rewrite_host_value =
        config.gateway_config.rewrite_host_value.trim().to_string();
    if config.gateway_config.rewrite_host_enabled
        && config.gateway_config.rewrite_host_value.is_empty()
    {
        config.gateway_config.rewrite_host_value = "$http_host".to_string();
    }
    config.gateway_config.ssl_protocols =
        normalize_supported_ssl_protocols(&config.gateway_config.ssl_protocols);
    if config.gateway_config.ssl_protocols.is_empty() {
        config.gateway_config.ssl_protocols = gateway::default_ssl_protocols();
    }
    config.gateway_config.ssl_ciphers = config.gateway_config.ssl_ciphers.trim().to_string();
    config.gateway_config.header_operations = config
        .gateway_config
        .header_operations
        .drain(..)
        .filter_map(|mut item| {
            item.header = item.header.trim().to_ascii_lowercase();
            item.value = item.value.trim().to_string();
            if item.header.is_empty() {
                None
            } else {
                Some(item)
            }
        })
        .collect();

    // QUIC shares the same public entry port as HTTPS to avoid double-configuring edge ports.
    config.http3_config.listen_addr = config.gateway_config.https_listen_addr.clone();
}

pub(super) fn normalize_integrations_and_admin(config: &mut Config) {
    config.integrations.safeline.base_url =
        normalize_base_url(&config.integrations.safeline.base_url);
    config.integrations.safeline.auto_sync_interval_secs = clamp_u64(
        config.integrations.safeline.auto_sync_interval_secs,
        15,
        86_400,
        default_safeline_auto_sync_interval_secs(),
    );
    config.integrations.safeline.api_token =
        config.integrations.safeline.api_token.trim().to_string();
    config.integrations.safeline.username =
        config.integrations.safeline.username.trim().to_string();
    config.integrations.safeline.password =
        config.integrations.safeline.password.trim().to_string();
    config.integrations.safeline.openapi_doc_path = normalize_path(
        &config.integrations.safeline.openapi_doc_path,
        "/openapi_doc/",
    );
    config.integrations.safeline.auth_probe_path = normalize_path(
        &config.integrations.safeline.auth_probe_path,
        "/api/IPGroupAPI",
    );
    config.integrations.safeline.site_list_path = normalize_path(
        &config.integrations.safeline.site_list_path,
        "/api/WebsiteAPI",
    );
    config.integrations.safeline.event_list_path = normalize_path(
        &config.integrations.safeline.event_list_path,
        "/api/AttackLogAPI",
    );
    config.integrations.safeline.blocklist_sync_path = normalize_path(
        &config.integrations.safeline.blocklist_sync_path,
        "/api/IPGroupAPI",
    );
    config.integrations.safeline.blocklist_delete_path = normalize_path(
        &config.integrations.safeline.blocklist_delete_path,
        "/api/IPGroupAPI",
    );
    config.integrations.safeline.blocklist_ip_group_ids =
        normalize_string_list(&config.integrations.safeline.blocklist_ip_group_ids);

    config.integrations.ai_audit.model = config.integrations.ai_audit.model.trim().to_string();
    config.integrations.ai_audit.base_url =
        normalize_base_url(&config.integrations.ai_audit.base_url);
    config.integrations.ai_audit.api_key = config.integrations.ai_audit.api_key.trim().to_string();
    config.integrations.ai_audit.timeout_ms = clamp_u64(
        config.integrations.ai_audit.timeout_ms,
        1_000,
        120_000,
        15_000,
    );

    config.admin_api_auth.bearer_token = config.admin_api_auth.bearer_token.trim().to_string();
    config.admin_api_auth.enabled =
        config.admin_api_auth.enabled || !config.admin_api_auth.bearer_token.is_empty();
}

fn normalize_supported_ssl_protocols(protocols: &[String]) -> Vec<String> {
    normalize_string_list(protocols)
        .into_iter()
        .filter_map(|value| match value.to_ascii_lowercase().as_str() {
            "tlsv1.2" | "tls1.2" | "tls12" => Some("TLSv1.2".to_string()),
            "tlsv1.3" | "tls1.3" | "tls13" => Some("TLSv1.3".to_string()),
            _ => None,
        })
        .collect()
}
