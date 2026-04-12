use super::super::*;

pub(super) fn normalize_profile_settings(config: &mut Config) {
    if config.runtime_profile.is_minimal() {
        config.api_enabled = false;
        config.bloom_enabled = false;
        config.l4_bloom_false_positive_verification = false;
        config.l7_bloom_false_positive_verification = false;
        config.l4_config.advanced_ddos_enabled = false;
        config.l4_config.connection_rate_limit = config.l4_config.connection_rate_limit.min(64);
        config.l4_config.syn_flood_threshold = config.l4_config.syn_flood_threshold.min(32);
        config.l4_config.max_tracked_ips =
            clamp_or_default(config.l4_config.max_tracked_ips, 512).min(1024);
        config.l4_config.max_blocked_ips =
            clamp_or_default(config.l4_config.max_blocked_ips, 128).min(256);
        config.l4_config.state_ttl_secs = clamp_u64(config.l4_config.state_ttl_secs, 60, 1800, 180);
        config.l7_config.max_request_size =
            clamp_or_default(config.l7_config.max_request_size, 4096);
        config.l7_config.first_byte_timeout_ms =
            clamp_u64(config.l7_config.first_byte_timeout_ms, 250, 10_000, 2_000);
        config.l7_config.read_idle_timeout_ms =
            clamp_u64(config.l7_config.read_idle_timeout_ms, 500, 15_000, 5_000);
        config.l7_config.tls_handshake_timeout_ms = clamp_u64(
            config.l7_config.tls_handshake_timeout_ms,
            500,
            10_000,
            3_000,
        );
        config.l7_config.proxy_connect_timeout_ms = clamp_u64(
            config.l7_config.proxy_connect_timeout_ms,
            250,
            10_000,
            1_500,
        );
        config.l7_config.proxy_write_timeout_ms =
            clamp_u64(config.l7_config.proxy_write_timeout_ms, 500, 15_000, 3_000);
        config.l7_config.proxy_read_timeout_ms =
            clamp_u64(config.l7_config.proxy_read_timeout_ms, 500, 30_000, 10_000);
        config.l7_config.upstream_healthcheck_interval_secs = clamp_u64(
            config.l7_config.upstream_healthcheck_interval_secs,
            1,
            60,
            5,
        );
        config.l7_config.upstream_healthcheck_timeout_ms = clamp_u64(
            config.l7_config.upstream_healthcheck_timeout_ms,
            250,
            10_000,
            1_000,
        );
        config.l4_config.bloom_filter_scale =
            clamp_scale(config.l4_config.bloom_filter_scale, 0.5, 0.1, 1.0);
        config.l7_config.bloom_filter_scale =
            clamp_scale(config.l7_config.bloom_filter_scale, 0.5, 0.1, 1.0);
        config.l4_config.behavior_event_channel_capacity =
            clamp_or_default(config.l4_config.behavior_event_channel_capacity, 2048)
                .clamp(512, 16_384);
    } else {
        config.l4_config.max_tracked_ips = clamp_or_default(config.l4_config.max_tracked_ips, 4096);
        config.l4_config.max_blocked_ips = clamp_or_default(config.l4_config.max_blocked_ips, 1024);
        config.l4_config.state_ttl_secs = clamp_u64(config.l4_config.state_ttl_secs, 60, 3600, 300);
        config.l7_config.max_request_size =
            clamp_or_default(config.l7_config.max_request_size, 8192);
        config.l7_config.first_byte_timeout_ms =
            clamp_u64(config.l7_config.first_byte_timeout_ms, 250, 30_000, 2_000);
        config.l7_config.read_idle_timeout_ms =
            clamp_u64(config.l7_config.read_idle_timeout_ms, 500, 30_000, 5_000);
        config.l7_config.tls_handshake_timeout_ms = clamp_u64(
            config.l7_config.tls_handshake_timeout_ms,
            500,
            15_000,
            3_000,
        );
        config.l7_config.proxy_connect_timeout_ms = clamp_u64(
            config.l7_config.proxy_connect_timeout_ms,
            250,
            15_000,
            1_500,
        );
        config.l7_config.proxy_write_timeout_ms =
            clamp_u64(config.l7_config.proxy_write_timeout_ms, 500, 30_000, 3_000);
        config.l7_config.proxy_read_timeout_ms =
            clamp_u64(config.l7_config.proxy_read_timeout_ms, 500, 60_000, 10_000);
        config.l7_config.upstream_healthcheck_interval_secs = clamp_u64(
            config.l7_config.upstream_healthcheck_interval_secs,
            1,
            120,
            5,
        );
        config.l7_config.upstream_healthcheck_timeout_ms = clamp_u64(
            config.l7_config.upstream_healthcheck_timeout_ms,
            250,
            15_000,
            1_000,
        );
        config.l4_config.bloom_filter_scale =
            clamp_scale(config.l4_config.bloom_filter_scale, 1.0, 0.25, 1.0);
        config.l7_config.bloom_filter_scale =
            clamp_scale(config.l7_config.bloom_filter_scale, 1.0, 0.25, 1.0);
        config.l4_config.behavior_event_channel_capacity =
            clamp_or_default(config.l4_config.behavior_event_channel_capacity, 4096)
                .clamp(1024, 65_536);
    }
}

pub(super) fn normalize_l4_behavior_thresholds(config: &mut Config) {
    config.l4_config.behavior_drop_critical_threshold = config
        .l4_config
        .behavior_drop_critical_threshold
        .clamp(1, config.l4_config.behavior_event_channel_capacity as u64);
    config.l4_config.behavior_fallback_ratio_percent = config
        .l4_config
        .behavior_fallback_ratio_percent
        .clamp(50, 95);
    config
        .l4_config
        .behavior_overload_blocked_connections_threshold = config
        .l4_config
        .behavior_overload_blocked_connections_threshold
        .clamp(64, 65_536);
    config
        .l4_config
        .behavior_overload_active_connections_threshold = config
        .l4_config
        .behavior_overload_active_connections_threshold
        .clamp(256, 262_144);
    config
        .l4_config
        .behavior_normal_connection_budget_per_minute = config
        .l4_config
        .behavior_normal_connection_budget_per_minute
        .clamp(16, 10_000);
    config
        .l4_config
        .behavior_suspicious_connection_budget_per_minute = config
        .l4_config
        .behavior_suspicious_connection_budget_per_minute
        .clamp(
            8,
            config
                .l4_config
                .behavior_normal_connection_budget_per_minute
                .max(8),
        );
    config
        .l4_config
        .behavior_high_risk_connection_budget_per_minute = config
        .l4_config
        .behavior_high_risk_connection_budget_per_minute
        .clamp(
            4,
            config
                .l4_config
                .behavior_suspicious_connection_budget_per_minute
                .max(4),
        );
    config.l4_config.behavior_high_overload_budget_scale_percent = config
        .l4_config
        .behavior_high_overload_budget_scale_percent
        .clamp(25, 100);
    config
        .l4_config
        .behavior_critical_overload_budget_scale_percent = config
        .l4_config
        .behavior_critical_overload_budget_scale_percent
        .clamp(
            10,
            config.l4_config.behavior_high_overload_budget_scale_percent,
        );
    config.l4_config.behavior_high_overload_delay_ms = clamp_u64(
        config.l4_config.behavior_high_overload_delay_ms,
        0,
        2_000,
        15,
    );
    config.l4_config.behavior_critical_overload_delay_ms = clamp_u64(
        config.l4_config.behavior_critical_overload_delay_ms,
        config.l4_config.behavior_high_overload_delay_ms,
        5_000,
        40,
    );
    config.l4_config.behavior_soft_delay_threshold_percent = config
        .l4_config
        .behavior_soft_delay_threshold_percent
        .clamp(50, 400);
    config.l4_config.behavior_hard_delay_threshold_percent = config
        .l4_config
        .behavior_hard_delay_threshold_percent
        .clamp(config.l4_config.behavior_soft_delay_threshold_percent, 600);
    config.l4_config.behavior_soft_delay_ms =
        clamp_u64(config.l4_config.behavior_soft_delay_ms, 0, 2_000, 25);
    config.l4_config.behavior_hard_delay_ms = clamp_u64(
        config.l4_config.behavior_hard_delay_ms,
        config.l4_config.behavior_soft_delay_ms,
        5_000,
        60,
    );
    config.l4_config.behavior_reject_threshold_percent =
        config.l4_config.behavior_reject_threshold_percent.clamp(
            config.l4_config.behavior_hard_delay_threshold_percent,
            1_000,
        );
    config.l4_config.behavior_critical_reject_threshold_percent = config
        .l4_config
        .behavior_critical_reject_threshold_percent
        .clamp(
            config.l4_config.behavior_soft_delay_threshold_percent,
            1_000,
        );
}
