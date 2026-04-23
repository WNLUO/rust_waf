use crate::config::{AiAuditConfig, Config, Http3Config, L4Config, L7Config, RuntimeProfile};
use crate::metrics::MetricsSnapshot;

use super::environment_profile::EnvironmentProfile;

#[derive(Debug, Clone)]
pub struct RuntimePlanningSignals {
    pub storage_queue_usage_percent: u64,
    pub cpu_usage_percent: f64,
    pub avg_proxy_latency_ms: u64,
    pub tls_handshake_timeout_rate_percent: f64,
}

impl RuntimePlanningSignals {
    pub fn from_metrics(
        metrics: &MetricsSnapshot,
        storage_queue_usage_percent: u64,
        cpu_usage_percent: f64,
    ) -> Self {
        let proxied = metrics.proxied_requests.max(1);
        let tls_handshake_timeout_rate_percent =
            metrics.tls_handshake_timeouts as f64 * 100.0 / proxied as f64;
        Self {
            storage_queue_usage_percent,
            cpu_usage_percent,
            avg_proxy_latency_ms: metrics.average_proxy_latency_micros / 1_000,
            tls_handshake_timeout_rate_percent,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DynamicRuntimePlan {
    pub environment: EnvironmentProfile,
    pub request_limit: usize,
    pub connection_limit: usize,
    pub sqlite_queue_capacity: usize,
    pub sqlite_pool_size: usize,
    pub config: Config,
}

pub fn apply_dynamic_runtime_plan(
    mut config: Config,
    metrics: Option<&MetricsSnapshot>,
    storage_queue_usage_percent: Option<u64>,
    cpu_usage_percent: Option<f64>,
) -> DynamicRuntimePlan {
    let environment = EnvironmentProfile::detect();
    let signals = metrics.map(|metrics| {
        RuntimePlanningSignals::from_metrics(
            metrics,
            storage_queue_usage_percent.unwrap_or_default(),
            cpu_usage_percent.unwrap_or(0.0),
        )
    });

    config.runtime_profile = if environment.memory_limit_mb <= 1024 || environment.cpu_cores <= 2 {
        RuntimeProfile::Minimal
    } else {
        RuntimeProfile::Standard
    };

    let request_limit = plan_request_limit(&environment, signals.as_ref());
    let connection_limit = plan_connection_limit(request_limit, &environment);
    let sqlite_queue_capacity = plan_sqlite_queue_capacity(&environment, signals.as_ref());
    let sqlite_pool_size = plan_sqlite_pool_size(&environment, signals.as_ref());

    config.max_concurrent_tasks = request_limit;
    config.sqlite_queue_capacity = sqlite_queue_capacity;
    config.sqlite_pool_size = sqlite_pool_size;
    config.l4_config = plan_l4_config(config.l4_config, &environment, signals.as_ref());
    config.l7_config = plan_l7_config(config.l7_config, &environment, signals.as_ref());
    config.http3_config = plan_http3_config(config.http3_config, &environment, request_limit);
    config.integrations.ai_audit =
        plan_ai_audit_config(config.integrations.ai_audit, &environment, signals.as_ref());

    if environment.memory_limit_mb <= 640 {
        config.http3_config.enabled = false;
        config.integrations.ai_audit.auto_audit_enabled = false;
    }

    DynamicRuntimePlan {
        environment,
        request_limit,
        connection_limit,
        sqlite_queue_capacity,
        sqlite_pool_size,
        config: config.normalized(),
    }
}

fn plan_request_limit(
    environment: &EnvironmentProfile,
    signals: Option<&RuntimePlanningSignals>,
) -> usize {
    let memory_factor = match environment.memory_limit_mb {
        0..=512 => 32,
        513..=768 => 48,
        769..=1024 => 64,
        1025..=2048 => 128,
        2049..=4096 => 256,
        _ => 512,
    };
    let cpu_factor = match environment.cpu_cores {
        0..=1 => 24,
        2 => 48,
        3..=4 => 128,
        _ => 256,
    };
    let fd_factor = environment
        .fd_soft_limit
        .map(|limit| ((limit / 32) as usize).clamp(32, 1024))
        .unwrap_or(256);
    let mut planned = memory_factor.min(cpu_factor.max(memory_factor)).min(fd_factor);

    if let Some(signals) = signals {
        if signals.storage_queue_usage_percent >= 85
            || signals.avg_proxy_latency_ms >= 1500
            || signals.cpu_usage_percent >= 90.0
        {
            planned = planned.saturating_mul(3) / 4;
        } else if signals.storage_queue_usage_percent <= 40
            && signals.avg_proxy_latency_ms <= 400
            && environment.memory_limit_mb >= 2048
        {
            planned = planned.saturating_mul(5) / 4;
        }
    }

    planned.clamp(16, 1024)
}

fn plan_connection_limit(request_limit: usize, environment: &EnvironmentProfile) -> usize {
    let scale = if environment.memory_limit_mb <= 768 { 2 } else { 3 };
    request_limit
        .saturating_mul(scale)
        .clamp(32, (environment.fd_soft_limit.unwrap_or(4096) / 4) as usize)
}

fn plan_sqlite_queue_capacity(
    environment: &EnvironmentProfile,
    signals: Option<&RuntimePlanningSignals>,
) -> usize {
    let mut capacity: usize = match environment.memory_limit_mb {
        0..=512 => 128,
        513..=768 => 192,
        769..=1024 => 256,
        1025..=2048 => 512,
        2049..=4096 => 1024,
        _ => 2048,
    };
    if let Some(signals) = signals {
        if signals.storage_queue_usage_percent >= 85 {
            capacity = capacity.saturating_mul(3) / 4;
        } else if signals.storage_queue_usage_percent <= 25 && environment.memory_limit_mb >= 2048
        {
            capacity = capacity.saturating_mul(5) / 4;
        }
    }
    capacity.clamp(64, 4096)
}

fn plan_sqlite_pool_size(
    environment: &EnvironmentProfile,
    signals: Option<&RuntimePlanningSignals>,
) -> usize {
    let mut pool: usize = match (environment.cpu_cores, environment.memory_limit_mb) {
        (_, 0..=512) => 2,
        (0..=2, _) => 3,
        (_, 513..=1024) => 3,
        (3..=4, _) => 4,
        (_, 1025..=4096) => 6,
        _ => 8,
    };
    if environment.containerized && environment.memory_limit_mb <= 768 {
        pool = pool.min(2);
    }
    if let Some(signals) = signals {
        if signals.storage_queue_usage_percent >= 90 {
            pool = pool.saturating_sub(1).max(1);
        }
    }
    pool.clamp(1, 16)
}

fn plan_l4_config(
    mut config: L4Config,
    environment: &EnvironmentProfile,
    signals: Option<&RuntimePlanningSignals>,
) -> L4Config {
    config.max_tracked_ips = match environment.memory_limit_mb {
        0..=512 => 256,
        513..=768 => 512,
        769..=1024 => 1024,
        1025..=2048 => 2048,
        _ => 4096,
    };
    config.max_blocked_ips = (config.max_tracked_ips / 4).clamp(64, 1024);
    config.behavior_event_channel_capacity = match environment.memory_limit_mb {
        0..=512 => 512,
        513..=768 => 1024,
        769..=1024 => 1536,
        1025..=2048 => 2048,
        _ => 4096,
    };
    config.connection_rate_limit = config
        .connection_rate_limit
        .min((environment.cpu_cores.max(1) * 48).clamp(32, 512));
    config.syn_flood_threshold = config
        .syn_flood_threshold
        .min((environment.cpu_cores.max(1) * 24).clamp(16, 256));
    config.bloom_filter_scale = if environment.memory_limit_mb <= 768 {
        0.20
    } else if environment.memory_limit_mb <= 1024 {
        0.35
    } else if environment.memory_limit_mb <= 2048 {
        0.6
    } else {
        1.0
    };
    if let Some(signals) = signals {
        if signals.storage_queue_usage_percent >= 80 {
            config.behavior_event_channel_capacity =
                config.behavior_event_channel_capacity.saturating_mul(3) / 4;
        }
    }
    config
}

fn plan_l7_config(
    mut config: L7Config,
    environment: &EnvironmentProfile,
    signals: Option<&RuntimePlanningSignals>,
) -> L7Config {
    config.max_request_size = match environment.memory_limit_mb {
        0..=512 => 4096,
        513..=1024 => 6144,
        _ => 8192,
    };
    config.http2_config.enabled = config.http2_config.enabled && environment.memory_limit_mb > 512;
    config.http2_config.max_concurrent_streams = match environment.memory_limit_mb {
        0..=512 => 16,
        513..=768 => 24,
        769..=1024 => 32,
        1025..=2048 => 48,
        _ => 100,
    };
    config.http2_config.initial_window_size = match environment.memory_limit_mb {
        0..=768 => 16_384,
        769..=1024 => 32_768,
        _ => 65_535,
    };
    let latency_ms = signals.map(|item| item.avg_proxy_latency_ms).unwrap_or(0);
    let connect_floor = if latency_ms >= 1000 { 3_000 } else { 1_500 };
    let read_floor = if latency_ms >= 1000 { 20_000 } else { 10_000 };
    config.first_byte_timeout_ms = if environment.memory_limit_mb <= 768 {
        1_500
    } else {
        2_000
    };
    config.read_idle_timeout_ms = if environment.memory_limit_mb <= 768 {
        3_000
    } else {
        5_000
    };
    config.tls_handshake_timeout_ms = if environment.cpu_cores <= 2 { 4_000 } else { 3_000 };
    config.proxy_connect_timeout_ms = connect_floor;
    config.proxy_write_timeout_ms = if latency_ms >= 1000 { 5_000 } else { 3_000 };
    config.proxy_read_timeout_ms = read_floor;
    config.upstream_healthcheck_interval_secs = if environment.memory_limit_mb <= 768 {
        10
    } else {
        5
    };
    config.upstream_healthcheck_timeout_ms = if latency_ms >= 1000 { 2_000 } else { 1_000 };
    config.slow_attack_defense.idle_keepalive_timeout_ms = if environment.memory_limit_mb <= 768 {
        5_000
    } else {
        10_000
    };
    config.bloom_filter_scale = if environment.memory_limit_mb <= 768 {
        0.20
    } else if environment.memory_limit_mb <= 1024 {
        0.35
    } else if environment.memory_limit_mb <= 2048 {
        0.6
    } else {
        1.0
    };
    config
}

fn plan_http3_config(
    mut config: Http3Config,
    environment: &EnvironmentProfile,
    request_limit: usize,
) -> Http3Config {
    if environment.memory_limit_mb <= 768 {
        config.enabled = false;
        config.max_concurrent_streams = 8;
        config.idle_timeout_secs = 15;
        config.enable_connection_migration = false;
        config.qpack_table_size = 1024;
        return config;
    }

    config.max_concurrent_streams = request_limit.clamp(16, 128);
    config.idle_timeout_secs = if environment.memory_limit_mb <= 1024 { 30 } else { 120 };
    config.enable_connection_migration = environment.memory_limit_mb > 1024;
    config.qpack_table_size = if environment.memory_limit_mb <= 1024 {
        1024
    } else {
        4096
    };
    config
}

fn plan_ai_audit_config(
    mut config: AiAuditConfig,
    environment: &EnvironmentProfile,
    signals: Option<&RuntimePlanningSignals>,
) -> AiAuditConfig {
    let low_memory = environment.memory_limit_mb <= 768;
    config.timeout_ms = if low_memory { 8_000 } else { 15_000 };
    config.event_sample_limit = match environment.memory_limit_mb {
        0..=512 => 24,
        513..=768 => 48,
        769..=1024 => 72,
        1025..=2048 => 96,
        _ => 120,
    };
    config.recent_event_limit = match environment.memory_limit_mb {
        0..=768 => 6,
        769..=1024 => 8,
        _ => 12,
    };
    config.max_active_temp_policies = match environment.memory_limit_mb {
        0..=768 => 6,
        769..=1024 => 10,
        1025..=2048 => 16,
        _ => 24,
    };
    if low_memory {
        config.auto_defense_max_apply_per_tick = 1;
        config.auto_audit_enabled = false;
        config.include_raw_event_samples = false;
    }
    if let Some(signals) = signals {
        if signals.storage_queue_usage_percent >= 80 || signals.avg_proxy_latency_ms >= 1500 {
            config.event_sample_limit = (config.event_sample_limit / 2).max(12);
            config.recent_event_limit = (config.recent_event_limit / 2).max(4);
        }
        if signals.tls_handshake_timeout_rate_percent >= 5.0 {
            config.timeout_ms = config.timeout_ms.min(6_000);
        }
    }
    config
}
