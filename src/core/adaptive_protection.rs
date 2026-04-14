use crate::config::l7::CcDefenseConfig;
use crate::config::{
    AdaptiveProtectionConfig, AdaptiveProtectionGoal, AdaptiveProtectionMode, Config,
};
use crate::core::AutoTuningRuntimeSnapshot;
use crate::metrics::MetricsSnapshot;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct AdaptiveProtectionRuntimeSnapshot {
    pub enabled: bool,
    pub mode: String,
    pub goal: String,
    pub system_pressure: String,
    pub reasons: Vec<String>,
    pub l4: AdaptiveL4RuntimePolicy,
    pub l7: AdaptiveL7RuntimePolicy,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdaptiveL4RuntimePolicy {
    pub normal_connection_budget_per_minute: u32,
    pub suspicious_connection_budget_per_minute: u32,
    pub high_risk_connection_budget_per_minute: u32,
    pub soft_delay_ms: u64,
    pub hard_delay_ms: u64,
    pub high_overload_delay_ms: u64,
    pub critical_overload_delay_ms: u64,
    pub reject_threshold_percent: u16,
    pub critical_reject_threshold_percent: u16,
    pub emergency_reject_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdaptiveL7RuntimePolicy {
    pub request_window_secs: u64,
    pub delay_ms: u64,
    pub route_challenge_threshold: u32,
    pub route_block_threshold: u32,
    pub ip_challenge_threshold: u32,
    pub ip_block_threshold: u32,
    pub challenge_enabled: bool,
}

impl Default for AdaptiveProtectionRuntimeSnapshot {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "balanced".to_string(),
            goal: "balanced".to_string(),
            system_pressure: "normal".to_string(),
            reasons: vec![],
            l4: AdaptiveL4RuntimePolicy {
                normal_connection_budget_per_minute: 960,
                suspicious_connection_budget_per_minute: 480,
                high_risk_connection_budget_per_minute: 168,
                soft_delay_ms: 25,
                hard_delay_ms: 60,
                high_overload_delay_ms: 15,
                critical_overload_delay_ms: 40,
                reject_threshold_percent: 300,
                critical_reject_threshold_percent: 200,
                emergency_reject_enabled: false,
            },
            l7: AdaptiveL7RuntimePolicy {
                request_window_secs: 10,
                delay_ms: 150,
                route_challenge_threshold: 24,
                route_block_threshold: 48,
                ip_challenge_threshold: 60,
                ip_block_threshold: 120,
                challenge_enabled: true,
            },
        }
    }
}

pub fn build_runtime_snapshot(
    config: &Config,
    auto: &AutoTuningRuntimeSnapshot,
    metrics: Option<&MetricsSnapshot>,
) -> AdaptiveProtectionRuntimeSnapshot {
    let adaptive = &config.adaptive_protection;
    let capacity_scale = capacity_scale(auto);
    let pressure = derive_pressure(metrics, auto);
    let mut reasons = pressure.reasons;
    if adaptive.cdn_fronted {
        reasons.push("cdn_fronted_profile".to_string());
    }

    let (l4_budgets, l4_delays, l4_rejects) =
        derive_l4_policy_parts(adaptive, capacity_scale, pressure.level.as_str());
    let l7 = derive_l7_policy(
        adaptive,
        pressure.level.as_str(),
        &config.l7_config.cc_defense,
    );

    AdaptiveProtectionRuntimeSnapshot {
        enabled: adaptive.enabled,
        mode: mode_label(adaptive.mode).to_string(),
        goal: goal_label(adaptive.goal).to_string(),
        system_pressure: pressure.level,
        reasons,
        l4: AdaptiveL4RuntimePolicy {
            normal_connection_budget_per_minute: l4_budgets.0,
            suspicious_connection_budget_per_minute: l4_budgets.1,
            high_risk_connection_budget_per_minute: l4_budgets.2,
            soft_delay_ms: l4_delays.0,
            hard_delay_ms: l4_delays.1,
            high_overload_delay_ms: l4_delays.2,
            critical_overload_delay_ms: l4_delays.3,
            reject_threshold_percent: l4_rejects.0,
            critical_reject_threshold_percent: l4_rejects.1,
            emergency_reject_enabled: adaptive.allow_emergency_reject && !adaptive.cdn_fronted,
        },
        l7,
    }
}

pub fn derive_effective_cc_config(
    config: &Config,
    runtime: &AdaptiveProtectionRuntimeSnapshot,
) -> CcDefenseConfig {
    let mut next = config.l7_config.cc_defense.clone();
    if !config.adaptive_protection.enabled {
        return next;
    }

    next.request_window_secs = runtime.l7.request_window_secs;
    next.delay_ms = runtime.l7.delay_ms;
    next.route_challenge_threshold = runtime.l7.route_challenge_threshold;
    next.route_block_threshold = runtime.l7.route_block_threshold;
    next.ip_challenge_threshold = runtime.l7.ip_challenge_threshold;
    next.ip_block_threshold = runtime.l7.ip_block_threshold;
    next.enabled = runtime.l7.challenge_enabled;
    next
}

pub fn apply_l4_runtime_policy(
    config: &mut crate::config::L4Config,
    runtime: &AdaptiveProtectionRuntimeSnapshot,
) {
    if !config.ddos_protection_enabled {
        return;
    }

    config.behavior_normal_connection_budget_per_minute =
        runtime.l4.normal_connection_budget_per_minute;
    config.behavior_suspicious_connection_budget_per_minute =
        runtime.l4.suspicious_connection_budget_per_minute;
    config.behavior_high_risk_connection_budget_per_minute =
        runtime.l4.high_risk_connection_budget_per_minute;
    config.behavior_soft_delay_ms = runtime.l4.soft_delay_ms;
    config.behavior_hard_delay_ms = runtime.l4.hard_delay_ms;
    config.behavior_high_overload_delay_ms = runtime.l4.high_overload_delay_ms;
    config.behavior_critical_overload_delay_ms = runtime.l4.critical_overload_delay_ms;
    config.behavior_reject_threshold_percent = runtime.l4.reject_threshold_percent;
    config.behavior_critical_reject_threshold_percent =
        runtime.l4.critical_reject_threshold_percent;
}

fn capacity_scale(auto: &AutoTuningRuntimeSnapshot) -> f64 {
    let cpu = auto.detected_cpu_cores.max(1) as f64;
    let mem = auto.detected_memory_limit_mb.unwrap_or(2048) as f64;
    let cpu_scale = if cpu >= 32.0 {
        1.35
    } else if cpu >= 16.0 {
        1.15
    } else if cpu <= 2.0 {
        0.7
    } else if cpu <= 4.0 {
        0.85
    } else {
        1.0
    };
    let mem_scale = if mem >= 32768.0 {
        1.2
    } else if mem >= 8192.0 {
        1.0
    } else if mem <= 1024.0 {
        0.75
    } else {
        0.9
    };
    ((cpu_scale + mem_scale) / 2.0_f64).clamp(0.65_f64, 1.5_f64)
}

struct DerivedPressure {
    level: String,
    reasons: Vec<String>,
}

fn derive_pressure(
    metrics: Option<&MetricsSnapshot>,
    auto: &AutoTuningRuntimeSnapshot,
) -> DerivedPressure {
    let mut score = 0u8;
    let mut reasons = Vec::new();

    if auto.last_observed_avg_proxy_latency_ms > 250 {
        score += 1;
        reasons.push("proxy_latency_elevated".to_string());
    }
    if auto.last_observed_avg_proxy_latency_ms > 800 {
        score += 2;
        reasons.push("proxy_latency_high".to_string());
    }
    if auto.last_observed_tls_handshake_timeout_rate_percent > 0.1 {
        score += 1;
        reasons.push("tls_timeout_observed".to_string());
    }
    if auto.last_observed_bucket_reject_rate_percent > 0.1 {
        score += 1;
        reasons.push("bucket_reject_observed".to_string());
    }

    if let Some(metrics) = metrics {
        if metrics.trusted_proxy_permit_drops > 0 {
            score += 2;
            reasons.push("request_permit_pressure".to_string());
        }
        if metrics.tls_handshake_failures + metrics.tls_handshake_timeouts > 0 {
            score += 1;
            reasons.push("handshake_errors_present".to_string());
        }
        if metrics.l7_cc_challenges + metrics.l7_cc_blocks > 20 {
            score += 1;
            reasons.push("l7_pressure_detected".to_string());
        }
    }

    let level = match score {
        0..=1 => "normal",
        2..=3 => "elevated",
        4..=5 => "high",
        _ => "attack",
    };

    DerivedPressure {
        level: level.to_string(),
        reasons,
    }
}

fn derive_l4_policy_parts(
    adaptive: &AdaptiveProtectionConfig,
    capacity_scale: f64,
    pressure: &str,
) -> ((u32, u32, u32), (u64, u64, u64, u64), (u16, u16)) {
    let base_budget = match adaptive.mode {
        AdaptiveProtectionMode::Relaxed => (1200u32, 720u32, 280u32),
        AdaptiveProtectionMode::Balanced => (960u32, 480u32, 168u32),
        AdaptiveProtectionMode::Strict => (720u32, 360u32, 120u32),
    };
    let goal_factor = match adaptive.goal {
        AdaptiveProtectionGoal::AvailabilityFirst => 1.15,
        AdaptiveProtectionGoal::Balanced => 1.0,
        AdaptiveProtectionGoal::SecurityFirst => 0.88,
    };
    let pressure_factor = match pressure {
        "normal" => 1.0,
        "elevated" => 0.92,
        "high" => 0.82,
        _ => 0.72,
    };
    let factor = (capacity_scale * goal_factor * pressure_factor).clamp(0.55, 1.8);
    let scale_budget = |value: u32| ((value as f64) * factor).round().max(24.0) as u32;

    let delays = match pressure {
        "normal" => (20, 45, 15, 35),
        "elevated" => (25, 60, 20, 45),
        "high" => (35, 75, 30, 60),
        _ => (45, 90, 40, 80),
    };
    let rejects = match (adaptive.allow_emergency_reject, adaptive.cdn_fronted) {
        (true, false) if pressure == "attack" => (220, 160),
        _ => (400, 260),
    };

    (
        (
            scale_budget(base_budget.0),
            scale_budget(base_budget.1),
            scale_budget(base_budget.2),
        ),
        delays,
        rejects,
    )
}

fn derive_l7_policy(
    adaptive: &AdaptiveProtectionConfig,
    pressure: &str,
    base: &CcDefenseConfig,
) -> AdaptiveL7RuntimePolicy {
    let challenge_scale = match adaptive.mode {
        AdaptiveProtectionMode::Relaxed => 1.25,
        AdaptiveProtectionMode::Balanced => 1.0,
        AdaptiveProtectionMode::Strict => 0.78,
    } * match adaptive.goal {
        AdaptiveProtectionGoal::AvailabilityFirst => 1.2,
        AdaptiveProtectionGoal::Balanced => 1.0,
        AdaptiveProtectionGoal::SecurityFirst => 0.85,
    } * match pressure {
        "normal" => 1.0,
        "elevated" => 0.9,
        "high" => 0.75,
        _ => 0.6,
    };

    let scale = |value: u32| ((value as f64) * challenge_scale).round().max(3.0) as u32;
    let delay_ms = match pressure {
        "normal" => base.delay_ms,
        "elevated" => base.delay_ms.max(180),
        "high" => base.delay_ms.max(260),
        _ => base.delay_ms.max(350),
    };

    AdaptiveL7RuntimePolicy {
        request_window_secs: base.request_window_secs,
        delay_ms,
        route_challenge_threshold: scale(base.route_challenge_threshold),
        route_block_threshold: scale(base.route_block_threshold),
        ip_challenge_threshold: scale(base.ip_challenge_threshold),
        ip_block_threshold: scale(base.ip_block_threshold),
        challenge_enabled: base.enabled,
    }
}

fn mode_label(mode: AdaptiveProtectionMode) -> &'static str {
    match mode {
        AdaptiveProtectionMode::Relaxed => "relaxed",
        AdaptiveProtectionMode::Balanced => "balanced",
        AdaptiveProtectionMode::Strict => "strict",
    }
}

fn goal_label(goal: AdaptiveProtectionGoal) -> &'static str {
    match goal {
        AdaptiveProtectionGoal::AvailabilityFirst => "availability_first",
        AdaptiveProtectionGoal::Balanced => "balanced",
        AdaptiveProtectionGoal::SecurityFirst => "security_first",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AdaptiveProtectionGoal, AdaptiveProtectionMode, AutoTuningIntent, AutoTuningMode, Config,
    };
    use crate::core::AutoTuningRecommendationSnapshot;

    fn base_config() -> Config {
        Config {
            adaptive_protection: AdaptiveProtectionConfig {
                enabled: true,
                mode: AdaptiveProtectionMode::Balanced,
                goal: AdaptiveProtectionGoal::Balanced,
                cdn_fronted: true,
                allow_emergency_reject: false,
            },
            ..Config::default()
        }
    }

    fn base_auto_snapshot() -> AutoTuningRuntimeSnapshot {
        AutoTuningRuntimeSnapshot {
            mode: AutoTuningMode::Off,
            intent: AutoTuningIntent::Balanced,
            controller_state: "idle".to_string(),
            detected_cpu_cores: 4,
            detected_memory_limit_mb: Some(4096),
            last_adjust_at: None,
            last_adjust_reason: None,
            last_adjust_diff: Vec::new(),
            rollback_count_24h: 0,
            cooldown_until: None,
            last_observed_tls_handshake_timeout_rate_percent: 0.0,
            last_observed_bucket_reject_rate_percent: 0.0,
            last_observed_avg_proxy_latency_ms: 0,
            recommendation: AutoTuningRecommendationSnapshot {
                l4_normal_connection_budget_per_minute: 960,
                l4_suspicious_connection_budget_per_minute: 480,
                l4_high_risk_connection_budget_per_minute: 168,
                l4_reject_threshold_percent: 300,
                l4_critical_reject_threshold_percent: 200,
                tls_handshake_timeout_ms: 3000,
            },
        }
    }

    #[test]
    fn adaptive_runtime_tightens_under_attack_pressure() {
        let config = base_config();
        let auto = AutoTuningRuntimeSnapshot {
            last_observed_avg_proxy_latency_ms: 1200,
            last_observed_tls_handshake_timeout_rate_percent: 0.2,
            last_observed_bucket_reject_rate_percent: 0.2,
            ..base_auto_snapshot()
        };
        let metrics = MetricsSnapshot {
            trusted_proxy_permit_drops: 4,
            tls_handshake_failures: 2,
            l7_cc_challenges: 12,
            l7_cc_blocks: 15,
            ..MetricsSnapshot::default()
        };

        let runtime = build_runtime_snapshot(&config, &auto, Some(&metrics));

        assert_eq!(runtime.system_pressure, "attack");
        assert!(runtime.l4.normal_connection_budget_per_minute < 960);
        assert!(runtime.l4.soft_delay_ms >= 45);
        assert!(runtime.l7.delay_ms >= 350);
        assert!(runtime.reasons.iter().any(|reason| reason == "request_permit_pressure"));
    }

    #[test]
    fn availability_first_mode_keeps_l7_thresholds_looser_than_strict_security() {
        let relaxed_config = Config {
            adaptive_protection: AdaptiveProtectionConfig {
                mode: AdaptiveProtectionMode::Relaxed,
                goal: AdaptiveProtectionGoal::AvailabilityFirst,
                ..base_config().adaptive_protection
            },
            ..base_config()
        };
        let strict_config = Config {
            adaptive_protection: AdaptiveProtectionConfig {
                mode: AdaptiveProtectionMode::Strict,
                goal: AdaptiveProtectionGoal::SecurityFirst,
                ..base_config().adaptive_protection
            },
            ..base_config()
        };
        let auto = base_auto_snapshot();

        let relaxed = build_runtime_snapshot(&relaxed_config, &auto, None);
        let strict = build_runtime_snapshot(&strict_config, &auto, None);

        assert!(relaxed.l7.ip_challenge_threshold > strict.l7.ip_challenge_threshold);
        assert!(relaxed.l4.normal_connection_budget_per_minute > strict.l4.normal_connection_budget_per_minute);
    }

    #[test]
    fn disabling_adaptive_protection_preserves_static_cc_config() {
        let config = Config {
            adaptive_protection: AdaptiveProtectionConfig {
                enabled: false,
                ..base_config().adaptive_protection
            },
            ..base_config()
        };
        let runtime = AdaptiveProtectionRuntimeSnapshot {
            l7: AdaptiveL7RuntimePolicy {
                request_window_secs: 99,
                delay_ms: 999,
                route_challenge_threshold: 9,
                route_block_threshold: 10,
                ip_challenge_threshold: 11,
                ip_block_threshold: 12,
                challenge_enabled: false,
            },
            ..AdaptiveProtectionRuntimeSnapshot::default()
        };

        let effective = derive_effective_cc_config(&config, &runtime);

        assert_eq!(
            effective.ip_challenge_threshold,
            config.l7_config.cc_defense.ip_challenge_threshold
        );
        assert_eq!(effective.delay_ms, config.l7_config.cc_defense.delay_ms);
        assert_eq!(effective.enabled, config.l7_config.cc_defense.enabled);
    }
}
