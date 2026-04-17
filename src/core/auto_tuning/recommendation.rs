use crate::config::{AutoTuningIntent, AutoTuningMode, Config};

use super::super::system_profile::SystemProfile;
use super::types::AutoTuningRecommendationSnapshot;

pub(super) fn recommend(
    config: &Config,
    profile: &SystemProfile,
) -> AutoTuningRecommendationSnapshot {
    let cpu = profile.cpu_cores.max(1) as f64;
    let memory_gb = profile
        .memory_limit_bytes
        .map(|value| value as f64 / (1024.0 * 1024.0 * 1024.0))
        .unwrap_or(2.0)
        .clamp(0.5, 256.0);
    let intent_factor = match config.auto_tuning.intent {
        AutoTuningIntent::Conservative => 0.85,
        AutoTuningIntent::Balanced => 1.0,
        AutoTuningIntent::Aggressive => 1.2,
    };

    let capacity_factor = (cpu * memory_gb.sqrt()).clamp(0.65, 8.0);

    let base_budget = (120.0 * capacity_factor * intent_factor).round() as u32;
    let normal_budget = base_budget.clamp(24, 10_000);
    let suspicious_budget = ((normal_budget as f64) * 0.5).round() as u32;
    let suspicious_budget = suspicious_budget.clamp(8, normal_budget.max(8));
    let high_risk_budget = ((suspicious_budget as f64) * 0.35).round() as u32;
    let high_risk_budget = high_risk_budget.clamp(4, suspicious_budget.max(4));

    let low_capacity_penalty = (1.6 - capacity_factor).max(0.0);
    let intent_timeout_bonus = match config.auto_tuning.intent {
        AutoTuningIntent::Conservative => 350.0,
        AutoTuningIntent::Balanced => 0.0,
        AutoTuningIntent::Aggressive => -150.0,
    };
    let tls_handshake_timeout_ms =
        (3000.0 + low_capacity_penalty * 900.0 + intent_timeout_bonus).round() as u64;
    let tls_handshake_timeout_ms = tls_handshake_timeout_ms.clamp(1500, 15_000);

    let reject_threshold = (330.0 - (capacity_factor * 8.0)
        + match config.auto_tuning.intent {
            AutoTuningIntent::Conservative => 25.0,
            AutoTuningIntent::Balanced => 0.0,
            AutoTuningIntent::Aggressive => -20.0,
        })
    .round() as u16;
    let reject_threshold = reject_threshold.clamp(220, 450);

    let critical_reject_threshold = (220.0 - (capacity_factor * 5.0)
        + match config.auto_tuning.intent {
            AutoTuningIntent::Conservative => 20.0,
            AutoTuningIntent::Balanced => 0.0,
            AutoTuningIntent::Aggressive => -15.0,
        })
    .round() as u16;
    let critical_reject_threshold = critical_reject_threshold.clamp(160, reject_threshold);

    AutoTuningRecommendationSnapshot {
        l4_normal_connection_budget_per_minute: normal_budget,
        l4_suspicious_connection_budget_per_minute: suspicious_budget,
        l4_high_risk_connection_budget_per_minute: high_risk_budget,
        l4_reject_threshold_percent: reject_threshold,
        l4_critical_reject_threshold_percent: critical_reject_threshold,
        tls_handshake_timeout_ms,
    }
}

pub(super) fn controller_state_label(mode: AutoTuningMode) -> &'static str {
    match mode {
        AutoTuningMode::Off => "disabled",
        AutoTuningMode::Observe => "observe_only",
        AutoTuningMode::Active => "active_bootstrap_pending",
    }
}
