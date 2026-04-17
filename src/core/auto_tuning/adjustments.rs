use crate::config::Config;

pub(super) fn adjust_l4_budgets(
    next: &mut Config,
    config: &Config,
    diff: &mut Vec<String>,
    increase: bool,
) -> bool {
    let mut touched = false;

    touched |= adjust_u32_field(
        config,
        next,
        "l4_config.behavior_normal_connection_budget_per_minute",
        diff,
        increase,
        16,
        10_000,
    );
    touched |= adjust_u32_field(
        config,
        next,
        "l4_config.behavior_suspicious_connection_budget_per_minute",
        diff,
        increase,
        8,
        10_000,
    );
    touched |= adjust_u32_field(
        config,
        next,
        "l4_config.behavior_high_risk_connection_budget_per_minute",
        diff,
        increase,
        4,
        10_000,
    );

    touched
}

pub(super) fn adjust_l4_reject_thresholds(
    next: &mut Config,
    config: &Config,
    diff: &mut Vec<String>,
    increase: bool,
) -> bool {
    let mut touched = false;

    touched |= adjust_u16_field(
        config,
        next,
        "l4_config.behavior_reject_threshold_percent",
        diff,
        increase,
        100,
        1_000,
    );
    touched |= adjust_u16_field(
        config,
        next,
        "l4_config.behavior_critical_reject_threshold_percent",
        diff,
        increase,
        100,
        1_000,
    );

    touched
}

pub(super) fn adjust_cc_route_thresholds(
    next: &mut Config,
    config: &Config,
    diff: &mut Vec<String>,
    increase: bool,
) {
    adjust_cc_u32_field(
        config,
        next,
        "l7_config.cc_defense.route_challenge_threshold",
        diff,
        increase,
        3,
        10_000,
    );
    adjust_cc_u32_field(
        config,
        next,
        "l7_config.cc_defense.route_block_threshold",
        diff,
        increase,
        3,
        10_000,
    );
}

pub(super) fn adjust_cc_host_thresholds(
    next: &mut Config,
    config: &Config,
    diff: &mut Vec<String>,
    increase: bool,
) {
    adjust_cc_u32_field(
        config,
        next,
        "l7_config.cc_defense.host_challenge_threshold",
        diff,
        increase,
        5,
        10_000,
    );
    adjust_cc_u32_field(
        config,
        next,
        "l7_config.cc_defense.host_block_threshold",
        diff,
        increase,
        5,
        10_000,
    );
}

pub(super) fn adjust_cc_ip_thresholds(
    next: &mut Config,
    config: &Config,
    diff: &mut Vec<String>,
    increase: bool,
) {
    adjust_cc_u32_field(
        config,
        next,
        "l7_config.cc_defense.ip_challenge_threshold",
        diff,
        increase,
        8,
        10_000,
    );
    adjust_cc_u32_field(
        config,
        next,
        "l7_config.cc_defense.ip_block_threshold",
        diff,
        increase,
        12,
        10_000,
    );
}

pub(super) fn adjust_cc_delay_ms(
    next: &mut Config,
    config: &Config,
    diff: &mut Vec<String>,
    increase: bool,
) {
    if is_pinned(config, "l7_config.cc_defense.delay_ms") {
        return;
    }
    let before = next.l7_config.cc_defense.delay_ms;
    let after = adjust_u64(
        before,
        config.auto_tuning.max_step_percent,
        increase,
        10,
        5_000,
    );
    if before == after {
        return;
    }
    next.l7_config.cc_defense.delay_ms = after;
    diff.push(format!(
        "l7_config.cc_defense.delay_ms: {} -> {}",
        before, after
    ));
}

pub(super) fn adjust_tls_handshake_timeout_ms(
    next: &mut Config,
    config: &Config,
    diff: &mut Vec<String>,
    increase: bool,
) {
    if is_pinned(config, "l7_config.tls_handshake_timeout_ms") {
        return;
    }
    let before = next.l7_config.tls_handshake_timeout_ms;
    let after = adjust_u64(
        before,
        config.auto_tuning.max_step_percent,
        increase,
        500,
        60_000,
    );
    if before == after {
        return;
    }
    next.l7_config.tls_handshake_timeout_ms = after;
    diff.push(format!(
        "l7_config.tls_handshake_timeout_ms: {} -> {}",
        before, after
    ));
}

pub(super) fn adjust_slow_attack_window(
    next: &mut Config,
    config: &Config,
    diff: &mut Vec<String>,
    increase: bool,
) {
    if !is_pinned(
        config,
        "l7_config.slow_attack_defense.max_events_per_window",
    ) {
        let before = next.l7_config.slow_attack_defense.max_events_per_window;
        let after = adjust_u32(
            before,
            config.auto_tuning.max_step_percent,
            increase,
            1,
            1_000,
        );
        if before != after {
            next.l7_config.slow_attack_defense.max_events_per_window = after;
            diff.push(format!(
                "l7_config.slow_attack_defense.max_events_per_window: {} -> {}",
                before, after
            ));
        }
    }

    if is_pinned(config, "l7_config.slow_attack_defense.event_window_secs") {
        return;
    }
    let before = next.l7_config.slow_attack_defense.event_window_secs;
    let after = adjust_u64(
        before,
        config.auto_tuning.max_step_percent,
        increase,
        30,
        86_400,
    );
    if before == after {
        return;
    }
    next.l7_config.slow_attack_defense.event_window_secs = after;
    diff.push(format!(
        "l7_config.slow_attack_defense.event_window_secs: {} -> {}",
        before, after
    ));
}

fn adjust_u32_field(
    config: &Config,
    next: &mut Config,
    field: &str,
    diff: &mut Vec<String>,
    increase: bool,
    min: u32,
    max: u32,
) -> bool {
    if is_pinned(config, field) {
        return false;
    }

    let before = match field {
        "l4_config.behavior_normal_connection_budget_per_minute" => {
            next.l4_config.behavior_normal_connection_budget_per_minute
        }
        "l4_config.behavior_suspicious_connection_budget_per_minute" => {
            next.l4_config
                .behavior_suspicious_connection_budget_per_minute
        }
        "l4_config.behavior_high_risk_connection_budget_per_minute" => {
            next.l4_config
                .behavior_high_risk_connection_budget_per_minute
        }
        _ => return false,
    };

    let after = adjust_u32(
        before,
        config.auto_tuning.max_step_percent,
        increase,
        min,
        max,
    );
    if before == after {
        return false;
    }

    match field {
        "l4_config.behavior_normal_connection_budget_per_minute" => {
            next.l4_config.behavior_normal_connection_budget_per_minute = after;
        }
        "l4_config.behavior_suspicious_connection_budget_per_minute" => {
            next.l4_config
                .behavior_suspicious_connection_budget_per_minute = after;
        }
        "l4_config.behavior_high_risk_connection_budget_per_minute" => {
            next.l4_config
                .behavior_high_risk_connection_budget_per_minute = after;
        }
        _ => return false,
    }

    diff.push(format!("{}: {} -> {}", field, before, after));
    true
}

fn adjust_cc_u32_field(
    config: &Config,
    next: &mut Config,
    field: &str,
    diff: &mut Vec<String>,
    increase: bool,
    min: u32,
    max: u32,
) -> bool {
    if is_pinned(config, field) {
        return false;
    }

    let before = match field {
        "l7_config.cc_defense.route_challenge_threshold" => {
            next.l7_config.cc_defense.route_challenge_threshold
        }
        "l7_config.cc_defense.route_block_threshold" => {
            next.l7_config.cc_defense.route_block_threshold
        }
        "l7_config.cc_defense.host_challenge_threshold" => {
            next.l7_config.cc_defense.host_challenge_threshold
        }
        "l7_config.cc_defense.host_block_threshold" => {
            next.l7_config.cc_defense.host_block_threshold
        }
        "l7_config.cc_defense.ip_challenge_threshold" => {
            next.l7_config.cc_defense.ip_challenge_threshold
        }
        "l7_config.cc_defense.ip_block_threshold" => next.l7_config.cc_defense.ip_block_threshold,
        _ => return false,
    };

    let after = adjust_u32(
        before,
        config.auto_tuning.max_step_percent,
        increase,
        min,
        max,
    );
    if before == after {
        return false;
    }

    match field {
        "l7_config.cc_defense.route_challenge_threshold" => {
            next.l7_config.cc_defense.route_challenge_threshold = after
        }
        "l7_config.cc_defense.route_block_threshold" => {
            next.l7_config.cc_defense.route_block_threshold = after
        }
        "l7_config.cc_defense.host_challenge_threshold" => {
            next.l7_config.cc_defense.host_challenge_threshold = after
        }
        "l7_config.cc_defense.host_block_threshold" => {
            next.l7_config.cc_defense.host_block_threshold = after
        }
        "l7_config.cc_defense.ip_challenge_threshold" => {
            next.l7_config.cc_defense.ip_challenge_threshold = after
        }
        "l7_config.cc_defense.ip_block_threshold" => {
            next.l7_config.cc_defense.ip_block_threshold = after
        }
        _ => return false,
    }

    diff.push(format!("{}: {} -> {}", field, before, after));
    true
}

fn adjust_u16_field(
    config: &Config,
    next: &mut Config,
    field: &str,
    diff: &mut Vec<String>,
    increase: bool,
    min: u16,
    max: u16,
) -> bool {
    if is_pinned(config, field) {
        return false;
    }

    let before = match field {
        "l4_config.behavior_reject_threshold_percent" => {
            next.l4_config.behavior_reject_threshold_percent
        }
        "l4_config.behavior_critical_reject_threshold_percent" => {
            next.l4_config.behavior_critical_reject_threshold_percent
        }
        _ => return false,
    };

    let after = adjust_u16(
        before,
        config.auto_tuning.max_step_percent,
        increase,
        min,
        max,
    );
    if before == after {
        return false;
    }

    match field {
        "l4_config.behavior_reject_threshold_percent" => {
            next.l4_config.behavior_reject_threshold_percent = after;
        }
        "l4_config.behavior_critical_reject_threshold_percent" => {
            next.l4_config.behavior_critical_reject_threshold_percent = after;
        }
        _ => return false,
    }

    diff.push(format!("{}: {} -> {}", field, before, after));
    true
}

pub(super) fn set_u32_if_unpinned(
    config: &Config,
    next: &mut Config,
    field: &str,
    value: u32,
    diff: &mut Vec<String>,
) -> bool {
    if is_pinned(config, field) {
        return false;
    }

    let before = match field {
        "l4_config.behavior_normal_connection_budget_per_minute" => {
            next.l4_config.behavior_normal_connection_budget_per_minute
        }
        "l4_config.behavior_suspicious_connection_budget_per_minute" => {
            next.l4_config
                .behavior_suspicious_connection_budget_per_minute
        }
        "l4_config.behavior_high_risk_connection_budget_per_minute" => {
            next.l4_config
                .behavior_high_risk_connection_budget_per_minute
        }
        _ => return false,
    };

    if before == value {
        return false;
    }

    match field {
        "l4_config.behavior_normal_connection_budget_per_minute" => {
            next.l4_config.behavior_normal_connection_budget_per_minute = value
        }
        "l4_config.behavior_suspicious_connection_budget_per_minute" => {
            next.l4_config
                .behavior_suspicious_connection_budget_per_minute = value
        }
        "l4_config.behavior_high_risk_connection_budget_per_minute" => {
            next.l4_config
                .behavior_high_risk_connection_budget_per_minute = value
        }
        _ => return false,
    }

    diff.push(format!("{}: {} -> {}", field, before, value));
    true
}

pub(super) fn set_u16_if_unpinned(
    config: &Config,
    next: &mut Config,
    field: &str,
    value: u16,
    diff: &mut Vec<String>,
) -> bool {
    if is_pinned(config, field) {
        return false;
    }

    let before = match field {
        "l4_config.behavior_reject_threshold_percent" => {
            next.l4_config.behavior_reject_threshold_percent
        }
        "l4_config.behavior_critical_reject_threshold_percent" => {
            next.l4_config.behavior_critical_reject_threshold_percent
        }
        _ => return false,
    };

    if before == value {
        return false;
    }

    match field {
        "l4_config.behavior_reject_threshold_percent" => {
            next.l4_config.behavior_reject_threshold_percent = value
        }
        "l4_config.behavior_critical_reject_threshold_percent" => {
            next.l4_config.behavior_critical_reject_threshold_percent = value
        }
        _ => return false,
    }

    diff.push(format!("{}: {} -> {}", field, before, value));
    true
}

fn adjust_u64(value: u64, percent: u8, increase: bool, min: u64, max: u64) -> u64 {
    let step = ((value.saturating_mul(percent as u64)) / 100).max(1);
    let next = if increase {
        value.saturating_add(step)
    } else {
        value.saturating_sub(step)
    };
    next.clamp(min, max)
}

fn adjust_u32(value: u32, percent: u8, increase: bool, min: u32, max: u32) -> u32 {
    adjust_u64(value as u64, percent, increase, min as u64, max as u64) as u32
}

fn adjust_u16(value: u16, percent: u8, increase: bool, min: u16, max: u16) -> u16 {
    adjust_u64(value as u64, percent, increase, min as u64, max as u64) as u16
}

pub(super) fn is_pinned(config: &Config, field: &str) -> bool {
    config
        .auto_tuning
        .pinned_fields
        .iter()
        .any(|item| item.eq_ignore_ascii_case(field))
}
