use crate::config::{AutoTuningIntent, AutoTuningMode, Config};
use crate::metrics::MetricsSnapshot;

use super::{recommend, run_control_step, AutoTuningControllerState};
use crate::core::system_profile::SystemProfile;

#[test]
fn recommendation_scales_with_capacity() {
    let mut config = Config::default();
    config.auto_tuning.intent = AutoTuningIntent::Balanced;

    let low = recommend(
        &config,
        &SystemProfile {
            cpu_cores: 1,
            memory_limit_bytes: Some(512 * 1024 * 1024),
        },
    );
    let high = recommend(
        &config,
        &SystemProfile {
            cpu_cores: 8,
            memory_limit_bytes: Some(16 * 1024 * 1024 * 1024),
        },
    );

    assert!(
        high.l4_normal_connection_budget_per_minute > low.l4_normal_connection_budget_per_minute
    );
    assert!(high.tls_handshake_timeout_ms <= low.tls_handshake_timeout_ms);
}

#[test]
fn observe_mode_emits_no_decision() {
    let mut config = Config::default();
    config.auto_tuning.mode = AutoTuningMode::Observe;
    let mut runtime = super::build_runtime_snapshot(&config);
    let mut state = AutoTuningControllerState::default();

    let baseline = MetricsSnapshot {
        proxied_requests: 100,
        tls_handshake_timeouts: 0,
        l4_bucket_budget_rejections: 0,
        ..MetricsSnapshot::default()
    };
    let current = MetricsSnapshot {
        proxied_requests: 200,
        tls_handshake_timeouts: 30,
        l4_bucket_budget_rejections: 20,
        ..MetricsSnapshot::default()
    };

    let warmup = run_control_step(&config, &mut runtime, &mut state, &baseline, 100);
    assert!(warmup.is_none());
    let decision = run_control_step(&config, &mut runtime, &mut state, &current, 140);
    assert!(decision.is_none());
}

#[test]
fn identity_pressure_prefers_tightening_l4_and_cc_thresholds() {
    let mut config = Config::default();
    config.auto_tuning.mode = AutoTuningMode::Active;
    config.auto_tuning.runtime_adjust_enabled = true;
    config.auto_tuning.control_interval_secs = 10;
    config.auto_tuning.cooldown_secs = 30;

    let original_l4_budget = config
        .l4_config
        .behavior_normal_connection_budget_per_minute;
    let original_ip_threshold = config.l7_config.cc_defense.ip_challenge_threshold;
    let original_delay_ms = config.l7_config.cc_defense.delay_ms;

    let mut runtime = super::build_runtime_snapshot(&config);
    let mut state = AutoTuningControllerState::default();

    let warmup = MetricsSnapshot {
        proxied_requests: 100,
        proxy_successes: 100,
        proxy_latency_micros_total: 100_000_000,
        ..MetricsSnapshot::default()
    };
    assert!(run_control_step(&config, &mut runtime, &mut state, &warmup, 100).is_none());
    state.bootstrap_applied = true;

    for (index, proxied_requests) in [140_u64, 180, 220].into_iter().enumerate() {
        let metrics = MetricsSnapshot {
            proxied_requests,
            proxy_successes: proxied_requests,
            proxy_latency_micros_total: proxied_requests * 1_000_000,
            trusted_proxy_permit_drops: 2 + index as u64 * 2,
            trusted_proxy_l4_degrade_actions: 2 + index as u64 * 2,
            l7_cc_unresolved_identity_delays: 3 + index as u64 * 3,
            l7_cc_challenges: 6 + index as u64 * 4,
            l7_behavior_delays: 4 + index as u64 * 2,
            ..MetricsSnapshot::default()
        };
        let decision = run_control_step(
            &config,
            &mut runtime,
            &mut state,
            &metrics,
            110 + index as i64 * 10,
        );
        if index < 2 {
            assert!(decision.is_none());
        } else {
            let decision = decision.expect("third identity-pressure window should adjust");
            assert_eq!(
                runtime.last_adjust_reason.as_deref(),
                Some("adjust_for_identity_resolution_pressure")
            );
            assert!(
                decision
                    .next_config
                    .l4_config
                    .behavior_normal_connection_budget_per_minute
                    < original_l4_budget
            );
            assert!(
                decision
                    .next_config
                    .l7_config
                    .cc_defense
                    .ip_challenge_threshold
                    < original_ip_threshold
            );
            assert!(decision.next_config.l7_config.cc_defense.delay_ms > original_delay_ms);
        }
    }
}

#[test]
fn active_mode_records_effect_evaluation_after_adjustment() {
    let mut config = Config::default();
    config.auto_tuning.mode = AutoTuningMode::Active;
    config.auto_tuning.runtime_adjust_enabled = true;
    config.auto_tuning.control_interval_secs = 10;
    config.auto_tuning.cooldown_secs = 30;

    let mut runtime = super::build_runtime_snapshot(&config);
    let mut state = AutoTuningControllerState::default();

    let warmup = MetricsSnapshot {
        proxied_requests: 100,
        proxy_successes: 100,
        proxy_latency_micros_total: 100_000_000,
        ..MetricsSnapshot::default()
    };
    assert!(run_control_step(&config, &mut runtime, &mut state, &warmup, 100).is_none());
    state.bootstrap_applied = true;

    let baseline = MetricsSnapshot {
        proxied_requests: 140,
        proxy_successes: 140,
        proxy_latency_micros_total: 140_000_000,
        tls_handshake_timeouts: 10,
        ..MetricsSnapshot::default()
    };
    assert!(run_control_step(&config, &mut runtime, &mut state, &baseline, 110).is_none());

    let trigger = MetricsSnapshot {
        proxied_requests: 180,
        proxy_successes: 180,
        proxy_latency_micros_total: 180_000_000,
        tls_handshake_timeouts: 20,
        ..MetricsSnapshot::default()
    };
    assert!(run_control_step(&config, &mut runtime, &mut state, &trigger, 120).is_none());

    let decision_window = MetricsSnapshot {
        proxied_requests: 220,
        proxy_successes: 220,
        proxy_latency_micros_total: 220_000_000,
        tls_handshake_timeouts: 30,
        ..MetricsSnapshot::default()
    };
    let decision = run_control_step(&config, &mut runtime, &mut state, &decision_window, 130);
    assert!(
        decision.is_some(),
        "third consecutive high handshake window should adjust"
    );
    assert_eq!(
        runtime
            .last_effect_evaluation
            .as_ref()
            .map(|value| value.status.as_str()),
        Some("pending")
    );

    let improved = MetricsSnapshot {
        proxied_requests: 1_020,
        proxy_successes: 1_020,
        proxy_latency_micros_total: 1_020_000_000,
        tls_handshake_timeouts: 31,
        ..MetricsSnapshot::default()
    };
    assert!(run_control_step(&config, &mut runtime, &mut state, &improved, 140).is_none());
    assert_eq!(
        runtime
            .last_effect_evaluation
            .as_ref()
            .map(|value| value.status.as_str()),
        Some("improved")
    );
}

#[test]
fn active_mode_rolls_back_on_hot_route_regression() {
    let mut config = Config::default();
    config.auto_tuning.mode = AutoTuningMode::Active;
    config.auto_tuning.runtime_adjust_enabled = true;
    config.auto_tuning.control_interval_secs = 10;
    config.auto_tuning.cooldown_secs = 30;

    let mut runtime = super::build_runtime_snapshot(&config);
    let mut state = AutoTuningControllerState::default();

    let warmup = MetricsSnapshot {
        proxied_requests: 100,
        proxy_successes: 100,
        proxy_latency_micros_total: 100_000_000,
        ..MetricsSnapshot::default()
    };
    assert!(run_control_step(&config, &mut runtime, &mut state, &warmup, 100).is_none());
    state.bootstrap_applied = true;

    let baseline = MetricsSnapshot {
        proxied_requests: 140,
        proxy_successes: 140,
        proxy_latency_micros_total: 140_000_000,
        tls_handshake_timeouts: 10,
        top_route_segments: vec![crate::metrics::ProxyTrafficSegmentSnapshot {
            scope_type: "route".to_string(),
            scope_key: "/checkout|api".to_string(),
            host: None,
            route: Some("/checkout".to_string()),
            request_kind: "api".to_string(),
            proxied_requests: 20,
            proxy_successes: 20,
            proxy_failures: 0,
            average_proxy_latency_micros: 80_000,
        }],
        ..MetricsSnapshot::default()
    };
    assert!(run_control_step(&config, &mut runtime, &mut state, &baseline, 110).is_none());

    let trigger = MetricsSnapshot {
        proxied_requests: 180,
        proxy_successes: 180,
        proxy_latency_micros_total: 180_000_000,
        tls_handshake_timeouts: 20,
        top_route_segments: vec![crate::metrics::ProxyTrafficSegmentSnapshot {
            scope_type: "route".to_string(),
            scope_key: "/checkout|api".to_string(),
            host: None,
            route: Some("/checkout".to_string()),
            request_kind: "api".to_string(),
            proxied_requests: 24,
            proxy_successes: 24,
            proxy_failures: 0,
            average_proxy_latency_micros: 90_000,
        }],
        ..MetricsSnapshot::default()
    };
    assert!(run_control_step(&config, &mut runtime, &mut state, &trigger, 120).is_none());

    let decision_window = MetricsSnapshot {
        proxied_requests: 220,
        proxy_successes: 220,
        proxy_latency_micros_total: 220_000_000,
        tls_handshake_timeouts: 30,
        top_route_segments: vec![crate::metrics::ProxyTrafficSegmentSnapshot {
            scope_type: "route".to_string(),
            scope_key: "/checkout|api".to_string(),
            host: None,
            route: Some("/checkout".to_string()),
            request_kind: "api".to_string(),
            proxied_requests: 28,
            proxy_successes: 28,
            proxy_failures: 0,
            average_proxy_latency_micros: 95_000,
        }],
        ..MetricsSnapshot::default()
    };
    assert!(run_control_step(&config, &mut runtime, &mut state, &decision_window, 130).is_some());

    let hotspot_regressed = MetricsSnapshot {
        proxied_requests: 260,
        proxy_successes: 260,
        proxy_latency_micros_total: 260_000_000,
        tls_handshake_timeouts: 31,
        top_route_segments: vec![crate::metrics::ProxyTrafficSegmentSnapshot {
            scope_type: "route".to_string(),
            scope_key: "/checkout|api".to_string(),
            host: None,
            route: Some("/checkout".to_string()),
            request_kind: "api".to_string(),
            proxied_requests: 40,
            proxy_successes: 36,
            proxy_failures: 4,
            average_proxy_latency_micros: 320_000,
        }],
        ..MetricsSnapshot::default()
    };
    let rollback = run_control_step(&config, &mut runtime, &mut state, &hotspot_regressed, 140);
    assert!(
        rollback.is_some(),
        "hot route regression should trigger rollback"
    );
    assert_eq!(runtime.controller_state, "rollback");
}

#[test]
fn hot_route_budget_pressure_prefers_route_threshold_adjustment() {
    let mut config = Config::default();
    config.auto_tuning.mode = AutoTuningMode::Active;
    config.auto_tuning.runtime_adjust_enabled = true;
    config.auto_tuning.control_interval_secs = 10;
    config.auto_tuning.cooldown_secs = 30;

    let original_route_threshold = config.l7_config.cc_defense.route_challenge_threshold;
    let original_l4_budget = config
        .l4_config
        .behavior_normal_connection_budget_per_minute;

    let mut runtime = super::build_runtime_snapshot(&config);
    let mut state = AutoTuningControllerState::default();

    let warmup = MetricsSnapshot {
        proxied_requests: 100,
        proxy_successes: 100,
        proxy_latency_micros_total: 100_000_000,
        ..MetricsSnapshot::default()
    };
    assert!(run_control_step(&config, &mut runtime, &mut state, &warmup, 100).is_none());
    state.bootstrap_applied = true;

    for (index, proxied_requests) in [140_u64, 180, 220].into_iter().enumerate() {
        let metrics = MetricsSnapshot {
            proxied_requests,
            proxy_successes: proxied_requests,
            proxy_latency_micros_total: proxied_requests * 1_000_000,
            top_route_segments: vec![crate::metrics::ProxyTrafficSegmentSnapshot {
                scope_type: "route".to_string(),
                scope_key: "/checkout|api".to_string(),
                host: None,
                route: Some("/checkout".to_string()),
                request_kind: "api".to_string(),
                proxied_requests: 12 + index as u64 * 10,
                proxy_successes: 8 + index as u64 * 8,
                proxy_failures: 4 + index as u64 * 2,
                average_proxy_latency_micros: 110_000,
            }],
            ..MetricsSnapshot::default()
        };
        let decision = run_control_step(
            &config,
            &mut runtime,
            &mut state,
            &metrics,
            110 + index as i64 * 10,
        );
        if index < 2 {
            assert!(decision.is_none());
        } else {
            let decision = decision.expect("third hot-route budget window should adjust");
            assert_eq!(
                runtime.last_adjust_reason.as_deref(),
                Some("adjust_for_budget_hot_route")
            );
            assert!(
                decision
                    .next_config
                    .l7_config
                    .cc_defense
                    .route_challenge_threshold
                    > original_route_threshold
            );
            assert_eq!(
                decision
                    .next_config
                    .l4_config
                    .behavior_normal_connection_budget_per_minute,
                original_l4_budget
            );
        }
    }
}

#[test]
fn slow_attack_pressure_prefers_tightening_handshake_and_slow_attack_window() {
    let mut config = Config::default();
    config.auto_tuning.mode = AutoTuningMode::Active;
    config.auto_tuning.runtime_adjust_enabled = true;
    config.auto_tuning.control_interval_secs = 10;
    config.auto_tuning.cooldown_secs = 30;

    let original_handshake_timeout_ms = config.l7_config.tls_handshake_timeout_ms;
    let original_event_window_secs = config.l7_config.slow_attack_defense.event_window_secs;
    let original_max_events = config.l7_config.slow_attack_defense.max_events_per_window;

    let mut runtime = super::build_runtime_snapshot(&config);
    let mut state = AutoTuningControllerState::default();

    let warmup = MetricsSnapshot {
        proxied_requests: 100,
        proxy_successes: 100,
        proxy_latency_micros_total: 100_000_000,
        ..MetricsSnapshot::default()
    };
    assert!(run_control_step(&config, &mut runtime, &mut state, &warmup, 100).is_none());
    state.bootstrap_applied = true;

    for (index, proxied_requests) in [140_u64, 180, 220].into_iter().enumerate() {
        let metrics = MetricsSnapshot {
            proxied_requests,
            proxy_successes: proxied_requests,
            proxy_latency_micros_total: proxied_requests * 1_000_000,
            slow_attack_tls_handshake_hits: 1 + index as u64 * 2,
            slow_attack_blocks: index as u64,
            l4_direct_idle_no_request_connections: 3 + index as u64,
            ..MetricsSnapshot::default()
        };
        let decision = run_control_step(
            &config,
            &mut runtime,
            &mut state,
            &metrics,
            110 + index as i64 * 10,
        );
        if index < 2 {
            assert!(decision.is_none());
        } else {
            let decision = decision.expect("third slow-attack window should adjust");
            assert_eq!(
                runtime.last_adjust_reason.as_deref(),
                Some("adjust_for_slow_attack_pressure")
            );
            assert!(
                decision.next_config.l7_config.tls_handshake_timeout_ms
                    < original_handshake_timeout_ms
            );
            assert!(
                decision
                    .next_config
                    .l7_config
                    .slow_attack_defense
                    .event_window_secs
                    < original_event_window_secs
            );
            assert!(
                decision
                    .next_config
                    .l7_config
                    .slow_attack_defense
                    .max_events_per_window
                    <= original_max_events
            );
        }
    }
}
