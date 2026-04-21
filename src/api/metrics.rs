use super::types::{
    AiTempPolicyMetricsResponse, MetricsResponse, StorageAttackHotspotResponse,
    StorageAttackInsightsResponse, SystemMetricsResponse,
};
use crate::core::RuntimePressureSnapshot;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;
use sysinfo::{get_current_pid, Networks, Pid, ProcessRefreshKind, System};

pub(super) fn build_metrics_response(
    metrics: Option<crate::metrics::MetricsSnapshot>,
    active_rules: u64,
    storage_summary: Option<crate::storage::StorageMetricsSummary>,
    aggregation_insights: Option<crate::storage::StorageAggregationInsightSummary>,
    l4_behavior: Option<crate::l4::behavior::L4BehaviorOverview>,
    runtime_pressure: RuntimePressureSnapshot,
    resource_sentinel: crate::core::ResourceSentinelSnapshot,
    ai_temp_policies: &[crate::storage::AiTempPolicyEntry],
    max_active_temp_policy_count: u32,
) -> MetricsResponse {
    let snapshot = metrics.unwrap_or_default();
    let sqlite_enabled = storage_summary.is_some();
    let storage_summary = storage_summary.unwrap_or_default();
    let aggregation_insights = aggregation_insights.unwrap_or_default();
    let l4_behavior = l4_behavior.unwrap_or(crate::l4::behavior::L4BehaviorOverview {
        bucket_count: 0,
        fine_grained_buckets: 0,
        coarse_buckets: 0,
        peer_only_buckets: 0,
        direct_idle_no_request_buckets: 0,
        direct_idle_no_request_connections: 0,
        normal_buckets: 0,
        suspicious_buckets: 0,
        high_risk_buckets: 0,
        safeline_feedback_hits: 0,
        l7_feedback_hits: 0,
        dropped_events: 0,
        overload_level: crate::l4::behavior::L4OverloadLevel::Normal,
        overload_reason: None,
    });
    let storage_degraded_reasons =
        build_storage_degraded_reasons(&storage_summary, &aggregation_insights, &runtime_pressure);

    MetricsResponse {
        total_packets: snapshot.total_packets,
        blocked_packets: snapshot.blocked_packets,
        blocked_l4: snapshot.blocked_l4,
        blocked_l7: snapshot.blocked_l7,
        early_defense_drops_total: snapshot.early_defense_drops_total,
        early_defense_spoofed_forward_header_drops: snapshot
            .early_defense_spoofed_forward_header_drops,
        early_defense_trusted_cdn_unresolved_drops: snapshot
            .early_defense_trusted_cdn_unresolved_drops,
        early_defense_l4_request_budget_drops: snapshot.early_defense_l4_request_budget_drops,
        early_defense_l4_high_risk_drops: snapshot.early_defense_l4_high_risk_drops,
        early_defense_l4_suspicious_drops: snapshot.early_defense_l4_suspicious_drops,
        early_defense_other_drops: snapshot.early_defense_other_drops,
        l7_drop_reason_cc_hot_block: snapshot.l7_drop_reason_cc_hot_block,
        l7_drop_reason_cc_fast_block: snapshot.l7_drop_reason_cc_fast_block,
        l7_drop_reason_cc_hard_block: snapshot.l7_drop_reason_cc_hard_block,
        l7_drop_reason_spoofed_forward_header: snapshot.l7_drop_reason_spoofed_forward_header,
        l7_drop_reason_behavior_aggregate: snapshot.l7_drop_reason_behavior_aggregate,
        l7_drop_reason_behavior_route_burst: snapshot.l7_drop_reason_behavior_route_burst,
        l7_drop_reason_l7_bloom_filter: snapshot.l7_drop_reason_l7_bloom_filter,
        l7_drop_reason_blocked_client_ip: snapshot.l7_drop_reason_blocked_client_ip,
        l7_drop_reason_other: snapshot.l7_drop_reason_other,
        l7_cc_challenges: snapshot.l7_cc_challenges,
        l7_cc_blocks: snapshot.l7_cc_blocks,
        l7_cc_delays: snapshot.l7_cc_delays,
        l7_cc_unresolved_identity_delays: snapshot.l7_cc_unresolved_identity_delays,
        l7_cc_verified_passes: snapshot.l7_cc_verified_passes,
        l7_cc_fast_path_requests: snapshot.l7_cc_fast_path_requests,
        l7_cc_fast_path_blocks: snapshot.l7_cc_fast_path_blocks,
        l7_cc_fast_path_challenges: snapshot.l7_cc_fast_path_challenges,
        l7_cc_fast_path_no_decisions: snapshot.l7_cc_fast_path_no_decisions,
        l7_cc_hot_cache_hits: snapshot.l7_cc_hot_cache_hits,
        l7_cc_hot_cache_misses: snapshot.l7_cc_hot_cache_misses,
        l7_cc_hot_cache_expired: snapshot.l7_cc_hot_cache_expired,
        l7_cc_fast_path_ratio_percent: if snapshot.total_packets == 0 {
            0.0
        } else {
            (snapshot.l7_cc_fast_path_requests as f64 / snapshot.total_packets as f64) * 100.0
        },
        l7_behavior_challenges: snapshot.l7_behavior_challenges,
        l7_behavior_blocks: snapshot.l7_behavior_blocks,
        l7_behavior_delays: snapshot.l7_behavior_delays,
        l7_ip_access_allows: snapshot.l7_ip_access_allows,
        l7_ip_access_alerts: snapshot.l7_ip_access_alerts,
        l7_ip_access_challenges: snapshot.l7_ip_access_challenges,
        l7_ip_access_blocks: snapshot.l7_ip_access_blocks,
        l7_ip_access_verified_passes: snapshot.l7_ip_access_verified_passes,
        total_bytes: snapshot.total_bytes,
        proxied_requests: snapshot.proxied_requests,
        proxy_successes: snapshot.proxy_successes,
        proxy_failures: snapshot.proxy_failures,
        proxy_fail_close_rejections: snapshot.proxy_fail_close_rejections,
        l4_bucket_budget_rejections: snapshot.l4_bucket_budget_rejections,
        tls_pre_handshake_rejections: snapshot.tls_pre_handshake_rejections,
        trusted_proxy_permit_drops: snapshot.trusted_proxy_permit_drops,
        trusted_proxy_l4_degrade_actions: snapshot.trusted_proxy_l4_degrade_actions,
        tls_handshake_timeouts: snapshot.tls_handshake_timeouts,
        tls_handshake_failures: snapshot.tls_handshake_failures,
        slow_attack_idle_timeouts: snapshot.slow_attack_idle_timeouts,
        slow_attack_header_timeouts: snapshot.slow_attack_header_timeouts,
        slow_attack_body_timeouts: snapshot.slow_attack_body_timeouts,
        slow_attack_tls_handshake_hits: snapshot.slow_attack_tls_handshake_hits,
        slow_attack_blocks: snapshot.slow_attack_blocks,
        upstream_healthcheck_successes: snapshot.upstream_healthcheck_successes,
        upstream_healthcheck_failures: snapshot.upstream_healthcheck_failures,
        proxy_latency_micros_total: snapshot.proxy_latency_micros_total,
        average_proxy_latency_micros: snapshot.average_proxy_latency_micros,
        active_rules,
        sqlite_enabled,
        persisted_security_events: storage_summary.security_events,
        persisted_blocked_ips: storage_summary.blocked_ips,
        persisted_rules: storage_summary.rules,
        sqlite_queue_capacity: storage_summary.queue_capacity,
        sqlite_queue_depth: storage_summary.queue_depth,
        sqlite_dropped_security_events: storage_summary.dropped_security_events,
        sqlite_dropped_blocked_ips: storage_summary.dropped_blocked_ips,
        last_persisted_event_at: storage_summary.latest_event_at,
        last_rule_update_at: storage_summary.latest_rule_update_at,
        l4_bucket_count: l4_behavior.bucket_count,
        l4_fine_grained_buckets: l4_behavior.fine_grained_buckets,
        l4_coarse_buckets: l4_behavior.coarse_buckets,
        l4_peer_only_buckets: l4_behavior.peer_only_buckets,
        l4_high_risk_buckets: l4_behavior.high_risk_buckets,
        l4_behavior_dropped_events: l4_behavior.dropped_events,
        l4_overload_level: match l4_behavior.overload_level {
            crate::l4::behavior::L4OverloadLevel::Normal => "normal".to_string(),
            crate::l4::behavior::L4OverloadLevel::High => "high".to_string(),
            crate::l4::behavior::L4OverloadLevel::Critical => "critical".to_string(),
        },
        runtime_pressure_level: runtime_pressure.level.to_string(),
        runtime_capacity_class: runtime_pressure.capacity_class.to_string(),
        runtime_defense_depth: runtime_pressure.defense_depth.to_string(),
        runtime_pressure_drop_delay: runtime_pressure.drop_delay,
        runtime_pressure_trim_event_persistence: runtime_pressure.trim_event_persistence,
        runtime_pressure_storage_queue_percent: runtime_pressure.storage_queue_usage_percent,
        runtime_pressure_cpu_percent: runtime_pressure.cpu_usage_percent,
        runtime_pressure_cpu_score: runtime_pressure.cpu_pressure_score,
        runtime_pressure_cpu_sample_available: runtime_pressure.cpu_sample_available,
        runtime_l7_bucket_limit: runtime_pressure.l7_bucket_limit as u64,
        runtime_l7_page_window_limit: runtime_pressure.l7_page_window_limit as u64,
        runtime_behavior_bucket_limit: runtime_pressure.behavior_bucket_limit as u64,
        runtime_behavior_sample_stride: runtime_pressure.behavior_sample_stride,
        resource_sentinel_mode: resource_sentinel.mode,
        resource_sentinel_attack_score: resource_sentinel.attack_score,
        resource_sentinel_tracked_debt_buckets: resource_sentinel.tracked_debt_buckets,
        resource_sentinel_high_debt_buckets: resource_sentinel.high_debt_buckets,
        resource_sentinel_extreme_debt_buckets: resource_sentinel.extreme_debt_buckets,
        resource_sentinel_tracked_attack_clusters: resource_sentinel.tracked_attack_clusters,
        resource_sentinel_active_cooldowns: resource_sentinel.active_cooldowns,
        resource_sentinel_pre_admission_rejections: resource_sentinel.pre_admission_rejections,
        resource_sentinel_aggregated_events: resource_sentinel.aggregated_events,
        resource_sentinel_automated_defense_actions: resource_sentinel.automated_defense_actions,
        resource_sentinel_automated_defense_extensions: resource_sentinel
            .automated_defense_extensions,
        resource_sentinel_automated_defense_relaxations: resource_sentinel
            .automated_defense_relaxations,
        resource_sentinel_automated_defense_memory_hits: resource_sentinel
            .automated_defense_memory_hits,
        resource_sentinel_automated_audit_events: resource_sentinel.automated_audit_events,
        resource_sentinel_top_attack_clusters: resource_sentinel.top_attack_clusters,
        resource_sentinel_defense_action_effects: resource_sentinel.defense_action_effects,
        resource_sentinel_defense_decision_traces: resource_sentinel.defense_decision_traces,
        resource_sentinel_ingress_gap_analysis: resource_sentinel.ingress_gap_analysis,
        resource_sentinel_resource_pressure_feedback: resource_sentinel.resource_pressure_feedback,
        resource_sentinel_attack_migrations: resource_sentinel.attack_migrations,
        resource_sentinel_attack_report_preview: resource_sentinel.attack_report_preview,
        resource_sentinel_attack_diagnosis: resource_sentinel.attack_diagnosis,
        resource_sentinel_attack_lifecycle: resource_sentinel.attack_lifecycle,
        resource_sentinel_attack_session: resource_sentinel.attack_session,
        ai_temp_policies: build_ai_temp_policy_metrics(
            ai_temp_policies,
            max_active_temp_policy_count,
        ),
        storage_degraded_reasons,
        storage_attack_insights: StorageAttackInsightsResponse {
            active_bucket_count: aggregation_insights.active_bucket_count,
            active_event_count: aggregation_insights.active_event_count,
            long_tail_bucket_count: aggregation_insights.long_tail_bucket_count,
            long_tail_event_count: aggregation_insights.long_tail_event_count,
            hotspot_sources: aggregation_insights
                .hotspot_sources
                .into_iter()
                .map(|item| StorageAttackHotspotResponse {
                    source_ip: item.source_ip,
                    action: item.action,
                    route: item.route,
                    count: item.count,
                    time_window_start: item.time_window_start,
                    time_window_end: item.time_window_end,
                })
                .collect(),
        },
        system: sample_system_metrics(),
    }
}

fn build_ai_temp_policy_metrics(
    policies: &[crate::storage::AiTempPolicyEntry],
    max_active_count: u32,
) -> AiTempPolicyMetricsResponse {
    let mut response = AiTempPolicyMetricsResponse {
        active_count: policies.len() as u32,
        max_active_count,
        ..AiTempPolicyMetricsResponse::default()
    };

    for policy in policies {
        if policy.auto_applied {
            response.auto_applied_count = response.auto_applied_count.saturating_add(1);
        }
        let effect =
            serde_json::from_str::<crate::storage::AiTempPolicyEffectStats>(&policy.effect_json)
                .unwrap_or_default();
        response.total_hits = response.total_hits.saturating_add(effect.total_hits);
        response.total_observations = response
            .total_observations
            .saturating_add(effect.post_policy_observations);
        response.auto_extensions = response
            .auto_extensions
            .saturating_add(effect.auto_extensions);
        if effect.auto_revoked {
            response.auto_revoked_count = response.auto_revoked_count.saturating_add(1);
        }
        match effect.outcome_status.as_deref().unwrap_or("warming") {
            "effective" => response.effective_count = response.effective_count.saturating_add(1),
            "harmful" => response.harmful_count = response.harmful_count.saturating_add(1),
            "neutral" => response.neutral_count = response.neutral_count.saturating_add(1),
            _ => response.warming_count = response.warming_count.saturating_add(1),
        }
    }

    response
}

struct SystemMetricsSampler {
    system: System,
    networks: Networks,
    process_pid: Option<Pid>,
    previous_network_rx_bytes: u64,
    previous_network_tx_bytes: u64,
    previous_process_disk_read_bytes: u64,
    previous_process_disk_write_bytes: u64,
    previous_sample_at: Instant,
}

impl SystemMetricsSampler {
    fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_cpu();
        system.refresh_memory();

        let networks = Networks::new_with_refreshed_list();
        let process_pid = get_current_pid().ok();
        if let Some(pid) = process_pid {
            system.refresh_process_specifics(pid, ProcessRefreshKind::new().with_disk_usage());
        }
        let (network_rx, network_tx) = network_totals(&networks);
        let (process_disk_read, process_disk_write) = process_disk_totals(&system, process_pid);

        Self {
            system,
            networks,
            process_pid,
            previous_network_rx_bytes: network_rx,
            previous_network_tx_bytes: network_tx,
            previous_process_disk_read_bytes: process_disk_read,
            previous_process_disk_write_bytes: process_disk_write,
            previous_sample_at: Instant::now(),
        }
    }

    fn sample(&mut self) -> SystemMetricsResponse {
        self.system.refresh_cpu();
        self.system.refresh_memory();
        if let Some(pid) = self.process_pid {
            self.system
                .refresh_process_specifics(pid, ProcessRefreshKind::new().with_disk_usage());
        }
        self.networks.refresh();

        let now = Instant::now();
        let elapsed_secs = now
            .duration_since(self.previous_sample_at)
            .as_secs_f64()
            .max(0.001);
        let (network_rx, network_tx) = network_totals(&self.networks);
        let (process_disk_read, process_disk_write) =
            process_disk_totals(&self.system, self.process_pid);
        let network_rx_bytes_per_sec =
            rate_per_second(network_rx, self.previous_network_rx_bytes, elapsed_secs);
        let network_tx_bytes_per_sec =
            rate_per_second(network_tx, self.previous_network_tx_bytes, elapsed_secs);
        let process_disk_read_bytes_per_sec = rate_per_second(
            process_disk_read,
            self.previous_process_disk_read_bytes,
            elapsed_secs,
        );
        let process_disk_write_bytes_per_sec = rate_per_second(
            process_disk_write,
            self.previous_process_disk_write_bytes,
            elapsed_secs,
        );

        self.previous_network_rx_bytes = network_rx;
        self.previous_network_tx_bytes = network_tx;
        self.previous_process_disk_read_bytes = process_disk_read;
        self.previous_process_disk_write_bytes = process_disk_write;
        self.previous_sample_at = now;

        let memory_total_bytes = self.system.total_memory();
        let memory_used_bytes = self.system.used_memory();
        let memory_usage_percent = if memory_total_bytes == 0 {
            0.0
        } else {
            (memory_used_bytes as f64 * 100.0 / memory_total_bytes as f64) as f32
        };

        SystemMetricsResponse {
            cpu_usage_percent: self.system.global_cpu_info().cpu_usage(),
            cpu_core_count: self.system.cpus().len(),
            memory_used_bytes,
            memory_total_bytes,
            memory_usage_percent,
            network_rx_bytes_per_sec,
            network_tx_bytes_per_sec,
            network_rx_total_bytes: network_rx,
            network_tx_total_bytes: network_tx,
            process_disk_read_bytes_per_sec,
            process_disk_write_bytes_per_sec,
        }
    }
}

fn sample_system_metrics() -> SystemMetricsResponse {
    static SAMPLER: OnceLock<Mutex<SystemMetricsSampler>> = OnceLock::new();
    let sampler = SAMPLER.get_or_init(|| Mutex::new(SystemMetricsSampler::new()));
    match sampler.lock() {
        Ok(mut guard) => guard.sample(),
        Err(err) => {
            log::warn!("Failed to sample system metrics: {}", err);
            SystemMetricsResponse::default()
        }
    }
}

fn network_totals(networks: &Networks) -> (u64, u64) {
    networks.iter().fold((0_u64, 0_u64), |(rx, tx), (_, data)| {
        (
            rx.saturating_add(data.total_received()),
            tx.saturating_add(data.total_transmitted()),
        )
    })
}

fn process_disk_totals(system: &System, pid: Option<Pid>) -> (u64, u64) {
    pid.and_then(|pid| system.process(pid))
        .map(|process| {
            let usage = process.disk_usage();
            (usage.total_read_bytes, usage.total_written_bytes)
        })
        .unwrap_or_default()
}

fn rate_per_second(current: u64, previous: u64, elapsed_secs: f64) -> u64 {
    (current.saturating_sub(previous) as f64 / elapsed_secs).round() as u64
}

fn build_storage_degraded_reasons(
    storage_summary: &crate::storage::StorageMetricsSummary,
    aggregation_insights: &crate::storage::StorageAggregationInsightSummary,
    runtime_pressure: &RuntimePressureSnapshot,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if runtime_pressure.trim_event_persistence {
        reasons.push("storage_low_value_event_persistence_trimmed".to_string());
    }
    if storage_summary.dropped_security_events > 0 {
        reasons.push("storage_security_events_dropped_under_pressure".to_string());
    }
    if aggregation_insights.long_tail_event_count > 0 {
        reasons.push("storage_long_tail_sources_merged".to_string());
    }
    if aggregation_insights.active_bucket_count > 0 {
        reasons.push("storage_hotspot_aggregation_active".to_string());
    }
    reasons
}
