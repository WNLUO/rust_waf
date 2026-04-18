use super::*;

impl WafContext {
    pub(super) fn ai_defense_l4_signal(&self) -> Option<AiDefenseL4Signal> {
        let stats = self.l4_inspector()?.get_statistics();
        let mut ports = stats
            .per_port_stats
            .values()
            .map(|port| AiDefensePortSignal {
                port: port.port.clone(),
                connections: port.connections,
                blocks: port.blocks,
                ddos_events: port.ddos_events,
            })
            .collect::<Vec<_>>();
        ports.sort_by(|left, right| {
            right
                .blocks
                .cmp(&left.blocks)
                .then_with(|| right.ddos_events.cmp(&left.ddos_events))
                .then_with(|| right.connections.cmp(&left.connections))
        });
        ports.truncate(5);
        Some(AiDefenseL4Signal {
            active_connections: stats.connections.active_connections,
            blocked_connections: stats.connections.blocked_connections,
            rate_limit_hits: stats.connections.rate_limit_hits,
            ddos_events: stats.ddos_events,
            protocol_anomalies: stats.protocol_anomalies,
            defense_actions: stats.defense_actions,
            top_ports: ports,
        })
    }

    pub(super) fn ai_defense_identity_summaries(
        &self,
        now: i64,
        limit: usize,
    ) -> Vec<AiDefenseIdentitySignal> {
        let mut summaries = self
            .ai_defense_identity_buckets
            .iter()
            .filter_map(|entry| {
                let (site_id, route) = split_ai_defense_identity_key(entry.key())?;
                let bucket = entry
                    .value()
                    .lock()
                    .expect("ai defense identity bucket lock poisoned");
                if now.saturating_sub(bucket.window_start) > 75 {
                    return None;
                }
                let mut top_user_agents = bucket
                    .user_agents
                    .iter()
                    .map(|(value, count)| AiDefenseUserAgentSignal {
                        value: value.clone(),
                        count: *count,
                    })
                    .collect::<Vec<_>>();
                top_user_agents.sort_by(|left, right| right.count.cmp(&left.count));
                top_user_agents.truncate(5);
                Some(AiDefenseIdentitySignal {
                    site_id,
                    route,
                    total_events: bucket.total_events,
                    distinct_client_count: bucket.distinct_clients.len(),
                    unresolved_events: bucket.unresolved_events,
                    trusted_proxy_events: bucket.trusted_proxy_events,
                    verified_challenge_events: bucket.verified_challenge_events,
                    interactive_session_events: bucket.interactive_session_events,
                    spoofed_forward_header_events: bucket.spoofed_forward_header_events,
                    top_user_agents,
                })
            })
            .collect::<Vec<_>>();
        summaries.sort_by(|left, right| {
            right
                .total_events
                .cmp(&left.total_events)
                .then_with(|| right.distinct_client_count.cmp(&left.distinct_client_count))
        });
        summaries.truncate(limit);
        summaries
    }

    pub(super) fn ai_defense_route_profile_signals(
        &self,
        limit: usize,
    ) -> Vec<AiDefenseRouteProfileSignal> {
        self.active_ai_route_profiles()
            .into_iter()
            .take(limit)
            .map(ai_defense_route_profile_signal)
            .collect()
    }

    pub(super) fn ai_defense_route_effect_signals(
        &self,
        now: i64,
        limit: usize,
    ) -> Vec<AiDefenseRouteEffectSignal> {
        let mut signals = self
            .ai_route_result_buckets
            .iter()
            .filter_map(|entry| {
                let (site_id, route) = split_ai_defense_identity_key(entry.key())?;
                let bucket = entry
                    .value()
                    .lock()
                    .expect("ai route result bucket lock poisoned");
                if now.saturating_sub(bucket.window_start) > 75 {
                    return None;
                }
                let false_positive_risk = classify_false_positive_risk(
                    bucket.total_responses,
                    bucket.suspected_false_positive_events,
                    bucket.challenge_verified,
                    bucket.interactive_sessions,
                    bucket.blocked_responses,
                );
                let effectiveness_hint = classify_route_effectiveness(&bucket);
                Some(AiDefenseRouteEffectSignal {
                    site_id,
                    route,
                    total_responses: bucket.total_responses,
                    upstream_successes: bucket.upstream_successes,
                    upstream_errors: bucket.upstream_errors,
                    local_responses: bucket.local_responses,
                    blocked_responses: bucket.blocked_responses,
                    challenge_issued: bucket.challenge_issued,
                    challenge_verified: bucket.challenge_verified,
                    interactive_sessions: bucket.interactive_sessions,
                    policy_matched_responses: bucket.policy_matched_responses,
                    suspected_false_positive_events: bucket.suspected_false_positive_events,
                    status_families: bucket.status_families.clone(),
                    status_codes: bucket.status_codes.clone(),
                    policy_actions: bucket.policy_actions.clone(),
                    avg_latency_ms: (bucket.latency_samples > 0)
                        .then(|| bucket.latency_ms_total / bucket.latency_samples),
                    slow_responses: bucket.slow_responses,
                    false_positive_risk: false_positive_risk.to_string(),
                    effectiveness_hint: effectiveness_hint.to_string(),
                })
            })
            .collect::<Vec<_>>();
        signals.sort_by(|left, right| {
            right
                .suspected_false_positive_events
                .cmp(&left.suspected_false_positive_events)
                .then_with(|| right.upstream_errors.cmp(&left.upstream_errors))
                .then_with(|| right.total_responses.cmp(&left.total_responses))
        });
        signals.truncate(limit);
        signals
    }
}
