use super::*;

#[derive(Debug)]
pub struct L7BehaviorGuard {
    pub(super) buckets: DashMap<String, BehaviorWindow>,
    pub(super) aggregate_buckets: DashMap<String, BehaviorWindow>,
    pub(super) aggregate_enforcements: DashMap<String, AggregateEnforcement>,
    pub(super) route_burst_buckets: DashMap<String, RouteBurstWindow>,
    request_sequence: AtomicU64,
}

impl L7BehaviorGuard {
    pub fn new() -> Self {
        Self {
            buckets: DashMap::new(),
            aggregate_buckets: DashMap::new(),
            aggregate_enforcements: DashMap::new(),
            route_burst_buckets: DashMap::new(),
            request_sequence: AtomicU64::new(0),
        }
    }

    pub async fn inspect_request(
        &self,
        request: &mut UnifiedHttpRequest,
    ) -> Option<InspectionResult> {
        if request
            .get_metadata("network.server_public_ip_exempt")
            .map(|value| value == "true")
            .unwrap_or(false)
        {
            request.add_metadata(
                "l7.behavior.skipped".to_string(),
                "server_public_ip".to_string(),
            );
            return None;
        }
        if request_utils::has_valid_behavior_clearance(request) {
            request.add_metadata(
                "l7.behavior.skipped".to_string(),
                "behavior_clearance".to_string(),
            );
            return None;
        }
        if request
            .get_metadata("ai.visitor.reduce_friction")
            .is_some_and(|value| value == "true")
        {
            request.add_metadata(
                "l7.behavior.skipped".to_string(),
                "visitor_reduce_friction".to_string(),
            );
            return None;
        }
        if matches!(
            request
                .get_metadata("client.trust_class")
                .map(String::as_str),
            Some("internal" | "verified_good_bot")
        ) {
            request.add_metadata(
                "l7.behavior.skipped".to_string(),
                request
                    .get_metadata("client.trust_class")
                    .map(|value| format!("client_trust:{value}"))
                    .unwrap_or_else(|| "client_trust".to_string()),
            );
            return None;
        }
        let defense_depth = runtime_defense_depth(request);
        if defense_depth == crate::core::DefenseDepth::Survival {
            request.add_metadata(
                "l7.behavior.skipped".to_string(),
                "resource_survival".to_string(),
            );
            return None;
        }
        let sample_stride =
            runtime_u64_metadata(request, "runtime.budget.behavior_sample_stride", 1);
        if sample_stride > 1 {
            let sequence = self.request_sequence.fetch_add(1, Ordering::Relaxed) + 1;
            if !sequence.is_multiple_of(sample_stride) {
                request.add_metadata(
                    "l7.behavior.skipped".to_string(),
                    "resource_sampling".to_string(),
                );
                return None;
            }
        }
        let bucket_limit = runtime_usize_metadata(
            request,
            "runtime.budget.behavior_bucket_limit",
            MAX_BEHAVIOR_BUCKETS,
        )
        .clamp(512, MAX_BEHAVIOR_BUCKETS);
        let route = request
            .get_metadata("l7.cc.route")
            .cloned()
            .unwrap_or_else(|| normalized_route_path(request_path(&request.uri)));
        let kind = request_kind(request);
        let client_ip = request
            .client_ip
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let user_agent = behavior_user_agent(request);
        let header_signature = behavior_header_signature(request);
        let now = Instant::now();
        let unix_now = unix_timestamp();
        let window = Duration::from_secs(BEHAVIOR_WINDOW_SECS);
        let aggregate_keys = behavior_aggregate_keys(request, &route, kind);
        let active_aggregate_enforcement = self.active_aggregate_enforcement(&aggregate_keys, now);
        if active_aggregate_enforcement
            .as_ref()
            .is_some_and(|enforcement| {
                matches!(enforcement.action, AggregateEnforcementAction::Block)
            })
        {
            let enforcement = active_aggregate_enforcement.expect("checked above");
            request.add_metadata(
                "l7.behavior.identity".to_string(),
                enforcement.identity.clone(),
            );
            request.add_metadata(
                "l7.behavior.score".to_string(),
                enforcement.score.to_string(),
            );
            request.add_metadata(
                "l7.behavior.action".to_string(),
                enforcement.action.as_str().to_string(),
            );
            request.add_metadata(
                "l7.behavior.aggregate_enforcement".to_string(),
                "active".to_string(),
            );
            request.add_metadata("l7.behavior.flags".to_string(), enforcement.flags.join(","));
            let reason = format!(
                "l7 behavior guard aggregate enforcement: identity={} score={} flags={}",
                enforcement.identity,
                enforcement.score,
                enforcement.flags.join("|"),
            );
            request.add_metadata("l7.enforcement".to_string(), "drop".to_string());
            request.add_metadata(
                "l7.drop_reason".to_string(),
                "behavior_aggregate_enforcement".to_string(),
            );
            request.add_metadata("l4.force_close".to_string(), "true".to_string());
            return Some(InspectionResult::drop(InspectionLayer::L7, reason));
        }
        if let Some(result) = self.inspect_route_burst(
            request,
            &route,
            kind,
            client_ip.clone(),
            user_agent.clone(),
            header_signature.clone(),
            now,
            unix_now,
            bucket_limit,
        ) {
            return Some(result);
        }
        let identity_assessment = request_identity(request).map(|identity| {
            self.observe_and_assess(
                &identity,
                route.clone(),
                kind,
                client_ip.clone(),
                user_agent.clone(),
                header_signature.clone(),
                now,
                unix_now,
                window,
                bucket_limit,
            )
        });
        let aggregate_assessment = aggregate_keys
            .into_iter()
            .map(|(key, aggregate_route)| {
                self.observe_aggregate_and_assess(
                    &key,
                    aggregate_route,
                    kind,
                    client_ip.clone(),
                    user_agent.clone(),
                    header_signature.clone(),
                    now,
                    unix_now,
                    window,
                    bucket_limit,
                )
            })
            .max_by_key(|assessment| assessment.score);
        let Some(mut assessment) =
            select_behavior_assessment(identity_assessment, aggregate_assessment)
        else {
            if let Some(enforcement) = active_aggregate_enforcement {
                return Some(self.respond_to_aggregate_challenge(request, enforcement));
            }
            return None;
        };
        let ai_score_boost = request
            .get_metadata("ai.behavior.score_boost")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0);
        let ai_force_watch = request
            .get_metadata("ai.behavior.force_watch")
            .map(|value| value == "true")
            .unwrap_or(false);
        if ai_score_boost > 0 {
            assessment.score = assessment.score.saturating_add(ai_score_boost).min(100);
            assessment.flags.push("ai_temp_risk");
        }
        if ai_force_watch && assessment.score < DELAY_SCORE {
            assessment.score = DELAY_SCORE;
            assessment.flags.push("ai_temp_watch");
        }
        let client_trust_class = request
            .get_metadata("client.trust_class")
            .map(String::as_str);
        if client_trust_class == Some("claimed_good_bot") {
            let reduction = if request.get_metadata("bot.policy").map(String::as_str)
                == Some("reduce_friction")
            {
                30
            } else {
                15
            };
            assessment.score = assessment.score.saturating_sub(reduction);
            assessment.flags.push("known_crawler_library");
        }
        if client_trust_class == Some("suspect_bot") {
            assessment.score = assessment.score.saturating_add(20).min(100);
            assessment.flags.push("crawler_ua_ip_mismatch");
        }

        request.add_metadata(
            "l7.behavior.identity".to_string(),
            assessment.identity.clone(),
        );
        request.add_metadata(
            "l7.behavior.score".to_string(),
            assessment.score.to_string(),
        );
        request.add_metadata(
            "l7.behavior.distinct_routes".to_string(),
            assessment.distinct_routes.to_string(),
        );
        request.add_metadata(
            "l7.behavior.distinct_client_ips".to_string(),
            assessment.distinct_client_ips.to_string(),
        );
        request.add_metadata(
            "l7.behavior.distinct_user_agents".to_string(),
            assessment.distinct_user_agents.to_string(),
        );
        request.add_metadata(
            "l7.behavior.distinct_header_signatures".to_string(),
            assessment.distinct_header_signatures.to_string(),
        );
        request.add_metadata(
            "l7.behavior.repeated_ratio".to_string(),
            assessment.repeated_ratio_percent.to_string(),
        );
        request.add_metadata(
            "l7.behavior.client_ip_repeated_ratio".to_string(),
            assessment.client_ip_repeated_ratio_percent.to_string(),
        );
        request.add_metadata(
            "l7.behavior.document_repeated_ratio".to_string(),
            assessment.document_repeated_ratio_percent.to_string(),
        );
        request.add_metadata(
            "l7.behavior.document_requests".to_string(),
            assessment.document_requests.to_string(),
        );
        request.add_metadata(
            "l7.behavior.api_requests".to_string(),
            assessment.api_requests.to_string(),
        );
        request.add_metadata(
            "l7.behavior.non_document_requests".to_string(),
            assessment.non_document_requests.to_string(),
        );
        request.add_metadata(
            "l7.behavior.api_repeated_ratio".to_string(),
            assessment.api_repeated_ratio_percent.to_string(),
        );
        request.add_metadata(
            "l7.behavior.challenge_count_window".to_string(),
            assessment.recent_challenges.to_string(),
        );
        request.add_metadata(
            "l7.behavior.session_span_secs".to_string(),
            assessment.session_span_secs.to_string(),
        );
        if !assessment.flags.is_empty() {
            request.add_metadata("l7.behavior.flags".to_string(), assessment.flags.join(","));
        }
        if let Some(route) = assessment.dominant_route.as_ref() {
            request.add_metadata("l7.behavior.dominant_route".to_string(), route.clone());
        }
        if let Some(route) = assessment.focused_document_route.as_ref() {
            request.add_metadata(
                "l7.behavior.focused_document_route".to_string(),
                route.clone(),
            );
        }
        if let Some(route) = assessment.focused_api_route.as_ref() {
            request.add_metadata("l7.behavior.focused_api_route".to_string(), route.clone());
        }
        if let Some(jitter_ms) = assessment.jitter_ms {
            request.add_metadata(
                "l7.behavior.interval_jitter_ms".to_string(),
                jitter_ms.to_string(),
            );
        }

        self.maybe_cleanup(unix_now);

        let should_auto_block = assessment.score >= BLOCK_SCORE
            || (assessment.score >= CHALLENGE_SCORE
                && assessment.recent_challenges >= CHALLENGES_BEFORE_AUTO_BLOCK);

        if should_auto_block {
            self.activate_aggregate_enforcement(
                &assessment,
                AggregateEnforcementAction::Block,
                now,
            );
            self.record_block(&assessment.identity, now, window);
            request.add_metadata("l7.behavior.action".to_string(), "block".to_string());
            request.add_metadata("l7.enforcement".to_string(), "drop".to_string());
            request.add_metadata(
                "l7.drop_reason".to_string(),
                "behavior_auto_block".to_string(),
            );
            request.add_metadata("l4.force_close".to_string(), "true".to_string());
            let reason = format!(
                "l7 behavior guard blocked suspicious session: score={} repeated_ratio={} document_repeated_ratio={} distinct_routes={} dominant_route={} recent_challenges={} flags={}",
                assessment.score,
                assessment.repeated_ratio_percent,
                assessment.document_repeated_ratio_percent,
                assessment.distinct_routes,
                assessment.dominant_route.as_deref().unwrap_or("*"),
                assessment.recent_challenges,
                assessment.flags.join("|"),
            );
            return Some(InspectionResult::drop_and_persist_ip(
                InspectionLayer::L7,
                reason,
            ));
        }

        if assessment.score >= CHALLENGE_SCORE {
            self.activate_aggregate_enforcement(
                &assessment,
                AggregateEnforcementAction::Challenge,
                now,
            );
            self.record_challenge(&assessment.identity, now, window);
            request.add_metadata("l7.behavior.action".to_string(), "challenge".to_string());
            let reason = format!(
                "l7 behavior guard challenged suspicious session: score={} repeated_ratio={} document_repeated_ratio={} distinct_routes={} dominant_route={} recent_challenges={} flags={}",
                assessment.score,
                assessment.repeated_ratio_percent,
                assessment.document_repeated_ratio_percent,
                assessment.distinct_routes,
                assessment.dominant_route.as_deref().unwrap_or("*"),
                assessment.recent_challenges,
                assessment.flags.join("|"),
            );
            return Some(InspectionResult::respond(
                InspectionLayer::L7,
                reason.clone(),
                build_behavior_response(request, 429, "访问行为异常，请稍后再试", &reason),
            ));
        }

        if let Some(enforcement) = active_aggregate_enforcement {
            return Some(self.respond_to_aggregate_challenge(request, enforcement));
        }

        if assessment.score >= DELAY_SCORE {
            if should_drop_delay_under_pressure(request) {
                self.record_challenge(&assessment.identity, now, window);
                request.add_metadata("l7.behavior.action".to_string(), "challenge".to_string());
                let reason = format!(
                    "l7 behavior guard upgraded delay to challenge under runtime pressure: score={} repeated_ratio={} document_repeated_ratio={} distinct_routes={} dominant_route={} flags={}",
                    assessment.score,
                    assessment.repeated_ratio_percent,
                    assessment.document_repeated_ratio_percent,
                    assessment.distinct_routes,
                    assessment.dominant_route.as_deref().unwrap_or("*"),
                    assessment.flags.join("|"),
                );
                return Some(InspectionResult::respond(
                    InspectionLayer::L7,
                    reason.clone(),
                    build_behavior_response(request, 429, "系统繁忙，请稍后重试", &reason),
                ));
            }
            request.add_metadata(
                "l7.behavior.action".to_string(),
                format!("delay:{DELAY_MS}ms"),
            );
            tokio::time::sleep(Duration::from_millis(DELAY_MS)).await;
        }

        None
    }

    fn respond_to_aggregate_challenge(
        &self,
        request: &mut UnifiedHttpRequest,
        enforcement: AggregateEnforcement,
    ) -> InspectionResult {
        request.add_metadata(
            "l7.behavior.identity".to_string(),
            enforcement.identity.clone(),
        );
        request.add_metadata(
            "l7.behavior.score".to_string(),
            enforcement.score.to_string(),
        );
        request.add_metadata(
            "l7.behavior.action".to_string(),
            enforcement.action.as_str().to_string(),
        );
        request.add_metadata(
            "l7.behavior.aggregate_enforcement".to_string(),
            "active".to_string(),
        );
        request.add_metadata("l7.behavior.flags".to_string(), enforcement.flags.join(","));
        let reason = format!(
            "l7 behavior guard aggregate enforcement: identity={} score={} flags={}",
            enforcement.identity,
            enforcement.score,
            enforcement.flags.join("|"),
        );
        InspectionResult::respond(
            InspectionLayer::L7,
            reason.clone(),
            build_behavior_response(request, 429, "访问行为异常，请稍后再试", &reason),
        )
    }

    fn observe_and_assess(
        &self,
        identity: &str,
        route: String,
        kind: RequestKind,
        client_ip: Option<String>,
        user_agent: Option<String>,
        header_signature: Option<String>,
        now: Instant,
        unix_now: i64,
        window: Duration,
        bucket_limit: usize,
    ) -> BehaviorAssessment {
        let identity = bounded_dashmap_key(
            &self.buckets,
            compact_component("identity", &identity, MAX_BEHAVIOR_KEY_LEN),
            bucket_limit,
            "behavior",
            OVERFLOW_SHARDS,
        );
        let mut entry = self
            .buckets
            .entry(identity.clone())
            .or_insert_with(BehaviorWindow::new);
        entry.observe_and_assess(
            identity,
            route,
            kind,
            client_ip,
            user_agent,
            header_signature,
            now,
            unix_now,
            window,
        )
    }

    fn observe_aggregate_and_assess(
        &self,
        identity: &str,
        route: String,
        kind: RequestKind,
        client_ip: Option<String>,
        user_agent: Option<String>,
        header_signature: Option<String>,
        now: Instant,
        unix_now: i64,
        window: Duration,
        bucket_limit: usize,
    ) -> BehaviorAssessment {
        let identity = bounded_dashmap_key(
            &self.aggregate_buckets,
            compact_component("aggregate", identity, MAX_BEHAVIOR_KEY_LEN),
            bucket_limit,
            "behavior-aggregate",
            OVERFLOW_SHARDS,
        );
        let mut entry = self
            .aggregate_buckets
            .entry(identity.clone())
            .or_insert_with(BehaviorWindow::new);
        entry.observe_and_assess(
            identity,
            route,
            kind,
            client_ip,
            user_agent,
            header_signature,
            now,
            unix_now,
            window,
        )
    }

    fn maybe_cleanup(&self, unix_now: i64) {
        let sequence = self.request_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        if !sequence.is_multiple_of(CLEANUP_EVERY_REQUESTS) {
            return;
        }

        let stale_before = unix_now - (BEHAVIOR_WINDOW_SECS as i64 * 3).max(180);
        let keys = self
            .buckets
            .iter()
            .filter(|entry| entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_before)
            .take(512)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in keys {
            self.buckets.remove(&key);
        }

        let aggregate_keys = self
            .aggregate_buckets
            .iter()
            .filter(|entry| entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_before)
            .take(512)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in aggregate_keys {
            self.aggregate_buckets.remove(&key);
        }

        let stale_burst_before = unix_now - (ROUTE_BURST_WINDOW_SECS as i64 * 6).max(30);
        let route_burst_keys = self
            .route_burst_buckets
            .iter()
            .filter(|entry| {
                entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_burst_before
            })
            .take(512)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in route_burst_keys {
            self.route_burst_buckets.remove(&key);
        }

        let expired_enforcements = self
            .aggregate_enforcements
            .iter()
            .filter(|entry| entry.value().expires_at <= Instant::now())
            .take(512)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in expired_enforcements {
            self.aggregate_enforcements.remove(&key);
        }
    }

    fn active_aggregate_enforcement(
        &self,
        aggregate_keys: &[(String, String)],
        now: Instant,
    ) -> Option<AggregateEnforcement> {
        let mut selected = None;
        for (key, _) in aggregate_keys {
            let key = aggregate_enforcement_key(key);
            let Some(entry) = self.aggregate_enforcements.get(&key) else {
                continue;
            };
            if entry.expires_at <= now {
                drop(entry);
                self.aggregate_enforcements.remove(&key);
                continue;
            }
            let enforcement = entry.clone();
            if matches!(enforcement.action, AggregateEnforcementAction::Block) {
                return Some(enforcement);
            }
            selected = Some(enforcement);
        }
        selected
    }

    fn activate_aggregate_enforcement(
        &self,
        assessment: &BehaviorAssessment,
        action: AggregateEnforcementAction,
        now: Instant,
    ) {
        if !assessment_allows_aggregate_enforcement(assessment) {
            return;
        }
        let ttl = match action {
            AggregateEnforcementAction::Challenge => AGGREGATE_CHALLENGE_ENFORCEMENT_SECS,
            AggregateEnforcementAction::Block => AGGREGATE_BLOCK_ENFORCEMENT_SECS,
        };
        self.aggregate_enforcements.insert(
            aggregate_enforcement_key(&assessment.identity),
            AggregateEnforcement {
                identity: assessment.identity.clone(),
                action,
                score: assessment.score,
                flags: assessment
                    .flags
                    .iter()
                    .map(|flag| (*flag).to_string())
                    .collect(),
                expires_at: now + Duration::from_secs(ttl),
            },
        );
    }

    fn inspect_route_burst(
        &self,
        request: &mut UnifiedHttpRequest,
        route: &str,
        kind: RequestKind,
        client_ip: Option<String>,
        user_agent: Option<String>,
        header_signature: Option<String>,
        now: Instant,
        unix_now: i64,
        bucket_limit: usize,
    ) -> Option<InspectionResult> {
        if !matches!(kind, RequestKind::Document | RequestKind::Api) || route_burst_exempt(route) {
            return None;
        }
        let keys = route_burst_keys(request, route, kind);
        if keys.is_empty() {
            return None;
        }
        let script_like = request_is_script_like_document(request);
        let mut selected = None;
        for key in keys {
            let key = bounded_dashmap_key(
                &self.route_burst_buckets,
                compact_component("route-burst", &key, MAX_BEHAVIOR_KEY_LEN),
                bucket_limit,
                "behavior-route-burst",
                OVERFLOW_SHARDS,
            );
            let mut entry = self
                .route_burst_buckets
                .entry(key.clone())
                .or_insert_with(RouteBurstWindow::new);
            let mut assessment = entry.observe_and_assess(
                RouteBurstSample {
                    client_ip: client_ip.clone(),
                    user_agent: user_agent.clone(),
                    header_signature: header_signature.clone(),
                    script_like,
                    at: now,
                },
                unix_now,
            );
            assessment.identity = key;
            if selected
                .as_ref()
                .map_or(true, |candidate: &RouteBurstAssessment| {
                    assessment.rank() > candidate.rank()
                })
            {
                selected = Some(assessment);
            }
        }
        let assessment = selected?;
        if assessment.action == RouteBurstAction::None {
            return None;
        }
        request.add_metadata(
            "l7.behavior.identity".to_string(),
            assessment.identity.clone(),
        );
        request.add_metadata(
            "l7.behavior.score".to_string(),
            assessment.score.to_string(),
        );
        request.add_metadata(
            "l7.behavior.action".to_string(),
            assessment.action.as_str().to_string(),
        );
        request.add_metadata(
            "l7.behavior.aggregate_enforcement".to_string(),
            "route_burst".to_string(),
        );
        request.add_metadata(
            "l7.behavior.flags".to_string(),
            "route_burst_gate".to_string(),
        );
        request.add_metadata(
            "l7.behavior.distinct_client_ips".to_string(),
            assessment.distinct_client_ips.to_string(),
        );
        request.add_metadata(
            "l7.behavior.distinct_user_agents".to_string(),
            assessment.distinct_user_agents.to_string(),
        );
        request.add_metadata(
            "l7.behavior.distinct_header_signatures".to_string(),
            assessment.distinct_header_signatures.to_string(),
        );
        let reason = format!(
            "l7 behavior route burst gate: identity={} total={} distinct_client_ips={} script_like_ratio={} distinct_user_agents={} distinct_header_signatures={}",
            assessment.identity,
            assessment.total,
            assessment.distinct_client_ips,
            assessment.script_like_ratio_percent,
            assessment.distinct_user_agents,
            assessment.distinct_header_signatures,
        );
        match assessment.action {
            RouteBurstAction::Block => {
                request.add_metadata("l7.enforcement".to_string(), "drop".to_string());
                request.add_metadata(
                    "l7.drop_reason".to_string(),
                    "behavior_route_burst".to_string(),
                );
                request.add_metadata("l4.force_close".to_string(), "true".to_string());
                Some(InspectionResult::drop(InspectionLayer::L7, reason))
            }
            RouteBurstAction::Challenge => Some(InspectionResult::respond(
                InspectionLayer::L7,
                reason.clone(),
                build_behavior_response(request, 429, "访问行为异常，请稍后再试", &reason),
            )),
            RouteBurstAction::None => None,
        }
    }

    fn record_challenge(&self, identity: &str, now: Instant, window: Duration) {
        if let Some(mut entry) = self.buckets.get_mut(identity) {
            entry.record_challenge(now, window);
            return;
        }
        if let Some(mut entry) = self.aggregate_buckets.get_mut(identity) {
            entry.record_challenge(now, window);
        }
    }

    fn record_block(&self, identity: &str, now: Instant, window: Duration) {
        if let Some(mut entry) = self.buckets.get_mut(identity) {
            entry.record_block(now, window);
            return;
        }
        if let Some(mut entry) = self.aggregate_buckets.get_mut(identity) {
            entry.record_block(now, window);
        }
    }

    pub fn snapshot_profiles(&self, limit: usize) -> Vec<BehaviorProfileSnapshot> {
        let now = Instant::now();
        let unix_now = unix_timestamp();
        let window = Duration::from_secs(BEHAVIOR_WINDOW_SECS);
        let mut profiles = self
            .buckets
            .iter()
            .filter_map(|entry| {
                let last_seen_unix = entry.value().last_seen_unix.load(Ordering::Relaxed);
                if unix_now.saturating_sub(last_seen_unix) > ACTIVE_PROFILE_IDLE_SECS {
                    return None;
                }
                entry.value().snapshot(entry.key().clone(), now, window)
            })
            .collect::<Vec<_>>();
        profiles.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| right.latest_seen_unix.cmp(&left.latest_seen_unix))
        });
        if limit > 0 && profiles.len() > limit {
            profiles.truncate(limit);
        }
        profiles
    }
}
