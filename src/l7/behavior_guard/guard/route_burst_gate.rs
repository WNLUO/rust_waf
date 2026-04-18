use super::*;

impl L7BehaviorGuard {
    pub(super) fn inspect_route_burst(
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
}
