use super::*;

impl L7BehaviorGuard {
    pub(super) fn respond_to_aggregate_challenge(
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

    pub(super) fn active_aggregate_enforcement(
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

    pub(super) fn activate_aggregate_enforcement(
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
}
