use super::types::{VisitorDecisionSignal, VisitorProfileSignal, VISITOR_WINDOW_SECS};
use crate::core::unix_timestamp;
use crate::storage::{AiVisitorDecisionUpsert, AiVisitorProfileUpsert};

impl From<VisitorProfileSignal> for AiVisitorProfileUpsert {
    fn from(value: VisitorProfileSignal) -> Self {
        let summary_json = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string());
        Self {
            identity_key: value.identity_key,
            identity_source: value.identity_source,
            site_id: value.site_id,
            client_ip: value.client_ip,
            user_agent: value.user_agent,
            first_seen_at: value.first_seen_at,
            last_seen_at: value.last_seen_at,
            request_count: value.request_count as i64,
            document_count: value.document_count as i64,
            api_count: value.api_count as i64,
            static_count: value.static_count as i64,
            admin_count: value.admin_count as i64,
            challenge_count: value.challenge_count as i64,
            challenge_verified_count: value.challenge_verified_count as i64,
            fingerprint_seen: value.fingerprint_seen,
            human_confidence: i64::from(value.human_confidence),
            automation_risk: i64::from(value.automation_risk),
            probe_risk: i64::from(value.probe_risk),
            abuse_risk: i64::from(value.abuse_risk),
            false_positive_risk: value.false_positive_risk,
            state: value.state,
            summary_json,
            last_ai_review_at: Some(unix_timestamp()),
            ai_rationale: value.ai_rationale,
            expires_at: unix_timestamp() + VISITOR_WINDOW_SECS,
        }
    }
}

impl From<VisitorDecisionSignal> for AiVisitorDecisionUpsert {
    fn from(value: VisitorDecisionSignal) -> Self {
        Self {
            decision_key: value.decision_key,
            identity_key: value.identity_key,
            site_id: value.site_id,
            created_at: unix_timestamp(),
            action: value.action,
            confidence: i64::from(value.confidence),
            ttl_secs: value.ttl_secs as i64,
            rationale: value.rationale,
            applied: value.applied,
            effect_json: serde_json::json!({
                "status": value.effect_status,
            })
            .to_string(),
        }
    }
}
