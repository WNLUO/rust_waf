use super::{
    ai_temp_policy::{
        ai_request_identity, match_ai_temp_policy, parse_scale_percent, parse_suggested_delay_ms,
    },
    unix_timestamp, InspectionLayer, InspectionResult, WafContext,
};
use crate::protocol::UnifiedHttpRequest;
use crate::storage::{AiTempPolicyEntry, AiTempPolicyHitRecord};
use anyhow::Result;

impl WafContext {
    pub fn active_ai_temp_policies(&self) -> Vec<AiTempPolicyEntry> {
        self.ai_temp_policies
            .read()
            .expect("ai_temp_policies lock poisoned")
            .clone()
    }

    pub async fn refresh_ai_temp_policies(&self) -> Result<()> {
        let Some(store) = self.sqlite_store.as_ref() else {
            return Ok(());
        };
        let now = unix_timestamp();
        let _ = store.expire_ai_temp_policies(now).await?;
        let items = store.list_active_ai_temp_policies(now).await?;
        let mut guard = self
            .ai_temp_policies
            .write()
            .expect("ai_temp_policies lock poisoned");
        *guard = items;
        Ok(())
    }

    pub fn apply_ai_temp_policies_to_request(
        &self,
        request: &mut UnifiedHttpRequest,
    ) -> Option<InspectionResult> {
        let policies = self.active_ai_temp_policies();
        if policies.is_empty() {
            return None;
        }

        let host = request
            .get_header("host")
            .map(|value| {
                value
                    .split(':')
                    .next()
                    .unwrap_or(value)
                    .trim()
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        let route = request
            .uri
            .split('?')
            .next()
            .unwrap_or(&request.uri)
            .to_string();
        let client_ip = request
            .client_ip
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or_default()
            .to_string();
        let identity = ai_request_identity(request);

        let mut matched_hits = Vec::new();
        let mut route_scale_percent = 100u32;
        let mut host_scale_percent = 100u32;
        let mut extra_delay_ms = 0u64;
        let mut behavior_score_boost = 0u32;
        let mut force_watch = false;
        let mut force_challenge = false;
        let mut block_reason = None::<String>;

        for policy in policies {
            let matched =
                match_ai_temp_policy(&policy, &host, &route, &client_ip, identity.as_deref());
            let Some(matched) = matched else {
                continue;
            };
            matched_hits.push(AiTempPolicyHitRecord {
                id: policy.id,
                action: policy.action.clone(),
                scope_type: policy.scope_type.clone(),
                scope_value: policy.scope_value.clone(),
                matched_value: matched.matched_value,
                match_mode: matched.match_mode,
            });
            match policy.action.as_str() {
                "add_temp_block" => {
                    block_reason = Some(format!(
                        "AI temp policy blocked request: {} ({})",
                        policy.title, policy.rationale
                    ));
                    request.add_metadata(
                        "ai.temp_block_duration_secs".to_string(),
                        self.config_snapshot()
                            .integrations
                            .ai_audit
                            .temp_block_ttl_secs
                            .to_string(),
                    );
                }
                "increase_delay" => {
                    extra_delay_ms = extra_delay_ms
                        .max(parse_suggested_delay_ms(&policy.suggested_value).unwrap_or(250));
                }
                "increase_challenge" => force_challenge = true,
                "tighten_route_cc" => {
                    route_scale_percent = route_scale_percent
                        .min(parse_scale_percent(&policy.suggested_value).unwrap_or(80));
                }
                "tighten_host_cc" => {
                    host_scale_percent = host_scale_percent
                        .min(parse_scale_percent(&policy.suggested_value).unwrap_or(85));
                }
                "raise_identity_risk" => {
                    behavior_score_boost = behavior_score_boost.max(35);
                }
                "add_behavior_watch" => {
                    behavior_score_boost = behavior_score_boost.max(20);
                    force_watch = true;
                }
                _ => {}
            }
        }

        self.record_ai_temp_policy_hits(matched_hits);

        if let Some(reason) = block_reason {
            request.add_metadata("ai.policy.action".to_string(), "add_temp_block".to_string());
            request.add_metadata("l7.enforcement".to_string(), "drop".to_string());
            request.add_metadata("l7.drop_reason".to_string(), "ai_temp_block".to_string());
            request.add_metadata("l4.force_close".to_string(), "true".to_string());
            return Some(InspectionResult::drop_and_persist_ip(
                InspectionLayer::L7,
                reason,
            ));
        }

        if route_scale_percent < 100 {
            request.add_metadata(
                "ai.cc.route_threshold_scale_percent".to_string(),
                route_scale_percent.to_string(),
            );
        }
        if host_scale_percent < 100 {
            request.add_metadata(
                "ai.cc.host_threshold_scale_percent".to_string(),
                host_scale_percent.to_string(),
            );
        }
        if extra_delay_ms > 0 {
            request.add_metadata(
                "ai.cc.extra_delay_ms".to_string(),
                extra_delay_ms.to_string(),
            );
        }
        if force_challenge {
            request.add_metadata("ai.cc.force_challenge".to_string(), "true".to_string());
        }
        if behavior_score_boost > 0 {
            request.add_metadata(
                "ai.behavior.score_boost".to_string(),
                behavior_score_boost.to_string(),
            );
        }
        if force_watch {
            request.add_metadata("ai.behavior.force_watch".to_string(), "true".to_string());
        }

        None
    }

    fn record_ai_temp_policy_hits(&self, hits: Vec<AiTempPolicyHitRecord>) {
        if hits.is_empty() {
            return;
        }
        let Some(store) = self.sqlite_store.as_ref().cloned() else {
            return;
        };
        tokio::spawn(async move {
            let now = unix_timestamp();
            for hit in hits {
                let _ = store.record_ai_temp_policy_hit(&hit, now).await;
            }
        });
    }
}
