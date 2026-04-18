use super::*;

#[derive(Debug, Clone)]
pub(super) struct AggregateEnforcement {
    pub(super) identity: String,
    pub(super) action: AggregateEnforcementAction,
    pub(super) score: u32,
    pub(super) flags: Vec<String>,
    pub(super) expires_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AggregateEnforcementAction {
    Challenge,
    Block,
}

impl AggregateEnforcementAction {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Challenge => "aggregate_challenge",
            Self::Block => "aggregate_block",
        }
    }
}
pub(super) fn behavior_aggregate_keys(
    request: &UnifiedHttpRequest,
    route: &str,
    kind: RequestKind,
) -> Vec<(String, String)> {
    if matches!(kind, RequestKind::Static) {
        return Vec::new();
    }
    let host = behavior_host(request);
    let mut keys = vec![(
        format!("site:{host}|route:{route}|kind:{}", kind.as_str()),
        route.to_string(),
    )];
    let client_ip = request
        .client_ip
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| compact_component("client", value, MAX_BEHAVIOR_KEY_LEN));
    if let Some(client_ip) = client_ip.as_ref() {
        keys.push((
            format!(
                "site:{host}|client:{client_ip}|route:{route}|kind:{}",
                kind.as_str()
            ),
            route.to_string(),
        ));
    }
    if let Some(family) = route_family(&request.uri, route) {
        keys.push((
            format!("site:{host}|family:{family}|kind:{}", kind.as_str()),
            format!("family:{family}"),
        ));
        if let Some(client_ip) = client_ip.as_ref() {
            keys.push((
                format!(
                    "site:{host}|client:{client_ip}|family:{family}|kind:{}",
                    kind.as_str()
                ),
                format!("family:{family}"),
            ));
        }
    }
    keys
}
fn assessment_is_aggregate(identity: &str) -> bool {
    identity.starts_with("site:")
        || identity.starts_with("aggregate:")
        || identity.starts_with("__overflow__:behavior-aggregate")
}

pub(super) fn assessment_allows_aggregate_enforcement(assessment: &BehaviorAssessment) -> bool {
    assessment_is_aggregate(&assessment.identity)
        && assessment.flags.iter().any(|flag| {
            matches!(
                *flag,
                "distributed_document_burst"
                    | "distributed_document_probe"
                    | "distributed_api_burst"
            )
        })
}

pub(super) fn aggregate_enforcement_key(identity: &str) -> String {
    compact_component("aggregate-enforcement", identity, MAX_BEHAVIOR_KEY_LEN)
}
