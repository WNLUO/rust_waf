use super::*;

pub(super) fn behavior_user_agent(request: &UnifiedHttpRequest) -> Option<String> {
    request
        .get_header("user-agent")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| compact_component("ua", value, MAX_BEHAVIOR_KEY_LEN))
}

pub(super) fn behavior_host(request: &UnifiedHttpRequest) -> String {
    let raw = request
        .get_header("host")
        .or_else(|| request.get_metadata("authority"))
        .map(String::as_str)
        .unwrap_or("-")
        .trim();
    if raw.is_empty() {
        return "-".to_string();
    }
    if let Ok(uri) = format!("http://{raw}").parse::<http::Uri>() {
        if let Some(authority) = uri.authority() {
            return compact_component(
                "host",
                &authority.host().to_ascii_lowercase(),
                MAX_BEHAVIOR_KEY_LEN,
            );
        }
    }
    let normalized = raw
        .trim_start_matches('[')
        .split(']')
        .next()
        .unwrap_or(raw)
        .split(':')
        .next()
        .unwrap_or(raw)
        .to_ascii_lowercase();
    compact_component("host", &normalized, MAX_BEHAVIOR_KEY_LEN)
}

pub(super) fn request_is_script_like_document(request: &UnifiedHttpRequest) -> bool {
    let ua = request
        .get_header("user-agent")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let accept = request
        .get_header("accept")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let accept_language_missing = request
        .get_header("accept-language")
        .map(|value| value.trim().is_empty())
        .unwrap_or(true);
    let sec_fetch_dest = request
        .get_header("sec-fetch-dest")
        .map(|value| value.to_ascii_lowercase());
    let sec_fetch_mode = request
        .get_header("sec-fetch-mode")
        .map(|value| value.to_ascii_lowercase());
    let browser_navigation = sec_fetch_dest.as_deref() == Some("document")
        || sec_fetch_mode.as_deref() == Some("navigate");
    let automation_ua = [
        "curl",
        "wget",
        "python",
        "go-http-client",
        "okhttp",
        "httpclient",
        "postman",
        "http_request",
    ]
    .iter()
    .any(|needle| ua.contains(needle));
    automation_ua
        || (!browser_navigation
            && (accept.is_empty() || accept == "*/*" || !accept.contains("text/html")))
        || (!browser_navigation && accept_language_missing && !accept.contains("text/html"))
}

pub(super) fn behavior_header_signature(request: &UnifiedHttpRequest) -> Option<String> {
    let fields = [
        "accept",
        "accept-language",
        "accept-encoding",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "x-requested-with",
    ];
    let signature = fields
        .iter()
        .map(|key| {
            request
                .get_header(key)
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "-".to_string())
        })
        .collect::<Vec<_>>()
        .join("|");
    (signature != "-|-|-|-|-|-|-")
        .then(|| compact_component("hdr", &signature, MAX_BEHAVIOR_KEY_LEN))
}

pub(super) fn select_behavior_assessment(
    identity_assessment: Option<BehaviorAssessment>,
    aggregate_assessment: Option<BehaviorAssessment>,
) -> Option<BehaviorAssessment> {
    let aggregate_assessment = aggregate_assessment
        .filter(distributed_assessment_is_actionable)
        .map(normalize_distributed_assessment_score);
    match (identity_assessment, aggregate_assessment) {
        (Some(identity), Some(aggregate)) if aggregate.score > identity.score => Some(aggregate),
        (Some(identity), _) => Some(identity),
        (None, Some(aggregate)) => Some(aggregate),
        (None, None) => None,
    }
}

fn distributed_assessment_is_actionable(assessment: &BehaviorAssessment) -> bool {
    assessment.score >= DELAY_SCORE
        && assessment.flags.iter().any(|flag| {
            matches!(
                *flag,
                "distributed_document_burst"
                    | "distributed_document_probe"
                    | "distributed_api_burst"
            ) || (assessment.identity.contains("|client:")
                && matches!(
                    *flag,
                    "single_source_document_loop" | "single_source_identity_rotation"
                ))
        })
}

fn normalize_distributed_assessment_score(
    mut assessment: BehaviorAssessment,
) -> BehaviorAssessment {
    let has_burst_flag = assessment.flags.iter().any(|flag| {
        matches!(
            *flag,
            "distributed_document_burst" | "distributed_api_burst"
        )
    });
    if !has_burst_flag {
        assessment.score = assessment.score.min(CHALLENGE_SCORE);
    }
    assessment
}
