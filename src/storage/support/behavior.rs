use anyhow::Result;
use serde_json::Value;
use sqlx::SqlitePool;

#[derive(Debug)]
struct ParsedSecurityContext {
    identity: String,
    identity_kind: String,
    source_ip: String,
    site_domain: Option<String>,
    user_agent: Option<String>,
    behavior: Option<ParsedBehaviorPayload>,
}

#[derive(Debug)]
struct ParsedBehaviorPayload {
    action: Option<String>,
    score: i64,
    dominant_route: Option<String>,
    focused_document_route: Option<String>,
    focused_api_route: Option<String>,
    distinct_routes: i64,
    repeated_ratio: i64,
    document_repeated_ratio: i64,
    api_repeated_ratio: i64,
    document_requests: i64,
    api_requests: i64,
    non_document_requests: i64,
    interval_jitter_ms: Option<i64>,
    challenge_count_window: i64,
    session_span_secs: i64,
    flags_json: String,
}

pub(crate) async fn persist_behavior_intelligence(
    pool: &SqlitePool,
    event: &crate::storage::SecurityEventEntry,
) -> Result<()> {
    let Some(context) = parse_security_context(event) else {
        return Ok(());
    };

    upsert_fingerprint_profile(pool, event, &context).await?;
    if let Some(behavior) = context.behavior.as_ref() {
        upsert_behavior_session(pool, event, &context, behavior).await?;
        insert_behavior_event(pool, event, &context, behavior).await?;
    }
    Ok(())
}

fn parse_security_context(
    event: &crate::storage::SecurityEventEntry,
) -> Option<ParsedSecurityContext> {
    let details = event
        .details_json
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok());
    let identity = details
        .as_ref()
        .and_then(parse_behavior_identity)
        .or_else(|| {
            (event.provider.as_deref() == Some("browser_fingerprint"))
                .then(|| {
                    event
                        .provider_event_id
                        .as_deref()
                        .map(|value| format!("fp:{value}"))
                })
                .flatten()
        })?;
    let identity_kind = identity_kind(&identity).to_string();
    let source_ip = details
        .as_ref()
        .and_then(parse_client_identity_source_ip)
        .unwrap_or_else(|| event.source_ip.clone());
    let site_domain = event
        .provider_site_domain
        .clone()
        .or_else(|| details.as_ref().and_then(parse_client_identity_host));
    let user_agent = details.as_ref().and_then(parse_client_identity_user_agent);
    let behavior = details.as_ref().and_then(parse_behavior_payload);

    Some(ParsedSecurityContext {
        identity,
        identity_kind,
        source_ip,
        site_domain,
        user_agent,
        behavior,
    })
}

fn parse_behavior_identity(details: &Value) -> Option<String> {
    details
        .get("l7_behavior")
        .and_then(|value| value.get("identity"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_client_identity_source_ip(details: &Value) -> Option<String> {
    details
        .get("client_identity")
        .and_then(|value| value.get("resolved_client_ip"))
        .or_else(|| {
            details
                .get("client_identity")
                .and_then(|value| value.get("source_ip"))
        })
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_client_identity_host(details: &Value) -> Option<String> {
    parse_client_identity_header(details, "host")
}

fn parse_client_identity_user_agent(details: &Value) -> Option<String> {
    parse_client_identity_header(details, "user-agent")
}

fn parse_client_identity_header(details: &Value, name: &str) -> Option<String> {
    details
        .get("client_identity")
        .and_then(|value| value.get("headers"))
        .and_then(|value| value.as_array())
        .and_then(|headers| {
            headers.iter().find_map(|entry| {
                let pair = entry.as_array()?;
                let key = pair.first()?.as_str()?.trim();
                let value = pair.get(1)?.as_str()?.trim();
                (key.eq_ignore_ascii_case(name) && !value.is_empty()).then(|| value.to_string())
            })
        })
}

fn parse_behavior_payload(details: &Value) -> Option<ParsedBehaviorPayload> {
    let behavior = details.get("l7_behavior")?;
    let identity = behavior
        .get("identity")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if identity.is_empty() {
        return None;
    }
    Some(ParsedBehaviorPayload {
        action: parse_optional_text(behavior.get("action")),
        score: parse_i64_field(behavior.get("score")),
        dominant_route: parse_optional_text(behavior.get("dominant_route")),
        focused_document_route: parse_optional_text(behavior.get("focused_document_route")),
        focused_api_route: parse_optional_text(behavior.get("focused_api_route")),
        distinct_routes: parse_i64_field(behavior.get("distinct_routes")),
        repeated_ratio: parse_i64_field(behavior.get("repeated_ratio")),
        document_repeated_ratio: parse_i64_field(behavior.get("document_repeated_ratio")),
        api_repeated_ratio: parse_i64_field(behavior.get("api_repeated_ratio")),
        document_requests: parse_i64_field(behavior.get("document_requests")),
        api_requests: parse_i64_field(behavior.get("api_requests")),
        non_document_requests: parse_i64_field(behavior.get("non_document_requests")),
        interval_jitter_ms: parse_optional_i64(behavior.get("interval_jitter_ms")),
        challenge_count_window: parse_i64_field(behavior.get("challenge_count_window")),
        session_span_secs: parse_i64_field(behavior.get("session_span_secs")),
        flags_json: parse_flags_json(behavior.get("flags")),
    })
}

fn parse_optional_text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_i64_field(value: Option<&Value>) -> i64 {
    parse_optional_i64(value).unwrap_or_default()
}

fn parse_optional_i64(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(number)) => number.as_i64(),
        Some(Value::String(raw)) => raw.trim().parse::<i64>().ok(),
        _ => None,
    }
}

fn parse_flags_json(value: Option<&Value>) -> String {
    if let Some(raw) = value.and_then(Value::as_str) {
        let items = raw
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        return serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string());
    }
    "[]".to_string()
}

fn identity_kind(identity: &str) -> &'static str {
    if identity.starts_with("fp:") {
        "fingerprint"
    } else if identity.starts_with("pfp:") {
        "passive_fingerprint"
    } else if identity.starts_with("cookie:") {
        "cookie"
    } else if identity.starts_with("ipua:") {
        "ipua"
    } else {
        "other"
    }
}

fn session_key(identity: &str, site_domain: Option<&str>) -> String {
    format!("{}|{}", identity, site_domain.unwrap_or("*"))
}

async fn upsert_fingerprint_profile(
    pool: &SqlitePool,
    event: &crate::storage::SecurityEventEntry,
    context: &ParsedSecurityContext,
) -> Result<()> {
    let is_behavior_event = context.behavior.is_some();
    let is_challenge = context
        .behavior
        .as_ref()
        .and_then(|value| value.action.as_deref())
        .map(|value| value == "challenge")
        .unwrap_or(false);
    let is_block = context
        .behavior
        .as_ref()
        .and_then(|value| value.action.as_deref())
        .map(|value| value == "block")
        .unwrap_or(false);
    let latest_score = context.behavior.as_ref().map(|value| value.score);
    let max_score = latest_score.unwrap_or_default();
    let latest_action = context
        .behavior
        .as_ref()
        .and_then(|value| value.action.clone());

    sqlx::query(
        r#"
        INSERT INTO fingerprint_profiles (
            identity, identity_kind, source_ip, first_seen_at, last_seen_at,
            first_site_domain, last_site_domain, first_user_agent, last_user_agent,
            total_security_events, total_behavior_events, total_challenges, total_blocks,
            latest_score, max_score, latest_action, reputation_score, notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 0, '')
        ON CONFLICT(identity) DO UPDATE SET
            source_ip = excluded.source_ip,
            last_seen_at = excluded.last_seen_at,
            last_site_domain = COALESCE(excluded.last_site_domain, fingerprint_profiles.last_site_domain),
            last_user_agent = COALESCE(excluded.last_user_agent, fingerprint_profiles.last_user_agent),
            total_security_events = fingerprint_profiles.total_security_events + 1,
            total_behavior_events = fingerprint_profiles.total_behavior_events + excluded.total_behavior_events,
            total_challenges = fingerprint_profiles.total_challenges + excluded.total_challenges,
            total_blocks = fingerprint_profiles.total_blocks + excluded.total_blocks,
            latest_score = COALESCE(excluded.latest_score, fingerprint_profiles.latest_score),
            max_score = MAX(fingerprint_profiles.max_score, excluded.max_score),
            latest_action = COALESCE(excluded.latest_action, fingerprint_profiles.latest_action)
        "#,
    )
    .bind(&context.identity)
    .bind(&context.identity_kind)
    .bind(&context.source_ip)
    .bind(event.created_at)
    .bind(event.created_at)
    .bind(&context.site_domain)
    .bind(&context.site_domain)
    .bind(&context.user_agent)
    .bind(&context.user_agent)
    .bind(if is_behavior_event { 1 } else { 0 })
    .bind(if is_challenge { 1 } else { 0 })
    .bind(if is_block { 1 } else { 0 })
    .bind(latest_score)
    .bind(max_score)
    .bind(&latest_action)
    .execute(pool)
    .await?;
    Ok(())
}

async fn upsert_behavior_session(
    pool: &SqlitePool,
    event: &crate::storage::SecurityEventEntry,
    context: &ParsedSecurityContext,
    behavior: &ParsedBehaviorPayload,
) -> Result<()> {
    let key = session_key(&context.identity, context.site_domain.as_deref());
    let is_challenge = behavior.action.as_deref() == Some("challenge");
    let is_block = behavior.action.as_deref() == Some("block");
    sqlx::query(
        r#"
        INSERT INTO behavior_sessions (
            session_key, identity, source_ip, site_domain, opened_at, last_seen_at,
            event_count, challenge_count, block_count, latest_action, latest_uri, latest_reason,
            dominant_route, focused_document_route, focused_api_route, distinct_routes,
            repeated_ratio, document_repeated_ratio, api_repeated_ratio, document_requests,
            api_requests, non_document_requests, interval_jitter_ms, session_span_secs, flags_json
        )
        VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(session_key) DO UPDATE SET
            source_ip = excluded.source_ip,
            last_seen_at = excluded.last_seen_at,
            event_count = behavior_sessions.event_count + 1,
            challenge_count = behavior_sessions.challenge_count + excluded.challenge_count,
            block_count = behavior_sessions.block_count + excluded.block_count,
            latest_action = COALESCE(excluded.latest_action, behavior_sessions.latest_action),
            latest_uri = COALESCE(excluded.latest_uri, behavior_sessions.latest_uri),
            latest_reason = excluded.latest_reason,
            dominant_route = COALESCE(excluded.dominant_route, behavior_sessions.dominant_route),
            focused_document_route = COALESCE(excluded.focused_document_route, behavior_sessions.focused_document_route),
            focused_api_route = COALESCE(excluded.focused_api_route, behavior_sessions.focused_api_route),
            distinct_routes = MAX(behavior_sessions.distinct_routes, excluded.distinct_routes),
            repeated_ratio = MAX(behavior_sessions.repeated_ratio, excluded.repeated_ratio),
            document_repeated_ratio = MAX(behavior_sessions.document_repeated_ratio, excluded.document_repeated_ratio),
            api_repeated_ratio = MAX(behavior_sessions.api_repeated_ratio, excluded.api_repeated_ratio),
            document_requests = MAX(behavior_sessions.document_requests, excluded.document_requests),
            api_requests = MAX(behavior_sessions.api_requests, excluded.api_requests),
            non_document_requests = MAX(behavior_sessions.non_document_requests, excluded.non_document_requests),
            interval_jitter_ms = COALESCE(excluded.interval_jitter_ms, behavior_sessions.interval_jitter_ms),
            session_span_secs = MAX(behavior_sessions.session_span_secs, excluded.session_span_secs),
            flags_json = excluded.flags_json
        "#,
    )
    .bind(&key)
    .bind(&context.identity)
    .bind(&context.source_ip)
    .bind(&context.site_domain)
    .bind(event.created_at)
    .bind(event.created_at)
    .bind(if is_challenge { 1 } else { 0 })
    .bind(if is_block { 1 } else { 0 })
    .bind(&behavior.action)
    .bind(&event.uri)
    .bind(&event.reason)
    .bind(&behavior.dominant_route)
    .bind(&behavior.focused_document_route)
    .bind(&behavior.focused_api_route)
    .bind(behavior.distinct_routes)
    .bind(behavior.repeated_ratio)
    .bind(behavior.document_repeated_ratio)
    .bind(behavior.api_repeated_ratio)
    .bind(behavior.document_requests)
    .bind(behavior.api_requests)
    .bind(behavior.non_document_requests)
    .bind(behavior.interval_jitter_ms)
    .bind(behavior.session_span_secs)
    .bind(&behavior.flags_json)
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_behavior_event(
    pool: &SqlitePool,
    event: &crate::storage::SecurityEventEntry,
    context: &ParsedSecurityContext,
    behavior: &ParsedBehaviorPayload,
) -> Result<()> {
    let key = session_key(&context.identity, context.site_domain.as_deref());
    sqlx::query(
        r#"
        INSERT INTO behavior_events (
            security_event_id, identity, session_key, source_ip, site_domain, http_method,
            uri, action, reason, score, dominant_route, focused_document_route,
            focused_api_route, distinct_routes, repeated_ratio, document_repeated_ratio,
            api_repeated_ratio, document_requests, api_requests, non_document_requests,
            interval_jitter_ms, challenge_count_window, session_span_secs, flags_json, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(event.id)
    .bind(&context.identity)
    .bind(&key)
    .bind(&context.source_ip)
    .bind(&context.site_domain)
    .bind(&event.http_method)
    .bind(&event.uri)
    .bind(&behavior.action)
    .bind(&event.reason)
    .bind(behavior.score)
    .bind(&behavior.dominant_route)
    .bind(&behavior.focused_document_route)
    .bind(&behavior.focused_api_route)
    .bind(behavior.distinct_routes)
    .bind(behavior.repeated_ratio)
    .bind(behavior.document_repeated_ratio)
    .bind(behavior.api_repeated_ratio)
    .bind(behavior.document_requests)
    .bind(behavior.api_requests)
    .bind(behavior.non_document_requests)
    .bind(behavior.interval_jitter_ms)
    .bind(behavior.challenge_count_window)
    .bind(behavior.session_span_secs)
    .bind(&behavior.flags_json)
    .bind(event.created_at)
    .execute(pool)
    .await?;
    Ok(())
}
