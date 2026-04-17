use super::types::AiAuditModelOutput;
use super::*;

pub(super) fn build_system_prompt() -> String {
    [
        "你是一个应用安全审计助手。",
        "只返回一个 JSON 对象，不要输出 markdown 代码块，也不要输出额外说明。",
        "JSON 顶层键必须且只能包含：risk_level, headline, executive_summary, findings, recommendations, suggested_local_rules。",
        "risk_level 必须是以下英文枚举之一：low, medium, high, critical。",
        "findings 数组项必须包含：key, severity, title, detail, evidence。",
        "recommendations 数组项必须包含：key, priority, title, action, rationale, action_type, rule_suggestion_key。",
        "action_type 必须是以下英文枚举之一：observe, tune_threshold, add_rule, investigate。",
        "suggested_local_rules 数组项必须包含：key, title, policy_type, layer, scope_type, scope_value, target, action, operator, suggested_value, ttl_secs, auto_apply, rationale。",
        "layer 必须是以下英文枚举之一：l4, l7。",
        "所有 JSON 键名、协议字段、枚举值、规则动作值保持英文，不能翻译。",
        "除上述键名和枚举值外，所有面向人的自然语言内容必须使用简体中文。",
        "这包括 headline、executive_summary、findings 的 title/detail/evidence、recommendations 的 title/action/rationale、suggested_local_rules 的 title/rationale。",
        "这是纯分析任务，绝不能声称模型直接拦截了流量。",
        "结论要保守：当摘要只支持怀疑时，不要写成确定结论。",
        "如果 data_quality.analysis_confidence 较低，应明确降低措辞强度，并优先建议人工复核。",
    ]
    .join(" ")
}

pub(super) fn build_user_prompt(
    summary: &AiAuditSummaryResponse,
    include_raw_event_samples: bool,
) -> anyhow::Result<String> {
    Ok(format!(
        "请分析下面的 WAF 审计摘要，并按照要求返回 JSON 对象。请注意：JSON 键名和枚举值保持英文，但所有说明性文本必须使用简体中文。\n摘要 JSON：\n{}",
        serde_json::to_string(&build_provider_input(summary, include_raw_event_samples))?
    ))
}

pub(super) fn build_localization_system_prompt() -> String {
    [
        "你是一个 JSON 本地化助手。",
        "你会收到一个 AI 审计结果 JSON。",
        "只做中文本地化，不做事实增删，不做字段增删，不做结构改写。",
        "只返回一个 JSON 对象，不要输出 markdown 代码块，也不要输出额外说明。",
        "所有 JSON 键名、协议字段、英文枚举值、策略动作值必须原样保留，不能翻译。",
        "将所有面向人的说明文本翻译为简体中文。",
        "这包括 headline、executive_summary、findings 的 title/detail/evidence、recommendations 的 title/action/rationale、suggested_local_rules 的 title/rationale。",
        "如果原文已经是简体中文，保持原样。",
    ]
    .join(" ")
}

pub(super) fn build_localization_user_prompt(
    output: &AiAuditModelOutput,
) -> anyhow::Result<String> {
    Ok(format!(
        "请把下面 JSON 中所有说明性文本转换为简体中文，键名和枚举值保持不变：\n{}",
        serde_json::to_string(output)?
    ))
}

pub(super) fn build_provider_input(
    summary: &AiAuditSummaryResponse,
    include_raw_event_samples: bool,
) -> serde_json::Value {
    serde_json::json!({
        "input_profile": build_input_profile(summary, include_raw_event_samples),
        "runtime_pressure_level": summary.runtime_pressure_level,
        "degraded_reasons": summary.degraded_reasons,
        "data_quality": summary.data_quality,
        "current": summary.current,
        "counters": summary.counters,
        "action_breakdown": summary.action_breakdown,
        "provider_breakdown": summary.provider_breakdown,
        "identity_states": summary.identity_states,
        "primary_signals": summary.primary_signals,
        "labels": summary.labels,
        "top_source_ips": summary.top_source_ips,
        "top_routes": summary.top_routes,
        "top_hosts": summary.top_hosts,
        "safeline_correlation": summary.safeline_correlation,
        "trend_windows": summary.trend_windows,
        "recent_policy_feedback": summary.recent_policy_feedback,
        "recent_events": if include_raw_event_samples {
            serde_json::to_value(&summary.recent_events).unwrap_or_else(|_| serde_json::Value::Array(Vec::new()))
        } else {
            serde_json::Value::Array(Vec::new())
        },
    })
}

pub(super) fn build_input_profile(
    summary: &AiAuditSummaryResponse,
    raw_samples_included: bool,
) -> AiAuditInputProfileResponse {
    AiAuditInputProfileResponse {
        source: "cc_behavior_joint_summary".to_string(),
        sampled_events: summary.sampled_events,
        included_recent_events: if raw_samples_included {
            summary.recent_events.len() as u32
        } else {
            0
        },
        raw_samples_included,
        recent_policy_feedback_count: summary.recent_policy_feedback.len() as u32,
    }
}
