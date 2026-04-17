import type { AiAuditSettingsPayload } from '@/shared/types'

export function createDefaultAiAuditSettings(): AiAuditSettingsPayload {
  return {
    enabled: false,
    provider: 'local_rules',
    model: '',
    base_url: '',
    api_key: '',
    timeout_ms: 15000,
    fallback_to_rules: true,
    event_sample_limit: 120,
    recent_event_limit: 12,
    include_raw_event_samples: false,
    auto_apply_temp_policies: true,
    temp_policy_ttl_secs: 900,
    temp_block_ttl_secs: 1800,
    auto_apply_min_confidence: 70,
    max_active_temp_policies: 24,
    allow_auto_temp_block: false,
    allow_auto_extend_effective_policies: true,
    auto_revoke_warmup_secs: 300,
    auto_audit_enabled: false,
    auto_audit_interval_secs: 300,
    auto_audit_cooldown_secs: 600,
    auto_audit_on_pressure_high: true,
    auto_audit_on_attack_mode: true,
    auto_audit_on_hotspot_shift: true,
    auto_audit_force_local_rules_under_attack: true,
  }
}

export function providerLabel(value: string | null | undefined) {
  switch ((value ?? '').toLowerCase()) {
    case 'local_rules':
      return '本地规则'
    case 'stub_model':
      return '占位模型'
    case 'openai_compatible':
      return 'OpenAI 兼容接口'
    case 'xiaomi_mimo':
      return '小米 Mimo'
    default:
      return value || '暂无'
  }
}

export function riskLevelLabel(value: string | null | undefined) {
  switch ((value ?? '').toLowerCase()) {
    case 'low':
      return '低'
    case 'medium':
      return '中'
    case 'high':
      return '高'
    case 'critical':
      return '紧急'
    default:
      return value || '未知'
  }
}

export function priorityLabel(value: string | null | undefined) {
  switch ((value ?? '').toLowerCase()) {
    case 'low':
      return '低'
    case 'medium':
      return '中'
    case 'high':
      return '高'
    case 'urgent':
      return '紧急'
    default:
      return value || '未知'
  }
}

export function actionTypeLabel(value: string | null | undefined) {
  switch ((value ?? '').toLowerCase()) {
    case 'observe':
      return '持续观察'
    case 'tune_threshold':
      return '调节阈值'
    case 'add_rule':
      return '添加规则'
    case 'investigate':
      return '人工排查'
    default:
      return value || '未知'
  }
}

export function feedbackStatusLabel(value: string | null | undefined) {
  switch ((value ?? '').toLowerCase()) {
    case 'confirmed':
      return '已确认'
    case 'false_positive':
      return '误报'
    case 'follow_up':
      return '待跟进'
    case 'unreviewed':
      return '未标记'
    default:
      return value || '暂无'
  }
}

export function analysisModeLabel(value: string | null | undefined) {
  switch ((value ?? '').toLowerCase()) {
    case 'analysis_only':
      return '仅分析'
    default:
      return value || '暂无'
  }
}

export function inputSourceLabel(value: string | null | undefined) {
  switch ((value ?? '').toLowerCase()) {
    case 'cc_behavior_joint_summary':
      return 'CC 行为联合摘要'
    default:
      return value || '暂无'
  }
}

export function createAiAuditFormatHelpers(
  formatNumber: (value: number) => string,
) {
  function formatPolicyEffectMap(values: Record<string, number>, limit = 3) {
    const entries = Object.entries(values)
      .sort((left, right) => right[1] - left[1])
      .slice(0, limit)
    if (!entries.length) return '暂无'
    return entries
      .map(([key, value]) => `${key}:${formatNumber(value)}`)
      .join(' · ')
  }

  function formatCountItems(
    items: Array<{ key: string; count: number }>,
    limit = 3,
  ) {
    if (!items.length) return '暂无'
    return items
      .slice(0, limit)
      .map((item) => `${item.key}:${formatNumber(item.count)}`)
      .join(' · ')
  }

  function formatDelta(value: number | null, suffix = '%') {
    if (value == null) return '暂无基线'
    const sign = value > 0 ? '+' : ''
    return `${sign}${formatNumber(value)}${suffix}`
  }

  function truncateMiddle(
    value: string | null | undefined,
    head = 16,
    tail = 10,
  ) {
    if (!value) return '暂无'
    if (value.length <= head + tail + 3) return value
    return `${value.slice(0, head)}...${value.slice(-tail)}`
  }

  function describeAutoTriggerReason(value: string | null | undefined) {
    if (!value) return '暂无'
    return value
      .split('+')
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean)
      .map((item) => {
        switch (item) {
          case 'pressure':
            return '高压力'
          case 'attack':
            return '攻击模式'
          case 'hotspot':
            return '热点变化'
          case 'auto':
            return '自动触发'
          case 'manual':
            return '手动执行'
          default:
            return item
        }
      })
      .join(' / ')
  }

  function triggerReasonFilterLabel(value: 'all' | 'auto' | 'manual' | 'pressure' | 'attack' | 'hotspot') {
    switch (value) {
      case 'auto':
        return '自动触发'
      case 'manual':
        return '手动执行'
      case 'pressure':
        return '高压力'
      case 'attack':
        return '攻击模式'
      case 'hotspot':
        return '热点变化'
      default:
        return '全部'
    }
  }

  return {
    formatPolicyEffectMap,
    formatCountItems,
    formatDelta,
    truncateMiddle,
    describeAutoTriggerReason,
    triggerReasonFilterLabel,
  }
}
