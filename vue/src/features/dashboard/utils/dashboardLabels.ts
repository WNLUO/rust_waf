export const l7ModeLabel = (mode?: string) => {
  const labels: Record<string, string> = {
    active: '主动',
    observe: '观察',
    off: '关闭',
  }
  return labels[mode || ''] || '关闭'
}

export const l4OverloadLabel = (level?: string) => {
  const labels: Record<string, string> = {
    normal: '正常',
    high: '偏高',
    critical: '严重',
  }
  return labels[level || ''] || '正常'
}

export const serverModeLabel = (mode?: string) => {
  const labels: Record<string, string> = {
    throughput: '吞吐优先',
    balanced: '均衡',
    conservative: '保守',
    survival: '生存',
  }
  return labels[mode || ''] || mode || '未知'
}

export const serverModeBadgeType = (mode?: string) => {
  switch (mode) {
    case 'throughput':
      return 'success' as const
    case 'balanced':
      return 'info' as const
    case 'conservative':
      return 'warning' as const
    case 'survival':
      return 'error' as const
    default:
      return 'muted' as const
  }
}

export const serverModeReasonLabel = (reason?: string) => {
  const labels: Record<string, string> = {
    large_capacity_or_low_pressure: '大容量或低压力',
    general_purpose_server: '通用服务器',
    small_or_busy_server: '小型或繁忙服务器',
    attack_or_queue_saturation: '攻击或队列饱和',
  }
  return labels[reason || ''] || reason || '未知原因'
}

export const controllerStateLabel = (state?: string) => {
  const labels: Record<string, string> = {
    active_bootstrap_pending: '主动预热',
    adjusted: '已调整',
    bootstrap_adjusted: '初始调整',
    cooldown: '冷却中',
    disabled: '已关闭',
    idle: '空闲',
    observe_only: '仅观察',
    observe_pending_adjust: '待调整',
    rollback: '已回滚',
    stable: '稳定',
    warming_up: '预热中',
  }
  return labels[state || ''] || '未知'
}

export const providerLabel = (value?: string) => {
  const labels: Record<string, string> = {
    local_rules: '本地规则',
    stub_model: '占位模型',
    openai_compatible: 'OpenAI兼容',
    xiaomi_mimo: '小米Mimo',
  }
  return labels[value || ''] || '未知'
}

export const confidenceLabel = (value?: string) => {
  const labels: Record<string, string> = {
    high: '高',
    medium: '中',
    low: '低',
  }
  return labels[value || ''] || '未知'
}

export const pressureLabel = (value?: string) => {
  const labels: Record<string, string> = {
    normal: '正常',
    elevated: '升高',
    high: '偏高',
    attack: '攻击',
  }
  return labels[value || ''] || '未知'
}

export const trendWindowLabel = (value?: string) => {
  const labels: Record<string, string> = {
    last_5m: '近5分钟',
    last_15m: '近15分钟',
    last_60m: '近60分钟',
  }
  return labels[value || ''] || value || '未知窗口'
}

export const aiTriggerReasonLabel = (value?: string | null) => {
  const labels: Record<string, string> = {
    adaptive_pressure: '运行压力升高',
    attack_mode: '攻击态势触发',
    auto_apply_disabled: '自动应用关闭',
    auto_defense_auto_apply_disabled: '自动防御未自动应用',
    data_quality_degraded: '数据质量下降',
    fallback_due: '兜底周期触发',
    force_local_rules_under_attack: '攻击态势本地兜底',
    hotspot_shift: '热点变化',
    identity_pressure: '身份解析压力',
    identity_resolution_pressure: '身份解析压力',
    local_rules_fallback: '本地规则兜底',
    manual_run: '手动运行',
    pressure_high: '运行压力升高',
    scheduled: '周期巡检',
    startup: '启动巡检',
  }
  const key = value || ''
  if (!key) return '暂无触发'
  return labels[key] || key.replace(/_/g, ' ')
}

export const aiActionLabel = (value?: string) => {
  const labels: Record<string, string> = {
    add_behavior_watch: '行为观察',
    add_temp_block: '临时封禁',
    increase_challenge: '增加挑战',
    increase_delay: '增加延迟',
    mark_trusted_temporarily: '临时信任',
    raise_identity_risk: '提高身份风险',
    reduce_friction: '降低摩擦',
    tighten_host_cc: '收紧Host CC',
    tighten_route_cc: '收紧路由CC',
    watch: '观察',
    watch_visitor: '观察访客',
  }
  return labels[value || ''] || value || '未知动作'
}

export const aiPolicyStatusLabel = (value?: string) => {
  const labels: Record<string, string> = {
    cold: '待命中',
    effective: '有效',
    needs_review: '需复核',
    observing: '观察中',
    watch: '观察',
  }
  return labels[value || ''] || value || '观察中'
}

export const aiScopeLabel = (value?: string) => {
  const labels: Record<string, string> = {
    client_ip: '来源IP',
    host: 'Host',
    identity: '身份',
    route: '路由',
    source_ip: '来源IP',
  }
  return labels[value || ''] || '范围'
}

const hasChineseText = (value?: string) => /[\u4e00-\u9fff]/.test(value || '')

export const aiPolicyTitle = (policy: {
  title: string
  action: string
  scope_type: string
  scope_value: string
}) => {
  if (hasChineseText(policy.title)) return policy.title
  const scopeValue = policy.scope_value ? ` ${policy.scope_value}` : ''
  return `${aiActionLabel(policy.action)} · ${aiScopeLabel(policy.scope_type)}${scopeValue}`
}

export const aiPolicyDetailLine = (policy: {
  title: string
  action: string
  scope_type: string
  scope_value: string
}) => {
  const title = aiPolicyTitle(policy)
  const action = aiActionLabel(policy.action)
  const scope = aiScopeLabel(policy.scope_type)
  const scopeValue = policy.scope_value || '全局范围'
  if (
    title.includes(action) &&
    title.includes(scope) &&
    (!policy.scope_value || title.includes(policy.scope_value))
  ) {
    return ''
  }
  return `${action} / ${scope} / ${scopeValue}`
}
