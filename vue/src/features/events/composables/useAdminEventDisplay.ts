import type {
  SecurityEventItem,
  StoragePressureSummaryDetails,
} from '@/shared/types'

interface EventDisplayOptions {
  actionLabel: (action: string) => string
  formatTimestamp: (unix: number) => string
  openPreview: (title: string, content: string | null | undefined) => void
}

export function useAdminEventDisplay({
  actionLabel,
  formatTimestamp,
  openPreview,
}: EventDisplayOptions) {
  const safeLineActionMap: Record<string, string> = {
    '0': '检测',
    '1': '拦截',
  }

  const safeLineAttackTypeMap: Record<string, string> = {
    '7': '漏洞利用',
    '8': '代码注入',
    '10': '文件上传',
  }
  const REASON_PREVIEW_LIMIT = 72
  const PATH_PREVIEW_LIMIT = 48

  const getSafeLineAttackTypeCode = (event: SecurityEventItem) => {
    if (event.layer.toLowerCase() !== 'safeline') return null
    const matched = event.reason.match(/^safeline:([^:]+):/)
    return matched?.[1] ?? null
  }

  const eventActionLabel = (action: string) => {
    const normalized = action.trim().toLowerCase()
    if (normalized === 'summary') {
      return '摘要'
    }
    if (normalized in safeLineActionMap) {
      return safeLineActionMap[normalized]
    }
    if (['block', 'allow', 'alert', 'log'].includes(normalized)) {
      return actionLabel(normalized)
    }
    return `未知动作(${action})`
  }

  const eventActionBadgeType = (action: string) => {
    const normalized = action.trim().toLowerCase()
    if (normalized === '1' || normalized === 'block') return 'error'
    if (normalized === 'allow') return 'success'
    if (normalized === 'summary') return 'warning'
    if (normalized === '0' || normalized === 'alert' || normalized === 'log') {
      return 'warning'
    }
    return 'warning'
  }

  const shouldShowActionBadge = (action: string) =>
    action.trim().toLowerCase() !== 'respond'

  const eventAttackTypeLabel = (event: SecurityEventItem) => {
    const code = getSafeLineAttackTypeCode(event)
    if (!code) return ''
    return safeLineAttackTypeMap[code] || `未知类型(${code})`
  }

  const eventReasonLabel = (event: SecurityEventItem) => {
    if (event.layer.toLowerCase() !== 'safeline') return event.reason

    const attackTypeCode = getSafeLineAttackTypeCode(event)
    const attackTypeLabel = attackTypeCode
      ? safeLineAttackTypeMap[attackTypeCode]
      : ''
    const normalized = event.reason.replace(/^safeline:[^:]+:/, '').trim()

    if (attackTypeCode && normalized === `检测到 ${attackTypeCode} 攻击`) {
      return attackTypeLabel || normalized
    }

    return normalized || event.reason
  }

  const truncateText = (value: string, limit: number) =>
    value.length > limit ? `${value.slice(0, limit)}…` : value

  const eventReasonPreview = (event: SecurityEventItem) =>
    truncateText(eventReasonLabel(event), REASON_PREVIEW_LIMIT)

  const isReasonTruncated = (event: SecurityEventItem) =>
    eventReasonLabel(event).length > REASON_PREVIEW_LIMIT

  const eventPathText = (event: SecurityEventItem) =>
    `${event.http_method || '-'}${event.uri ? ` ${event.uri}` : ''}`

  const eventPathPreview = (event: SecurityEventItem) =>
    truncateText(eventPathText(event), PATH_PREVIEW_LIMIT)

  const isPathTruncated = (event: SecurityEventItem) =>
    eventPathText(event).length > PATH_PREVIEW_LIMIT

  const identityStateLabelMap: Record<string, string> = {
    trusted_cdn_forwarded: '可信 CDN',
    trusted_cdn_unresolved: 'CDN 未解析',
    direct_client: '直连客户端',
    spoofed_forward_header: '伪造头部',
  }

  const primarySignalLabelMap: Record<string, string> = {
    slow_attack: '慢速攻击',
    safeline: '雷池',
    rule_engine: '规则引擎',
  }

  const eventIdentityStateLabel = (event: SecurityEventItem) => {
    const value = event.decision_summary?.identity_state
    if (!value) return ''
    return identityStateLabelMap[value] || value
  }

  const eventPrimarySignalLabel = (event: SecurityEventItem) => {
    const value = event.decision_summary?.primary_signal
    if (!value) return ''
    return primarySignalLabelMap[value] || value
  }

  const eventLabelsPreview = (event: SecurityEventItem) =>
    (event.decision_summary?.labels || []).slice(0, 3)

  const parseStorageSummaryDetails = (
    event: SecurityEventItem,
  ): StoragePressureSummaryDetails | null => {
    if (event.action.toLowerCase() !== 'summary' || !event.details_json)
      return null
    try {
      const payload = JSON.parse(event.details_json) as {
        storage_pressure?: Partial<StoragePressureSummaryDetails>
      }
      const summary = payload.storage_pressure
      if (!summary || summary.mode !== 'aggregated') return null
      return {
        mode: String(summary.mode || 'aggregated'),
        action:
          typeof summary.action === 'string' && summary.action.trim()
            ? summary.action.trim()
            : null,
        original_reason:
          typeof summary.original_reason === 'string' &&
          summary.original_reason.trim()
            ? summary.original_reason.trim()
            : null,
        count: Number(summary.count || 0),
        source_scope:
          typeof summary.source_scope === 'string' &&
          summary.source_scope.trim()
            ? summary.source_scope.trim()
            : null,
        route:
          typeof summary.route === 'string' && summary.route.trim()
            ? summary.route.trim()
            : null,
        time_window_start:
          typeof summary.time_window_start === 'number'
            ? summary.time_window_start
            : null,
        time_window_end:
          typeof summary.time_window_end === 'number'
            ? summary.time_window_end
            : null,
        first_created_at:
          typeof summary.first_created_at === 'number'
            ? summary.first_created_at
            : null,
        last_created_at:
          typeof summary.last_created_at === 'number'
            ? summary.last_created_at
            : null,
      }
    } catch {
      return null
    }
  }

  const isStorageSummaryEvent = (event: SecurityEventItem) =>
    parseStorageSummaryDetails(event) !== null

  const storageSummaryScopeLabel = (event: SecurityEventItem) => {
    const details = parseStorageSummaryDetails(event)
    if (!details?.source_scope) return ''
    return details.source_scope === 'long_tail' ? '长尾汇总' : '热点摘要'
  }

  const storageSummaryCountLabel = (event: SecurityEventItem) => {
    const details = parseStorageSummaryDetails(event)
    if (!details || !details.count) return ''
    return `${details.count} 次`
  }

  const storageSummaryWindowLabel = (event: SecurityEventItem) => {
    const details = parseStorageSummaryDetails(event)
    if (!details?.time_window_start || !details?.time_window_end) return ''
    return `${formatTimestamp(details.time_window_start)} - ${formatTimestamp(details.time_window_end)}`
  }

  const storageSummaryRouteLabel = (event: SecurityEventItem) =>
    parseStorageSummaryDetails(event)?.route || ''

  const openStorageSummaryPreview = (event: SecurityEventItem) => {
    const details = parseStorageSummaryDetails(event)
    if (!details) return
    openPreview(
      '攻击摘要',
      JSON.stringify(
        {
          source_ip: event.source_ip,
          action: details.action,
          source_scope: details.source_scope,
          count: details.count,
          route: details.route,
          time_window_start: details.time_window_start,
          time_window_end: details.time_window_end,
          original_reason: details.original_reason,
          first_created_at: details.first_created_at,
          last_created_at: details.last_created_at,
        },
        null,
        2,
      ),
    )
  }

  const parseEventDetails = (event: SecurityEventItem) => {
    if (!event.details_json) return null
    try {
      return JSON.parse(event.details_json) as {
        client_identity?: Record<string, unknown>
        connect_target?: string
        host?: string
        sni?: string
        status?: number
        reason?: string | null
        stage?: string
        error?: string
      }
    } catch {
      return null
    }
  }

  const hasClientIdentityDebug = (event: SecurityEventItem) =>
    Boolean(parseEventDetails(event)?.client_identity) &&
    event.layer.toLowerCase() === 'l7'

  const hasUpstreamHttp2Debug = (event: SecurityEventItem) =>
    event.reason.startsWith('upstream http2 debug (') &&
    event.layer.toLowerCase() === 'l7'

  const openClientIdentityDebug = (event: SecurityEventItem) => {
    const details = parseEventDetails(event)
    const payload = details?.client_identity ?? details
    if (!payload) return
    openPreview('客户端身份调试', JSON.stringify(payload, null, 2))
  }

  const openUpstreamHttp2Debug = (event: SecurityEventItem) => {
    const details = parseEventDetails(event)
    if (!details) return
    openPreview('上游 HTTP/2 调试', JSON.stringify(details, null, 2))
  }

  return {
    safeLineActionMap,
    safeLineAttackTypeMap,
    REASON_PREVIEW_LIMIT,
    PATH_PREVIEW_LIMIT,
    getSafeLineAttackTypeCode,
    eventActionLabel,
    eventActionBadgeType,
    shouldShowActionBadge,
    eventAttackTypeLabel,
    eventReasonLabel,
    truncateText,
    eventReasonPreview,
    isReasonTruncated,
    eventPathText,
    eventPathPreview,
    isPathTruncated,
    identityStateLabelMap,
    primarySignalLabelMap,
    eventIdentityStateLabel,
    eventPrimarySignalLabel,
    eventLabelsPreview,
    parseStorageSummaryDetails,
    isStorageSummaryEvent,
    storageSummaryScopeLabel,
    storageSummaryCountLabel,
    storageSummaryWindowLabel,
    storageSummaryRouteLabel,
    openStorageSummaryPreview,
    parseEventDetails,
    hasClientIdentityDebug,
    hasUpstreamHttp2Debug,
    openClientIdentityDebug,
    openUpstreamHttp2Debug,
  }
}
