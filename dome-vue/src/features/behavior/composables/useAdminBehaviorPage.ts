import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { fetchBehaviorProfiles, fetchSecurityEvents } from '@/shared/api/events'
import { fetchMetrics } from '@/shared/api/system'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import {
  useAdminRealtimeState,
  useAdminRealtimeTopic,
} from '@/shared/realtime/adminRealtime'
import type {
  BehaviorProfileItem,
  MetricsResponse,
  SecurityEventItem,
} from '@/shared/types'

export function useAdminBehaviorPage() {
  interface BehaviorDetails {
    action: string | null
    score: number
    identity: string | null
    dominant_route: string | null
    focused_document_route: string | null
    distinct_routes: number
    repeated_ratio: number
    document_repeated_ratio: number
    interval_jitter_ms: number | null
    document_requests: number
    non_document_requests: number
    challenge_count_window: number
    session_span_secs: number
    flags: string[]
  }

  interface BehaviorEventView {
    id: number
    sourceIp: string
    createdAt: number
    method: string
    uri: string
    reason: string
    action: 'challenge' | 'block' | 'delay' | 'other'
    score: number
    identity: string
    dominantRoute: string
    distinctRoutes: number
    repeatedRatio: number
    documentRepeatedRatio: number
    intervalJitterMs: number | null
    documentRequests: number
    nonDocumentRequests: number
    challengeCountWindow: number
    sessionSpanSecs: number
    flags: string[]
  }

  interface BehaviorProfileView {
    key: string
    identity: string
    sourceIp: string
    latestAction: BehaviorEventView['action']
    latestSeenAt: number
    latestUri: string
    dominantRoute: string
    eventCount: number
    challengeCount: number
    blockCount: number
    maxScore: number
    avgScore: number
    maxRepeatedRatio: number
    maxDocumentRepeatedRatio: number
    distinctRoutes: number
    intervalJitterMs: number | null
    documentRequests: number
    nonDocumentRequests: number
    challengeCountWindow: number
    focusedDocumentRoute: string
    focusedApiRoute: string
    apiRequests: number
    apiRepeatedRatio: number
    sessionSpanSecs: number
    flags: string[]
    blocked: boolean
    blockedAt: number | null
    blockedExpiresAt: number | null
    blockedReason: string
  }

  const MAX_EVENTS = 120

  const { formatNumber, formatTimestamp } = useFormatters()
  const realtimeState = useAdminRealtimeState()
  const loading = ref(true)
  const refreshing = ref(false)
  const error = ref('')
  const lastUpdated = ref<number | null>(null)
  const metrics = ref<MetricsResponse | null>(null)
  const behaviorEvents = ref<BehaviorEventView[]>([])
  const activeProfiles = ref<BehaviorProfileItem[]>([])
  const selectedProfileKey = ref('')
  let refreshTimer: number | null = null

  useFlashMessages({
    error,
    errorTitle: '行为观测',
    errorDuration: 5600,
  })

  function parseInteger(value: unknown): number {
    if (typeof value === 'number' && Number.isFinite(value)) return value
    if (typeof value === 'string') {
      const parsed = Number.parseInt(value, 10)
      if (Number.isFinite(parsed)) return parsed
    }
    return 0
  }

  function parseNullableInteger(value: unknown): number | null {
    if (value === null || value === undefined || value === '') return null
    const parsed = parseInteger(value)
    return Number.isFinite(parsed) ? parsed : null
  }

  function parseBehaviorDetails(
    event: SecurityEventItem,
  ): BehaviorDetails | null {
    if (!event.reason.toLowerCase().includes('l7 behavior guard')) {
      return null
    }

    if (!event.details_json) {
      return null
    }

    try {
      const payload = JSON.parse(event.details_json) as {
        l7_behavior?: Record<string, unknown>
      }
      const details = payload.l7_behavior
      if (!details) return null

      return {
        action:
          typeof details.action === 'string' && details.action.trim()
            ? details.action.trim()
            : null,
        score: parseInteger(details.score),
        identity:
          typeof details.identity === 'string' && details.identity.trim()
            ? details.identity.trim()
            : null,
        dominant_route:
          typeof details.dominant_route === 'string' &&
          details.dominant_route.trim()
            ? details.dominant_route.trim()
            : null,
        focused_document_route:
          typeof details.focused_document_route === 'string' &&
          details.focused_document_route.trim()
            ? details.focused_document_route.trim()
            : null,
        distinct_routes: parseInteger(details.distinct_routes),
        repeated_ratio: parseInteger(details.repeated_ratio),
        document_repeated_ratio: parseInteger(details.document_repeated_ratio),
        interval_jitter_ms: parseNullableInteger(details.interval_jitter_ms),
        document_requests: parseInteger(details.document_requests),
        non_document_requests: parseInteger(details.non_document_requests),
        challenge_count_window: parseInteger(details.challenge_count_window),
        session_span_secs: parseInteger(details.session_span_secs),
        flags:
          typeof details.flags === 'string' && details.flags.trim()
            ? details.flags
                .split(',')
                .map((item) => item.trim())
                .filter(Boolean)
            : [],
      }
    } catch {
      return null
    }
  }

  function normalizeBehaviorAction(
    action: string | null,
  ): BehaviorEventView['action'] {
    if (!action) return 'other'
    if (action === 'challenge') return 'challenge'
    if (action === 'block') return 'block'
    if (action.startsWith('delay:')) return 'delay'
    return 'other'
  }

  function toBehaviorEvent(event: SecurityEventItem): BehaviorEventView | null {
    const details = parseBehaviorDetails(event)
    if (!details) return null

    return {
      id: event.id,
      sourceIp: event.source_ip,
      createdAt: event.created_at,
      method: event.http_method || '-',
      uri: event.uri || '-',
      reason: event.reason,
      action: normalizeBehaviorAction(details.action),
      score: details.score,
      identity: details.identity || `ip:${event.source_ip}`,
      dominantRoute: details.dominant_route || '-',
      distinctRoutes: details.distinct_routes,
      repeatedRatio: details.repeated_ratio,
      documentRepeatedRatio: details.document_repeated_ratio,
      intervalJitterMs: details.interval_jitter_ms,
      documentRequests: details.document_requests,
      nonDocumentRequests: details.non_document_requests,
      challengeCountWindow: details.challenge_count_window,
      sessionSpanSecs: details.session_span_secs,
      flags: details.flags,
    }
  }

  const eventSummaryByIdentity = computed(() => {
    const summary = new Map<
      string,
      {
        eventCount: number
        challengeCount: number
        blockCount: number
        latestAction: BehaviorEventView['action']
        latestSeenAt: number
        latestUri: string
        sourceIp: string
      }
    >()
    for (const event of behaviorEvents.value) {
      const current = summary.get(event.identity)
      if (!current) {
        summary.set(event.identity, {
          eventCount: 1,
          challengeCount: event.action === 'challenge' ? 1 : 0,
          blockCount: event.action === 'block' ? 1 : 0,
          latestAction: event.action,
          latestSeenAt: event.createdAt,
          latestUri: event.uri,
          sourceIp: event.sourceIp,
        })
        continue
      }
      current.eventCount += 1
      if (event.action === 'challenge') current.challengeCount += 1
      if (event.action === 'block') current.blockCount += 1
      if (event.createdAt >= current.latestSeenAt) {
        current.latestSeenAt = event.createdAt
        current.latestAction = event.action
        current.latestUri = event.uri
        current.sourceIp = event.sourceIp
      }
    }
    return summary
  })

  const profiles = computed<BehaviorProfileView[]>(() => {
    return activeProfiles.value
      .map((profile) => {
        const eventSummary = eventSummaryByIdentity.value.get(profile.identity)
        return {
          key: profile.identity,
          identity: profile.identity,
          sourceIp: profile.source_ip || eventSummary?.sourceIp || '-',
          latestAction: profile.blocked
            ? 'block'
            : eventSummary?.latestAction || 'other',
          latestSeenAt: profile.latest_seen_at,
          latestUri: eventSummary?.latestUri || profile.latest_route,
          dominantRoute: profile.dominant_route || '-',
          eventCount: eventSummary?.eventCount || 0,
          challengeCount: eventSummary?.challengeCount || 0,
          blockCount: eventSummary?.blockCount || 0,
          maxScore: profile.score,
          avgScore: profile.score,
          maxRepeatedRatio: profile.repeated_ratio,
          maxDocumentRepeatedRatio: profile.document_repeated_ratio,
          distinctRoutes: profile.distinct_routes,
          intervalJitterMs: profile.interval_jitter_ms,
          documentRequests: profile.document_requests,
          apiRequests: profile.api_requests,
          nonDocumentRequests: profile.non_document_requests,
          apiRepeatedRatio: profile.api_repeated_ratio,
          challengeCountWindow: profile.challenge_count_window,
          focusedDocumentRoute:
            profile.focused_document_route || profile.dominant_route || '-',
          focusedApiRoute:
            profile.focused_api_route || profile.dominant_route || '-',
          sessionSpanSecs: profile.session_span_secs,
          flags: profile.flags,
          blocked: profile.blocked,
          blockedAt: profile.blocked_at,
          blockedExpiresAt: profile.blocked_expires_at,
          blockedReason: profile.blocked_reason || '-',
        }
      })
      .sort((left, right) => {
        if (right.maxScore !== left.maxScore)
          return right.maxScore - left.maxScore
        return right.latestSeenAt - left.latestSeenAt
      })
  })

  const selectedProfile = computed(
    () =>
      profiles.value.find((item) => item.key === selectedProfileKey.value) ||
      profiles.value[0] ||
      null,
  )

  const selectedProfileEvents = computed(() => {
    if (!selectedProfile.value) return []
    return behaviorEvents.value
      .filter((item) => item.identity === selectedProfile.value?.identity)
      .slice(0, 12)
  })

  const statusLabel = computed(() => {
    if (refreshing.value) return '正在同步行为观测...'
    if (realtimeState.connected && lastUpdated.value) {
      return `实时通道已连接：${new Intl.DateTimeFormat('zh-CN', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      }).format(new Date(lastUpdated.value))}`
    }
    if (realtimeState.connecting) return '实时通道连接中...'
    if (lastUpdated.value) {
      return `上次刷新：${new Intl.DateTimeFormat('zh-CN', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      }).format(new Date(lastUpdated.value))}`
    }
    return '等待首次同步'
  })

  function actionBadgeType(action: BehaviorEventView['action']) {
    if (action === 'block') return 'error' as const
    if (action === 'challenge') return 'warning' as const
    if (action === 'delay') return 'info' as const
    return 'muted' as const
  }

  function actionLabel(action: BehaviorEventView['action']) {
    if (action === 'block') return '已封禁'
    if (action === 'challenge') return '已挑战'
    if (action === 'delay') return '已延迟'
    return '已记录'
  }

  function currentStateType(profile: BehaviorProfileView) {
    if (profile.blocked) return 'error' as const
    if (profile.maxScore >= 60) return 'warning' as const
    if (profile.maxScore >= 20) return 'info' as const
    return 'success' as const
  }

  function currentStateLabel(profile: BehaviorProfileView) {
    if (profile.blocked) return '当前封禁中'
    if (profile.maxScore >= 60) return '当前高风险'
    if (profile.maxScore >= 20) return '当前观察中'
    return '当前正常'
  }

  function mergeBehaviorEvent(event: BehaviorEventView) {
    const merged = [event, ...behaviorEvents.value].filter(
      (item, index, items) =>
        items.findIndex((candidate) => candidate.id === item.id) === index,
    )
    behaviorEvents.value = merged
      .sort((left, right) => right.createdAt - left.createdAt)
      .slice(0, MAX_EVENTS)
    if (!selectedProfileKey.value) {
      selectedProfileKey.value = event.identity
    }
  }

  async function loadPage(showLoader = false) {
    if (showLoader) loading.value = true
    refreshing.value = true
    try {
      const [metricsPayload, profilesPayload, eventsPayload] =
        await Promise.all([
          fetchMetrics(),
          fetchBehaviorProfiles(),
          fetchSecurityEvents({
            limit: MAX_EVENTS,
            offset: 0,
            layer: 'L7',
            action: 'respond',
            sort_by: 'created_at',
            sort_direction: 'desc',
          }),
        ])
      metrics.value = metricsPayload
      activeProfiles.value = profilesPayload.profiles
      behaviorEvents.value = eventsPayload.events
        .map(toBehaviorEvent)
        .filter((item): item is BehaviorEventView => item !== null)
        .sort((left, right) => right.createdAt - left.createdAt)
      if (
        !selectedProfileKey.value ||
        !activeProfiles.value.some(
          (item) => item.identity === selectedProfileKey.value,
        )
      ) {
        selectedProfileKey.value = activeProfiles.value[0]?.identity || ''
      }
      lastUpdated.value = Date.now()
    } catch (err) {
      error.value = err instanceof Error ? err.message : '加载行为观测失败'
    } finally {
      loading.value = false
      refreshing.value = false
    }
  }

  useAdminRealtimeTopic<MetricsResponse>('metrics', (payload) => {
    metrics.value = payload
    lastUpdated.value = Date.now()
  })

  useAdminRealtimeTopic<SecurityEventItem>(
    'security_event_delta',
    (payload) => {
      const event = toBehaviorEvent(payload)
      if (!event) return
      mergeBehaviorEvent(event)
      lastUpdated.value = Date.now()
    },
  )

  useAdminRealtimeTopic<{ events: SecurityEventItem[] }>(
    'recent_events',
    (payload) => {
      const incoming = payload.events
        .map(toBehaviorEvent)
        .filter((item): item is BehaviorEventView => item !== null)
      if (!incoming.length) return
      for (const event of incoming) {
        mergeBehaviorEvent(event)
      }
      lastUpdated.value = Date.now()
    },
  )

  onMounted(() => {
    loadPage(true)
    refreshTimer = window.setInterval(() => {
      void loadPage()
    }, 5000)
  })

  onBeforeUnmount(() => {
    if (refreshTimer !== null) {
      window.clearInterval(refreshTimer)
      refreshTimer = null
    }
  })

  return {
    MAX_EVENTS,
    formatNumber,
    formatTimestamp,
    realtimeState,
    loading,
    refreshing,
    error,
    lastUpdated,
    metrics,
    behaviorEvents,
    activeProfiles,
    selectedProfileKey,
    parseInteger,
    parseNullableInteger,
    parseBehaviorDetails,
    normalizeBehaviorAction,
    toBehaviorEvent,
    eventSummaryByIdentity,
    profiles,
    selectedProfile,
    selectedProfileEvents,
    statusLabel,
    actionBadgeType,
    actionLabel,
    currentStateType,
    currentStateLabel,
    mergeBehaviorEvent,
    loadPage,
  }
}
