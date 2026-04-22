import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import {
  fetchAiAutomationOverview,
  fetchTrafficMap,
} from '@/shared/api/dashboard'
import { fetchBlockedIps, fetchSecurityEvents } from '@/shared/api/events'
import { fetchL4Config, fetchL4Stats } from '@/shared/api/l4'
import { fetchL7Config, fetchL7Stats } from '@/shared/api/l7'
import { fetchRulesList } from '@/shared/api/rules'
import { fetchHealth, fetchMetrics } from '@/shared/api/system'
import type {
  BlockedIpsResponse,
  BlockedIpItem,
  DashboardPayload,
  L4ConfigPayload,
  L4StatsPayload,
  L7ConfigPayload,
  L7StatsPayload,
  MetricsResponse,
  SecurityEventItem,
  AiAutomationOverviewResponse,
  TrafficEventDelta,
  SecurityEventsResponse,
  TrafficMapResponse,
} from '@/shared/types'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import {
  useAdminRealtimeState,
  useAdminRealtimeTopic,
} from '@/shared/realtime/adminRealtime'

type AttackTimelineCounterKey =
  | 'proxy_successes'
  | 'proxy_failures'
  | 'l7_cc_fast_path_blocks'
  | 'l7_cc_hot_cache_hits'
  | 'l7_cc_fast_path_no_decisions'
  | 'l7_cc_verified_passes'
  | 'trusted_proxy_l4_degrade_actions'
  | 'blocked_l7'

const DASHBOARD_REFRESH_INTERVAL_MS = 5_000
const TRAFFIC_MAP_REFRESH_INTERVAL_MS = 10_000

export function useAdminDashboardPage() {
  const dashboard = ref<DashboardPayload | null>(null)
  const trafficMap = ref<TrafficMapResponse | null>(null)
  const aiAutomation = ref<AiAutomationOverviewResponse | null>(null)
  const trafficEvents = ref<TrafficEventDelta[]>([])
  const l4Stats = ref<L4StatsPayload | null>(null)
  const l4Config = ref<L4ConfigPayload | null>(null)
  const l7Stats = ref<L7StatsPayload | null>(null)
  const l7Config = ref<L7ConfigPayload | null>(null)
  const loading = ref(true)
  const refreshing = ref(false)
  const error = ref('')
  const lastUpdated = ref<number | null>(null)
  const lastTotalPackets = ref<number | null>(null)
  const lastBlockedPackets = ref<number | null>(null)
  const lastBlockedDelta = ref<number | null>(null)
  const blockedPeriodDelta = ref(0)
  const lastLatencyMicros = ref<number | null>(null)
  const lastProxySuccessRate = ref<number | null>(null)
  const realtimeState = useAdminRealtimeState()
  let dashboardRefreshTimer: number | null = null
  let trafficMapRefreshTimer: number | null = null

  useFlashMessages({
    error,
    errorTitle: '控制台',
    errorDuration: 5600,
  })

  const metricsHistory = reactive({
    totalPackets: [] as number[],
    latency: [] as number[],
  })
  const metricTrends = reactive({
    blocked: 'neutral' as 'up' | 'down' | 'neutral',
    latency: 'neutral' as 'up' | 'down' | 'neutral',
    successRate: 'neutral' as 'up' | 'down' | 'neutral',
  })
  const networkHistory = reactive({
    timestamps: [] as number[],
    rx: [] as number[],
    tx: [] as number[],
  })
  const attackTimeline = reactive({
    timestamps: [] as number[],
    proxySuccesses: [] as number[],
    proxyFailures: [] as number[],
    fastPathBlocks: [] as number[],
    hotCacheHits: [] as number[],
    noDecisions: [] as number[],
    verifiedPasses: [] as number[],
    l4DegradeActions: [] as number[],
    blockedL7: [] as number[],
    pressureLevels: [] as string[],
    defenseDepths: [] as string[],
  })
  const lastAttackCounters = ref<Record<
    AttackTimelineCounterKey,
    number
  > | null>(null)

  const pushHistory = (key: keyof typeof metricsHistory, value: number) => {
    const series = metricsHistory[key]
    series.push(Number.isFinite(value) ? value : 0)
    if (series.length > 12) {
      series.shift()
    }
  }
  const pushNetworkHistory = (metrics: MetricsResponse) => {
    const now = Date.now()
    networkHistory.timestamps.push(now)
    networkHistory.rx.push(metrics.system.network_rx_bytes_per_sec || 0)
    networkHistory.tx.push(metrics.system.network_tx_bytes_per_sec || 0)
    if (networkHistory.timestamps.length > 60) {
      networkHistory.timestamps.shift()
      networkHistory.rx.shift()
      networkHistory.tx.shift()
    }
  }
  const pushAttackTimeline = (metrics: MetricsResponse) => {
    const counters: Record<AttackTimelineCounterKey, number> = {
      proxy_successes: metrics.proxy_successes || 0,
      proxy_failures: metrics.proxy_failures || 0,
      l7_cc_fast_path_blocks: metrics.l7_cc_fast_path_blocks || 0,
      l7_cc_hot_cache_hits: metrics.l7_cc_hot_cache_hits || 0,
      l7_cc_fast_path_no_decisions: metrics.l7_cc_fast_path_no_decisions || 0,
      l7_cc_verified_passes: metrics.l7_cc_verified_passes || 0,
      trusted_proxy_l4_degrade_actions:
        metrics.trusted_proxy_l4_degrade_actions || 0,
      blocked_l7: metrics.blocked_l7 || 0,
    }
    const previous = lastAttackCounters.value
    const delta = (key: AttackTimelineCounterKey) =>
      previous === null ? 0 : Math.max(0, counters[key] - previous[key])

    attackTimeline.timestamps.push(Date.now())
    attackTimeline.proxySuccesses.push(delta('proxy_successes'))
    attackTimeline.proxyFailures.push(delta('proxy_failures'))
    attackTimeline.fastPathBlocks.push(delta('l7_cc_fast_path_blocks'))
    attackTimeline.hotCacheHits.push(delta('l7_cc_hot_cache_hits'))
    attackTimeline.noDecisions.push(delta('l7_cc_fast_path_no_decisions'))
    attackTimeline.verifiedPasses.push(delta('l7_cc_verified_passes'))
    attackTimeline.l4DegradeActions.push(
      delta('trusted_proxy_l4_degrade_actions'),
    )
    attackTimeline.blockedL7.push(delta('blocked_l7'))
    attackTimeline.pressureLevels.push(
      metrics.runtime_pressure_level || 'normal',
    )
    attackTimeline.defenseDepths.push(
      metrics.runtime_defense_depth || 'unknown',
    )

    if (attackTimeline.timestamps.length > 90) {
      attackTimeline.timestamps.shift()
      attackTimeline.proxySuccesses.shift()
      attackTimeline.proxyFailures.shift()
      attackTimeline.fastPathBlocks.shift()
      attackTimeline.hotCacheHits.shift()
      attackTimeline.noDecisions.shift()
      attackTimeline.verifiedPasses.shift()
      attackTimeline.l4DegradeActions.shift()
      attackTimeline.blockedL7.shift()
      attackTimeline.pressureLevels.shift()
      attackTimeline.defenseDepths.shift()
    }

    lastAttackCounters.value = counters
  }

  const trendFromDiff = (diff: number, threshold = 0) => {
    if (diff > threshold) return 'up' as const
    if (diff < -threshold) return 'down' as const
    return 'neutral' as const
  }

  const { formatBytes, formatNumber, formatLatency } = useFormatters()

  const emptyEventsResponse = (): SecurityEventsResponse => ({
    total: 0,
    limit: 0,
    offset: 0,
    events: [],
  })

  const emptyBlockedResponse = (): BlockedIpsResponse => ({
    total: 0,
    limit: 0,
    offset: 0,
    blocked_ips: [],
  })

  const successRate = computed(() => {
    const metrics = dashboard.value?.metrics
    if (!metrics) return '暂无'
    const total = metrics.proxy_successes + metrics.proxy_failures
    if (total === 0) return '暂无'
    return `${((metrics.proxy_successes / total) * 100).toFixed(1)}%`
  })

  const requestStatus = computed(() => {
    if (refreshing.value) return '正在同步数据...'
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
    return '等待首次同步，当前为手动刷新'
  })

  const autoSlo = computed(
    () =>
      l7Config.value?.auto_tuning.slo ?? {
        tls_handshake_timeout_rate_percent: 0.3,
        bucket_reject_rate_percent: 0.5,
        p95_proxy_latency_ms: 800,
      },
  )

  const adaptiveRuntime = computed(
    () =>
      l7Config.value?.adaptive_runtime ??
      l4Config.value?.adaptive_runtime ??
      null,
  )
  const adaptiveManaged = computed(
    () =>
      l7Config.value?.adaptive_managed_fields ||
      l4Config.value?.adaptive_managed_fields ||
      false,
  )
  const adaptivePressureType = computed(() => {
    const pressure = adaptiveRuntime.value?.system_pressure ?? 'normal'
    if (pressure === 'attack') return 'error' as const
    if (pressure === 'high') return 'warning' as const
    if (pressure === 'elevated') return 'info' as const
    return 'success' as const
  })
  const runtimePressureType = computed(() => {
    const pressure = dashboard.value?.metrics.runtime_pressure_level ?? 'normal'
    if (pressure === 'attack') return 'error' as const
    if (pressure === 'high') return 'warning' as const
    if (pressure === 'elevated') return 'info' as const
    return 'success' as const
  })
  const storageInsights = computed(
    () =>
      dashboard.value?.metrics.storage_attack_insights ?? {
        active_bucket_count: 0,
        active_event_count: 0,
        long_tail_bucket_count: 0,
        long_tail_event_count: 0,
        hotspot_sources: [],
      },
  )
  const storageDegradedReasons = computed(
    () => dashboard.value?.metrics.storage_degraded_reasons ?? [],
  )
  const storageInsightType = computed(() => {
    if ((storageInsights.value.long_tail_event_count || 0) > 0)
      return 'warning' as const
    if ((storageInsights.value.active_bucket_count || 0) > 0)
      return 'info' as const
    return 'muted' as const
  })
  const formatShortTime = (unix: number) =>
    new Intl.DateTimeFormat('zh-CN', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).format(new Date(unix * 1000))
  const hotspotEventsRoute = (
    sourceIp: string,
    _route: string | null,
    timeWindowStart: number,
    timeWindowEnd: number,
  ) => ({
    name: 'admin-events',
    query: {
      action: 'summary',
      source_ip: sourceIp,
      created_from: String(timeWindowStart),
      created_to: String(timeWindowEnd),
    },
  })
  const summaryEventsRoute = {
    name: 'admin-events',
    query: {
      action: 'summary',
    },
  }

  const calcAutoState = (observed: number, target: number) => {
    if (!Number.isFinite(observed) || !Number.isFinite(target) || target <= 0) {
      return 'muted' as const
    }
    const ratio = observed / target
    if (ratio <= 1) return 'success' as const
    if (ratio <= 1.5) return 'warning' as const
    return 'error' as const
  }

  const autoStateStyles: Record<
    'success' | 'warning' | 'error' | 'muted',
    string
  > = {
    success: 'text-emerald-700 bg-emerald-50 border-emerald-200',
    warning: 'text-amber-700 bg-amber-50 border-amber-200',
    error: 'text-red-700 bg-red-50 border-red-200',
    muted: 'text-slate-600 bg-slate-50 border-slate-200',
  }

  const tlsTimeoutState = computed(() =>
    calcAutoState(
      l7Stats.value?.auto_tuning
        .last_observed_tls_handshake_timeout_rate_percent ?? 0,
      autoSlo.value.tls_handshake_timeout_rate_percent,
    ),
  )
  const bucketRejectState = computed(() =>
    calcAutoState(
      l7Stats.value?.auto_tuning.last_observed_bucket_reject_rate_percent ?? 0,
      autoSlo.value.bucket_reject_rate_percent,
    ),
  )
  const latencyState = computed(() =>
    calcAutoState(
      l7Stats.value?.auto_tuning.last_observed_avg_proxy_latency_ms ?? 0,
      autoSlo.value.p95_proxy_latency_ms,
    ),
  )

  const applyMetrics = (metrics: MetricsResponse) => {
    if (!dashboard.value) return
    dashboard.value.metrics = metrics
    const packetDelta =
      lastTotalPackets.value === null
        ? 0
        : Math.max(0, metrics.total_packets - lastTotalPackets.value)
    lastTotalPackets.value = metrics.total_packets
    pushHistory('totalPackets', packetDelta)
    const blockedDelta =
      lastBlockedPackets.value === null
        ? 0
        : Math.max(0, metrics.blocked_packets - lastBlockedPackets.value)
    if (lastBlockedDelta.value !== null) {
      metricTrends.blocked = trendFromDiff(
        blockedDelta - lastBlockedDelta.value,
      )
    }
    lastBlockedPackets.value = metrics.blocked_packets
    lastBlockedDelta.value = blockedDelta
    blockedPeriodDelta.value = blockedDelta
    if (lastLatencyMicros.value !== null) {
      metricTrends.latency = trendFromDiff(
        metrics.average_proxy_latency_micros - lastLatencyMicros.value,
        1_000,
      )
    }
    lastLatencyMicros.value = metrics.average_proxy_latency_micros
    const proxyTotal = metrics.proxy_successes + metrics.proxy_failures
    const proxySuccessRate = proxyTotal
      ? (metrics.proxy_successes / proxyTotal) * 100
      : 0
    if (lastProxySuccessRate.value !== null) {
      metricTrends.successRate = trendFromDiff(
        proxySuccessRate - lastProxySuccessRate.value,
        0.1,
      )
    }
    lastProxySuccessRate.value = proxySuccessRate
    pushHistory('latency', metrics.average_proxy_latency_micros)
    pushNetworkHistory(metrics)
    pushAttackTimeline(metrics)
    lastUpdated.value = Date.now()
  }

  useAdminRealtimeTopic<MetricsResponse>('metrics', (payload) => {
    applyMetrics(payload)
  })

  useAdminRealtimeTopic<L4StatsPayload>('l4_stats', (payload) => {
    l4Stats.value = payload
    lastUpdated.value = Date.now()
  })

  useAdminRealtimeTopic<L7StatsPayload>('l7_stats', (payload) => {
    l7Stats.value = payload
    lastUpdated.value = Date.now()
  })

  useAdminRealtimeTopic<SecurityEventsResponse>('recent_events', (payload) => {
    if (!dashboard.value) return
    dashboard.value.events = payload
    lastUpdated.value = Date.now()
  })

  useAdminRealtimeTopic<BlockedIpsResponse>('recent_blocked_ips', (payload) => {
    if (!dashboard.value) return
    dashboard.value.blockedIps = payload
    lastUpdated.value = Date.now()
  })

  useAdminRealtimeTopic<SecurityEventItem>(
    'security_event_delta',
    (payload) => {
      if (!dashboard.value) return
      const events = [payload, ...dashboard.value.events.events].filter(
        (event, index, items) =>
          items.findIndex((item) => item.id === event.id) === index,
      )
      dashboard.value.events = {
        ...dashboard.value.events,
        total: dashboard.value.events.total + 1,
        events: events.slice(0, 8),
      }
      lastUpdated.value = Date.now()
    },
  )

  useAdminRealtimeTopic<BlockedIpItem>('blocked_ip_upsert', (payload) => {
    if (!dashboard.value) return
    const blockedIps = [
      payload,
      ...dashboard.value.blockedIps.blocked_ips,
    ].filter(
      (item, index, items) =>
        items.findIndex((candidate) => candidate.id === item.id) === index,
    )
    dashboard.value.blockedIps = {
      ...dashboard.value.blockedIps,
      total: dashboard.value.blockedIps.total + 1,
      blocked_ips: blockedIps.slice(0, 8),
    }
    lastUpdated.value = Date.now()
  })

  useAdminRealtimeTopic<{ id: number }>('blocked_ip_deleted', ({ id }) => {
    if (!dashboard.value) return
    const blockedIps = dashboard.value.blockedIps.blocked_ips.filter(
      (item) => item.id !== id,
    )
    dashboard.value.blockedIps = {
      ...dashboard.value.blockedIps,
      total: Math.max(0, dashboard.value.blockedIps.total - 1),
      blocked_ips: blockedIps,
    }
    lastUpdated.value = Date.now()
  })

  useAdminRealtimeTopic<TrafficMapResponse>('traffic_map', (payload) => {
    trafficMap.value = payload
  })

  useAdminRealtimeTopic<TrafficEventDelta>('traffic_event_delta', (payload) => {
    trafficEvents.value = [...trafficEvents.value, payload].slice(-48)
  })

  const fetchData = async (showLoader = false) => {
    if (showLoader) loading.value = true
    refreshing.value = true
    try {
      const [
        health,
        metrics,
        rules,
        events,
        blockedIps,
        l4StatsPayload,
        l4ConfigPayload,
        l7StatsPayload,
        l7ConfigPayload,
        aiAutomationPayload,
      ] = await Promise.all([
        fetchHealth(),
        fetchMetrics(),
        fetchRulesList(),
        fetchSecurityEvents({
          limit: 8,
          sort_direction: 'desc',
          sort_by: 'created_at',
        }),
        fetchBlockedIps({
          limit: 8,
          active_only: true,
          sort_direction: 'desc',
          sort_by: 'blocked_at',
        }),
        fetchL4Stats(),
        fetchL4Config(),
        fetchL7Stats(),
        fetchL7Config(),
        fetchAiAutomationOverview(),
      ])

      dashboard.value = {
        health,
        metrics,
        rules,
        events: events || emptyEventsResponse(),
        blockedIps: blockedIps || emptyBlockedResponse(),
      }

      applyMetrics(metrics)
      l4Stats.value = l4StatsPayload
      l4Config.value = l4ConfigPayload
      l7Stats.value = l7StatsPayload
      l7Config.value = l7ConfigPayload
      aiAutomation.value = aiAutomationPayload
      error.value = ''
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取控制台数据失败'
    } finally {
      if (showLoader) loading.value = false
      refreshing.value = false
    }
  }

  const fetchTrafficMapData = async () => {
    try {
      trafficMap.value = await fetchTrafficMap({ window_seconds: 60 })
      trafficEvents.value = []
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取实时地图失败'
    }
  }

  onMounted(() => {
    void fetchData(true)
    void fetchTrafficMapData()

    dashboardRefreshTimer = window.setInterval(() => {
      void fetchData(false)
    }, DASHBOARD_REFRESH_INTERVAL_MS)
    trafficMapRefreshTimer = window.setInterval(() => {
      void fetchTrafficMapData()
    }, TRAFFIC_MAP_REFRESH_INTERVAL_MS)
  })

  onBeforeUnmount(() => {
    if (dashboardRefreshTimer !== null) {
      window.clearInterval(dashboardRefreshTimer)
    }
    if (trafficMapRefreshTimer !== null) {
      window.clearInterval(trafficMapRefreshTimer)
    }
  })

  return {
    dashboard,
    trafficMap,
    aiAutomation,
    trafficEvents,
    l4Stats,
    l4Config,
    l7Stats,
    l7Config,
    loading,
    refreshing,
    error,
    lastUpdated,
    realtimeState,
    metricsHistory,
    networkHistory,
    attackTimeline,
    metricTrends,
    blockedPeriodDelta,
    pushHistory,
    formatBytes,
    formatNumber,
    formatLatency,
    emptyEventsResponse,
    emptyBlockedResponse,
    successRate,
    requestStatus,
    autoSlo,
    adaptiveRuntime,
    adaptiveManaged,
    adaptivePressureType,
    runtimePressureType,
    storageInsights,
    storageDegradedReasons,
    storageInsightType,
    formatShortTime,
    hotspotEventsRoute,
    summaryEventsRoute,
    calcAutoState,
    autoStateStyles,
    tlsTimeoutState,
    bucketRejectState,
    latencyState,
    applyMetrics,
    fetchData,
    fetchTrafficMapData,
  }
}
