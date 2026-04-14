<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { fetchTrafficMap } from '@/shared/api/dashboard'
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
  TrafficEventDelta,
  SecurityEventsResponse,
  TrafficMapResponse,
} from '@/shared/types'
import AppLayout from '@/app/layout/AppLayout.vue'
import MetricWidget from '@/shared/ui/MetricWidget.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import CyberCard from '@/shared/ui/CyberCard.vue'
import AdminEventMapSection from '@/features/dashboard/components/AdminEventMapSection.vue'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import {
  useAdminRealtimeState,
  useAdminRealtimeTopic,
} from '@/shared/realtime/adminRealtime'
import {
  Activity,
  Database,
  Gauge,
  RefreshCw,
  Shield,
  ArrowUpRight,
  TimerReset,
} from 'lucide-vue-next'

const dashboard = ref<DashboardPayload | null>(null)
const trafficMap = ref<TrafficMapResponse | null>(null)
const trafficEvents = ref<TrafficEventDelta[]>([])
const l4Stats = ref<L4StatsPayload | null>(null)
const l4Config = ref<L4ConfigPayload | null>(null)
const l7Stats = ref<L7StatsPayload | null>(null)
const l7Config = ref<L7ConfigPayload | null>(null)
const loading = ref(true)
const refreshing = ref(false)
const error = ref('')
const lastUpdated = ref<number | null>(null)
const realtimeState = useAdminRealtimeState()

useFlashMessages({
  error,
  errorTitle: '控制台',
  errorDuration: 5600,
})

const metricsHistory = reactive({
  totalPackets: [] as number[],
  blockRate: [] as number[],
  latency: [] as number[],
})

const pushHistory = (key: keyof typeof metricsHistory, value: number) => {
  const series = metricsHistory[key]
  series.push(Number.isFinite(value) ? value : 0)
  if (series.length > 12) {
    series.shift()
  }
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

const autoSlo = computed(() => l7Config.value?.auto_tuning.slo ?? {
  tls_handshake_timeout_rate_percent: 0.3,
  bucket_reject_rate_percent: 0.5,
  p95_proxy_latency_ms: 800,
})

const adaptiveRuntime = computed(
  () => l7Config.value?.adaptive_runtime ?? l4Config.value?.adaptive_runtime ?? null,
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

const calcAutoState = (observed: number, target: number) => {
  if (!Number.isFinite(observed) || !Number.isFinite(target) || target <= 0) {
    return 'muted' as const
  }
  const ratio = observed / target
  if (ratio <= 1) return 'success' as const
  if (ratio <= 1.5) return 'warning' as const
  return 'error' as const
}

const autoStateStyles: Record<'success' | 'warning' | 'error' | 'muted', string> = {
  success: 'text-emerald-700 bg-emerald-50 border-emerald-200',
  warning: 'text-amber-700 bg-amber-50 border-amber-200',
  error: 'text-red-700 bg-red-50 border-red-200',
  muted: 'text-slate-600 bg-slate-50 border-slate-200',
}

const tlsTimeoutState = computed(() =>
  calcAutoState(
    l7Stats.value?.auto_tuning.last_observed_tls_handshake_timeout_rate_percent ?? 0,
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
  pushHistory('totalPackets', metrics.total_packets)
  pushHistory(
    'blockRate',
    metrics.total_packets
      ? Number(((metrics.blocked_packets / metrics.total_packets) * 100).toFixed(2))
      : 0,
  )
  pushHistory('latency', metrics.average_proxy_latency_micros)
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

useAdminRealtimeTopic<SecurityEventItem>('security_event_delta', (payload) => {
  if (!dashboard.value) return
  const events = [payload, ...dashboard.value.events.events].filter(
    (event, index, items) => items.findIndex((item) => item.id === event.id) === index,
  )
  dashboard.value.events = {
    ...dashboard.value.events,
    total: dashboard.value.events.total + 1,
    events: events.slice(0, 8),
  }
  lastUpdated.value = Date.now()
})

useAdminRealtimeTopic<BlockedIpItem>('blocked_ip_upsert', (payload) => {
  if (!dashboard.value) return
  const blockedIps = [payload, ...dashboard.value.blockedIps.blocked_ips].filter(
    (item, index, items) => items.findIndex((candidate) => candidate.id === item.id) === index,
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
  const blockedIps = dashboard.value.blockedIps.blocked_ips.filter((item) => item.id !== id)
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
    const [health, metrics, rules, events, blockedIps, l4StatsPayload, l4ConfigPayload, l7StatsPayload, l7ConfigPayload] = await Promise.all([
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
})

</script>

<template>
  <AppLayout>
    <template #header-extra>
      <div class="flex items-center gap-3">
        <span class="text-xs text-slate-500 whitespace-nowrap">{{
          requestStatus
        }}</span>
        <button
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
          :disabled="refreshing"
          @click="fetchData()"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
          同步
        </button>
      </div>
    </template>

    <div v-if="loading" class="flex h-72 items-center justify-center">
      <div
        class="flex flex-col items-center gap-4 rounded-2xl border border-slate-200 bg-white px-4 py-6 shadow-sm"
      >
        <RefreshCw class="animate-spin text-blue-700" :size="30" />
        <p class="text-sm text-slate-500">正在载入边界态势</p>
      </div>
    </div>

    <div v-else class="space-y-4">
      <section class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricWidget
          label="累计处理报文"
          :value="formatNumber(dashboard?.metrics.total_packets || 0)"
          :hint="`累计流量 ${formatBytes(dashboard?.metrics.total_bytes || 0)}`"
          :icon="Activity"
          :series="metricsHistory.totalPackets"
        />
        <MetricWidget
          label="累计拦截次数"
          :value="formatNumber(dashboard?.metrics.blocked_packets || 0)"
          :hint="`四层 ${formatNumber(dashboard?.metrics.blocked_l4 || 0)} / HTTP ${formatNumber(dashboard?.metrics.blocked_l7 || 0)}`"
          :icon="Shield"
          trend="up"
          :series="metricsHistory.blockRate"
        />
        <MetricWidget
          label="平均代理延迟"
          :value="
            formatLatency(dashboard?.metrics.average_proxy_latency_micros || 0)
          "
          :hint="`失败关闭次数 ${formatNumber(dashboard?.metrics.proxy_fail_close_rejections || 0)}`"
          :icon="Gauge"
          trend="down"
          :series="metricsHistory.latency"
        />
        <div
          class="relative overflow-hidden rounded-xl border border-amber-200/80 bg-gradient-to-br from-amber-50 via-white to-stone-50 p-3 shadow-sm"
        >
          <div
            class="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-amber-400 via-amber-300 to-transparent"
          ></div>
          <div class="absolute right-0 top-0 p-3 opacity-20">
            <Database :size="20" class="text-amber-700" />
          </div>

          <div class="space-y-3">
            <div class="flex items-start justify-between gap-3">
              <div>
                <p class="text-xs font-medium text-amber-700/80">启用规则</p>
                <h3 class="mt-1 text-xl font-semibold text-slate-900">
                  {{ dashboard?.metrics.active_rules || 0 }}
                </h3>
              </div>
              <StatusBadge
                :text="
                  (dashboard?.metrics.active_rules || 0) > 0 ? '配置生效中' : '待启用'
                "
                :type="
                  (dashboard?.metrics.active_rules || 0) > 0 ? 'warning' : 'muted'
                "
              />
            </div>

            <div class="grid grid-cols-2 gap-3 rounded-lg border border-amber-100 bg-white/80 p-3">
              <div>
                <p class="text-[11px] uppercase tracking-[0.18em] text-slate-400">
                  规则总数
                </p>
                <p class="mt-1 text-lg font-semibold text-slate-900">
                  {{ formatNumber(dashboard?.rules.rules.length || 0) }}
                </p>
              </div>
              <div>
                <p class="text-[11px] uppercase tracking-[0.18em] text-slate-400">
                  代理成功率
                </p>
                <p class="mt-1 text-lg font-semibold text-slate-900">
                  {{ successRate }}
                </p>
              </div>
            </div>

          </div>
        </div>
      </section>

      <section class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricWidget
          label="CC Challenge 次数"
          :value="formatNumber(dashboard?.metrics.l7_cc_challenges || 0)"
          hint="已返回挑战页或挑战响应"
          :icon="Shield"
        />
        <MetricWidget
          label="CC 429 次数"
          :value="formatNumber(dashboard?.metrics.l7_cc_blocks || 0)"
          :hint="`HTTP 拦截 ${formatNumber(dashboard?.metrics.blocked_l7 || 0)} 中的硬阻断部分`"
          :icon="Activity"
          trend="up"
        />
        <MetricWidget
          label="CC 延迟处置"
          :value="formatNumber(dashboard?.metrics.l7_cc_delays || 0)"
          hint="命中软阈值后执行延迟"
          :icon="TimerReset"
        />
        <MetricWidget
          label="Challenge 放行"
          :value="formatNumber(dashboard?.metrics.l7_cc_verified_passes || 0)"
          hint="已完成验证并继续放行"
          :icon="ArrowUpRight"
        />
      </section>

      <section
        v-if="adaptiveManaged && adaptiveRuntime"
        class="rounded-xl border border-emerald-200 bg-[linear-gradient(135deg,rgba(240,253,244,0.92),rgba(236,253,245,0.88),rgba(239,246,255,0.9))] p-4 shadow-sm"
      >
        <div class="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
          <div class="space-y-2">
            <div class="flex flex-wrap items-center gap-2">
              <p class="text-sm tracking-wider text-emerald-700">Adaptive Protection</p>
              <StatusBadge
                :text="adaptiveRuntime.system_pressure"
                :type="adaptivePressureType"
              />
            </div>
            <p class="text-sm leading-6 text-stone-700">
              当前按 {{ adaptiveRuntime.mode }} / {{ adaptiveRuntime.goal }} 自动调节 L4 与 L7。首页展示的是运行时主策略，不再把细粒度阈值当主操作面板。
            </p>
          </div>
          <div class="grid gap-3 text-sm text-stone-700 md:grid-cols-2">
            <div class="rounded-lg border border-white/80 bg-white/70 p-3">
              <p class="text-xs text-slate-500">L4 连接预算</p>
              <p class="mt-1 font-semibold text-stone-900">
                {{ adaptiveRuntime.l4.normal_connection_budget_per_minute }} / {{ adaptiveRuntime.l4.suspicious_connection_budget_per_minute }} / {{ adaptiveRuntime.l4.high_risk_connection_budget_per_minute }}
              </p>
            </div>
            <div class="rounded-lg border border-white/80 bg-white/70 p-3">
              <p class="text-xs text-slate-500">L7 Challenge / Block</p>
              <p class="mt-1 font-semibold text-stone-900">
                {{ adaptiveRuntime.l7.ip_challenge_threshold }} / {{ adaptiveRuntime.l7.ip_block_threshold }}
              </p>
            </div>
          </div>
        </div>
        <div
          v-if="adaptiveRuntime.reasons.length"
          class="mt-3 flex flex-wrap gap-2"
        >
          <span
            v-for="reason in adaptiveRuntime.reasons"
            :key="reason"
            class="rounded-full border border-white/80 bg-white/70 px-2.5 py-1 text-xs text-stone-700"
          >
            {{ reason }}
          </span>
        </div>
      </section>

      <section class="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <div class="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div class="flex items-center justify-between gap-3">
            <p class="text-sm tracking-wider text-blue-700">L7 AUTO</p>
            <StatusBadge
              :text="l7Stats?.auto_tuning.mode || 'off'"
              :type="
                l7Stats?.auto_tuning.mode === 'active'
                  ? 'success'
                  : l7Stats?.auto_tuning.mode === 'observe'
                    ? 'warning'
                    : 'muted'
              "
            />
          </div>
          <div class="mt-3 grid grid-cols-2 gap-3 text-sm">
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">控制器状态</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ l7Stats?.auto_tuning.controller_state || 'unknown' }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">最近动作</p>
              <p class="mt-1 font-semibold text-slate-900 truncate" :title="l7Stats?.auto_tuning.last_adjust_reason || ''">
                {{ l7Stats?.auto_tuning.last_adjust_reason || 'none' }}
              </p>
            </div>
            <div :class="`rounded-lg border p-3 ${autoStateStyles[tlsTimeoutState]}`">
              <p class="text-xs text-slate-500">握手超时率</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ (l7Stats?.auto_tuning.last_observed_tls_handshake_timeout_rate_percent || 0).toFixed(2) }}%
              </p>
              <p class="mt-1 text-[11px]">目标 ≤ {{ autoSlo.tls_handshake_timeout_rate_percent.toFixed(2) }}%</p>
            </div>
            <div :class="`rounded-lg border p-3 ${autoStateStyles[bucketRejectState]}`">
              <p class="text-xs text-slate-500">预算拒绝率</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ (l7Stats?.auto_tuning.last_observed_bucket_reject_rate_percent || 0).toFixed(2) }}%
              </p>
              <p class="mt-1 text-[11px]">目标 ≤ {{ autoSlo.bucket_reject_rate_percent.toFixed(2) }}%</p>
            </div>
            <div :class="`rounded-lg border p-3 ${autoStateStyles[latencyState]}`">
              <p class="text-xs text-slate-500">平均代理延迟</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ formatNumber(l7Stats?.auto_tuning.last_observed_avg_proxy_latency_ms || 0) }} ms
              </p>
              <p class="mt-1 text-[11px]">目标 ≤ {{ formatNumber(autoSlo.p95_proxy_latency_ms) }} ms</p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">24h 回滚次数</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ formatNumber(l7Stats?.auto_tuning.rollback_count_24h || 0) }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">TLS 预握手拒绝累计</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ formatNumber(dashboard?.metrics.tls_pre_handshake_rejections || 0) }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">TLS 握手超时累计</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ formatNumber(dashboard?.metrics.tls_handshake_timeouts || 0) }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">TLS 握手失败累计</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ formatNumber(dashboard?.metrics.tls_handshake_failures || 0) }}
              </p>
            </div>
          </div>
          <p class="mt-3 text-xs text-slate-500">
            资源探测: CPU {{ l7Stats?.auto_tuning.detected_cpu_cores || 0 }} cores /
            内存上限 {{ l7Stats?.auto_tuning.detected_memory_limit_mb ?? 'unknown' }} MB
          </p>
        </div>

        <div class="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div class="flex items-center justify-between gap-3">
            <p class="text-sm tracking-wider text-blue-700">L4 AUTO</p>
            <StatusBadge
              :text="l4Stats?.behavior.overview.overload_level || 'normal'"
              :type="
                l4Stats?.behavior.overview.overload_level === 'critical'
                  ? 'error'
                  : l4Stats?.behavior.overview.overload_level === 'high'
                    ? 'warning'
                    : 'success'
              "
            />
          </div>
          <div class="mt-3 grid grid-cols-2 gap-3 text-sm">
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">Bucket 总数</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ formatNumber(l4Stats?.behavior.overview.bucket_count || 0) }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">高风险 Bucket</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ formatNumber(l4Stats?.behavior.overview.high_risk_buckets || 0) }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">事件丢弃</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ formatNumber(l4Stats?.behavior.overview.dropped_events || 0) }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">预算拒绝累计</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ formatNumber(dashboard?.metrics.l4_bucket_budget_rejections || 0) }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">推荐 normal budget</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ formatNumber(l7Stats?.auto_tuning.recommendation.l4_normal_connection_budget_per_minute || 0) }}
              </p>
            </div>
            <div class="rounded-lg border border-slate-200 bg-slate-50 p-3">
              <p class="text-xs text-slate-500">推荐 TLS 握手超时</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ formatNumber(l7Stats?.auto_tuning.recommendation.tls_handshake_timeout_ms || 0) }} ms
              </p>
            </div>
          </div>
        </div>
      </section>

      <section class="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        <AdminEventMapSection :traffic-map="trafficMap" :traffic-events="trafficEvents" />

        <CyberCard title="运行摘要">
          <div class="grid gap-4">
            <div class="rounded-xl border border-amber-200 bg-amber-50/70 p-4">
              <div class="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p class="text-xs text-amber-700/80">Challenge / 429</p>
                  <p class="mt-1 text-2xl font-semibold text-stone-900">
                    {{ formatNumber(dashboard?.metrics.l7_cc_challenges || 0) }}
                    /
                    {{ formatNumber(dashboard?.metrics.l7_cc_blocks || 0) }}
                  </p>
                </div>
                <div>
                  <p class="text-xs text-amber-700/80">Delay / 放行</p>
                  <p class="mt-1 text-2xl font-semibold text-stone-900">
                    {{ formatNumber(dashboard?.metrics.l7_cc_delays || 0) }}
                    /
                    {{
                      formatNumber(
                        dashboard?.metrics.l7_cc_verified_passes || 0,
                      )
                    }}
                  </p>
                </div>
              </div>
            </div>

            <div class="rounded-xl bg-slate-50 px-4 py-3">
              <div class="grid grid-cols-2 gap-3">
                <div>
                  <p class="text-xs text-slate-500">成功</p>
                  <p class="mt-0.5 text-2xl font-semibold text-stone-900">
                    {{ formatNumber(dashboard?.metrics.proxy_successes || 0) }}
                  </p>
                </div>
                <div>
                  <p class="text-xs text-slate-500">上游代理失败</p>
                  <p class="mt-0.5 text-2xl font-semibold text-red-600">
                    {{ formatNumber(dashboard?.metrics.proxy_failures || 0) }}
                  </p>
                </div>
              </div>
            </div>

            <div class="grid gap-4 md:grid-cols-2">
              <div class="rounded-xl border border-slate-200 p-4">
                <div class="flex items-center justify-between gap-3">
                  <p class="text-xs text-slate-500">上游状态</p>
                  <StatusBadge
                    :text="dashboard?.health.upstream_healthy ? '可用' : '异常'"
                    :type="dashboard?.health.upstream_healthy ? 'success' : 'error'"
                  />
                </div>
                <p class="mt-2 text-2xl font-semibold text-slate-900">
                  {{ dashboard?.health.upstream_healthy ? 'Healthy' : 'Degraded' }}
                </p>
              </div>
              <div class="rounded-xl border border-slate-200 p-4">
                <p class="text-xs text-slate-500">最近检查</p>
                <p class="mt-2 text-lg font-semibold text-slate-900">
                  {{
                    dashboard?.health.upstream_last_check_at
                      ? new Intl.DateTimeFormat('zh-CN', {
                          month: '2-digit',
                          day: '2-digit',
                          hour: '2-digit',
                          minute: '2-digit',
                          second: '2-digit',
                        }).format(new Date(dashboard.health.upstream_last_check_at * 1000))
                      : '暂无记录'
                  }}
                </p>
                <p
                  v-if="dashboard?.health.upstream_last_error"
                  class="mt-2 truncate text-xs text-red-600"
                  :title="dashboard.health.upstream_last_error"
                >
                  {{ dashboard.health.upstream_last_error }}
                </p>
              </div>
            </div>

            <div class="rounded-xl border border-slate-200 p-4">
              <p class="text-xs text-slate-500">本地数据库状态</p>
              <div class="mt-3 flex items-center justify-between">
                <p class="text-lg font-semibold text-stone-900">
                  {{ dashboard?.metrics.sqlite_enabled ? '已启用' : '未启用' }}
                </p>
                <StatusBadge
                  :text="
                    dashboard?.metrics.sqlite_enabled ? '持久化可用' : '未连接'
                  "
                  :type="
                    dashboard?.metrics.sqlite_enabled ? 'success' : 'muted'
                  "
                />
              </div>
            </div>
          </div>
        </CyberCard>
      </section>
    </div>
  </AppLayout>
</template>
