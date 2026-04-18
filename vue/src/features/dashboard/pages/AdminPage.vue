<script setup lang="ts">
import { computed, defineAsyncComponent } from 'vue'
import AppLayout from '@/app/layout/AppLayout.vue'
import MetricWidget from '@/shared/ui/MetricWidget.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import { RefreshCw } from 'lucide-vue-next'
import { useAdminDashboardPage } from '@/features/dashboard/composables/useAdminDashboardPage'

const AdminEventMapSection = defineAsyncComponent(
  () => import('@/features/dashboard/components/AdminEventMapSection.vue'),
)
const AdminNetworkPerformancePanel = defineAsyncComponent(
  () =>
    import('@/features/dashboard/components/AdminNetworkPerformancePanel.vue'),
)

const {
  dashboard,
  trafficMap,
  trafficEvents,
  l4Stats,
  l7Stats,
  loading,
  refreshing,
  metricsHistory,
  networkHistory,
  metricTrends,
  formatBytes,
  formatNumber,
  successRate,
  requestStatus,
  storageInsights,
  autoStateStyles,
  tlsTimeoutState,
  bucketRejectState,
  fetchData,
} = useAdminDashboardPage()

const ccTotal = computed(
  () =>
    (dashboard.value?.metrics.l7_cc_challenges || 0) +
    (dashboard.value?.metrics.l7_cc_blocks || 0) +
    (dashboard.value?.metrics.l7_cc_delays || 0),
)

const l4OverloadLevel = computed(
  () => l4Stats.value?.behavior.overview.overload_level || 'normal',
)

const l4OverloadType = computed(() => {
  if (l4OverloadLevel.value === 'critical') return 'error' as const
  if (l4OverloadLevel.value === 'high') return 'warning' as const
  return 'success' as const
})

const l7ModeType = computed(() => {
  const mode = l7Stats.value?.auto_tuning.mode
  if (mode === 'active') return 'success' as const
  if (mode === 'observe') return 'warning' as const
  return 'muted' as const
})

const clampPercent = (value: number) => Math.max(0, Math.min(100, value))

const gaugeTone = (percent: number) => {
  if (percent >= 92) {
    return {
      card: 'border-red-200 bg-red-50/80 text-red-700',
      color: '#dc2626',
      track: 'rgba(254, 202, 202, 0.8)',
    }
  }
  if (percent >= 80) {
    return {
      card: 'border-amber-200 bg-amber-50/80 text-amber-700',
      color: '#d97706',
      track: 'rgba(253, 230, 138, 0.85)',
    }
  }
  return {
    card: 'border-slate-200 bg-white text-blue-700',
    color: '#2563eb',
    track: 'rgba(203, 213, 225, 0.75)',
  }
}

const formatLatencyEnglish = (micros: number) => {
  if (micros < 1000) return `${formatNumber(Math.round(micros))} us`

  const millis = micros / 1000
  if (millis < 1000) {
    const value =
      millis < 10
        ? millis.toFixed(2)
        : millis < 100
          ? millis.toFixed(1)
          : Math.round(millis).toString()
    return `${value} ms`
  }

  return `${(millis / 1000).toFixed(2)} s`
}

const formatGaugeValue = (percent: number) => {
  if (percent >= 100) return '100%'
  return `${percent.toFixed(0)}%`
}

const proxySuccessPercent = computed(() => {
  const metrics = dashboard.value?.metrics
  if (!metrics) return 0
  const total = metrics.proxy_successes + metrics.proxy_failures
  if (total === 0) return 0
  return (metrics.proxy_successes / total) * 100
})

const packetSparkMax = computed(() => {
  const max = Math.max(...metricsHistory.totalPackets, 1)
  return Math.max(5, max * 1.5)
})

const latencySparkMax = computed(() => {
  const current = dashboard.value?.metrics.average_proxy_latency_micros || 0
  const max = Math.max(...metricsHistory.latency, current, 1_000)
  return max * 1.5
})

type PerformanceGaugeCard = {
  kind: 'gauge'
  label: string
  value: string
  gaugeValue: string
  primaryLabel: string
  primaryValue: string
  secondaryLabel: string
  secondaryValue: string
  percent: number
  tone: string
  color: string
  track: string
}

type PerformanceIoCard = {
  kind: 'io'
  label: string
  readValue: string
  writeValue: string
  readPercent: number
  writePercent: number
  tone: string
  color: string
  track: string
}

type PerformanceCard = PerformanceGaugeCard | PerformanceIoCard

const performanceCards = computed(() => {
  const system = dashboard.value?.metrics.system
  const cpuPercent = clampPercent(system?.cpu_usage_percent || 0)
  const memoryPercent = clampPercent(system?.memory_usage_percent || 0)
  const cpuCoreCount =
    system?.cpu_core_count || l7Stats.value?.auto_tuning.detected_cpu_cores || 0
  const activeCpuCores = (cpuCoreCount * cpuPercent) / 100
  const memoryUsed = system?.memory_used_bytes || 0
  const memoryTotal = system?.memory_total_bytes || 0
  const ioRead = system?.process_disk_read_bytes_per_sec || 0
  const ioWrite = system?.process_disk_write_bytes_per_sec || 0
  const ioTotal = ioRead + ioWrite
  const ioPeak = Math.max(ioRead, ioWrite, 1)
  const ioReadPercent = Math.max(6, (ioRead / ioPeak) * 100)
  const ioWritePercent = Math.max(6, (ioWrite / ioPeak) * 100)
  const cpuTone = gaugeTone(cpuPercent)
  const memoryTone = gaugeTone(memoryPercent)

  return [
    {
      kind: 'gauge',
      label: 'CPU',
      value: `${cpuPercent.toFixed(1)}%`,
      gaugeValue: formatGaugeValue(cpuPercent),
      primaryLabel: '总核心',
      primaryValue: formatNumber(cpuCoreCount),
      secondaryLabel: '活跃核',
      secondaryValue: activeCpuCores.toFixed(1),
      percent: cpuPercent,
      tone: cpuTone.card,
      color: cpuTone.color,
      track: cpuTone.track,
    },
    {
      kind: 'gauge',
      label: '内存',
      value: `${memoryPercent.toFixed(1)}%`,
      gaugeValue: formatGaugeValue(memoryPercent),
      primaryLabel: '已用',
      primaryValue: formatBytes(memoryUsed),
      secondaryLabel: '总量',
      secondaryValue: formatBytes(memoryTotal),
      percent: memoryPercent,
      tone: memoryTone.card,
      color: memoryTone.color,
      track: memoryTone.track,
    },
    {
      kind: 'io',
      label: 'IO',
      readValue: `${formatBytes(ioRead)}/s`,
      writeValue: `${formatBytes(ioWrite)}/s`,
      readPercent: ioReadPercent,
      writePercent: ioWritePercent,
      tone:
        ioTotal > 10 * 1024 * 1024
          ? 'border-blue-200 bg-blue-50/80 text-blue-700'
          : 'border-slate-200 bg-white text-indigo-700',
      color: ioTotal > 10 * 1024 * 1024 ? '#2563eb' : '#4f46e5',
      track: 'rgba(224, 231, 255, 0.9)',
    },
  ] satisfies PerformanceCard[]
})

const defenseMatrix = computed(() => [
  {
    label: 'CC',
    badge: ccTotal.value > 0 ? '活跃' : '无命中',
    type: ccTotal.value > 0 ? ('warning' as const) : ('muted' as const),
    value: `挑战 ${formatNumber(dashboard.value?.metrics.l7_cc_challenges || 0)} / 拦截 ${formatNumber(
      dashboard.value?.metrics.l7_cc_blocks || 0,
    )}`,
    hint: `延迟 ${formatNumber(dashboard.value?.metrics.l7_cc_delays || 0)} / 放行 ${formatNumber(
      dashboard.value?.metrics.l7_cc_verified_passes || 0,
    )}`,
  },
  {
    label: 'L7',
    badge: l7Stats.value?.auto_tuning.mode || 'off',
    type: l7ModeType.value,
    value: l7Stats.value?.auto_tuning.controller_state || 'unknown',
    hint: l7Stats.value?.auto_tuning.last_adjust_reason || '最近无自动动作',
  },
  {
    label: 'L4',
    badge: l4OverloadLevel.value,
    type: l4OverloadType.value,
    value: `高风险 ${formatNumber(
      l4Stats.value?.behavior.overview.high_risk_buckets || 0,
    )}`,
    hint: `Bucket ${formatNumber(
      l4Stats.value?.behavior.overview.bucket_count || 0,
    )} / 丢弃 ${formatNumber(
      l4Stats.value?.behavior.overview.dropped_events || 0,
    )}`,
  },
  {
    label: '存储',
    badge: dashboard.value?.metrics.sqlite_enabled ? '持久化' : '未连接',
    type: dashboard.value?.metrics.sqlite_enabled
      ? ('success' as const)
      : ('muted' as const),
    value: `队列 ${formatNumber(
      dashboard.value?.metrics.runtime_pressure_storage_queue_percent || 0,
    )}%`,
    hint: `聚合 ${formatNumber(storageInsights.value.active_event_count)} / 长尾 ${formatNumber(
      storageInsights.value.long_tail_event_count,
    )}`,
  },
])
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

    <div
      v-if="loading"
      class="grid min-h-[calc(100vh-8rem)] place-items-center"
    >
      <div
        class="flex flex-col items-center gap-3 rounded-xl border border-slate-200 bg-white px-4 py-5 shadow-sm"
      >
        <RefreshCw class="animate-spin text-blue-700" :size="30" />
        <p class="text-sm text-slate-500">正在载入边界态势</p>
      </div>
    </div>

    <div v-else class="space-y-3">
      <section class="grid grid-cols-2 gap-2 lg:grid-cols-4 2xl:grid-cols-7">
        <div
          v-for="card in performanceCards"
          :key="card.label"
          class="flex min-h-[5.75rem] min-w-0 flex-col rounded-xl border px-2.5 py-2 shadow-sm"
          :class="card.tone"
        >
          <p class="truncate text-xs font-medium opacity-75">
            {{ card.label }}
          </p>
          <div
            v-if="card.kind === 'gauge'"
            class="mt-1.5 flex min-w-0 items-center gap-2.5"
          >
            <div
              class="relative grid h-12 w-12 shrink-0 place-items-center rounded-full"
              :style="{
                background: `conic-gradient(${card.color} ${card.percent * 3.6}deg, ${card.track} 0deg)`,
              }"
            >
              <div
                class="grid h-9 w-9 place-items-center rounded-full bg-white text-[10px] font-semibold text-slate-950 shadow-inner"
                :title="card.value"
              >
                {{ card.gaugeValue }}
              </div>
            </div>
            <div class="grid min-w-0 flex-1 gap-1 leading-none">
              <div class="flex min-w-0 items-baseline justify-between gap-2">
                <p class="text-[10px] leading-3 text-slate-500">
                  {{ card.primaryLabel }}
                </p>
                <p
                  class="truncate text-xs font-semibold leading-4 text-slate-950"
                  :title="card.primaryValue"
                >
                  {{ card.primaryValue }}
                </p>
              </div>
              <div class="flex min-w-0 items-baseline justify-between gap-2">
                <p class="text-[10px] leading-3 text-slate-500">
                  {{ card.secondaryLabel }}
                </p>
                <p
                  class="truncate text-xs font-semibold leading-4 text-slate-950"
                  :title="card.secondaryValue"
                >
                  {{ card.secondaryValue }}
                </p>
              </div>
            </div>
          </div>
          <div v-else class="mt-2 min-w-0">
            <div class="grid gap-1.5 text-[11px]">
              <div class="min-w-0">
                <div class="flex min-w-0 items-baseline justify-between gap-2">
                  <p class="text-slate-500">Read</p>
                  <p
                    class="truncate font-semibold leading-4 text-slate-950"
                    :title="card.readValue"
                  >
                    {{ card.readValue }}
                  </p>
                </div>
                <div class="mt-0.5 h-1 overflow-hidden rounded-full bg-slate-100">
                  <div
                    class="h-full rounded-full bg-indigo-600"
                    :style="{ width: `${card.readPercent}%` }"
                  ></div>
                </div>
              </div>
              <div class="min-w-0">
                <div class="flex min-w-0 items-baseline justify-between gap-2">
                  <p class="text-slate-500">Write</p>
                  <p
                    class="truncate font-semibold leading-4 text-slate-950"
                    :title="card.writeValue"
                  >
                    {{ card.writeValue }}
                  </p>
                </div>
                <div class="mt-0.5 h-1 overflow-hidden rounded-full bg-slate-100">
                  <div
                    class="h-full rounded-full bg-cyan-600"
                    :style="{ width: `${card.writePercent}%` }"
                  ></div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <MetricWidget
          label="累计处理报文"
          :value="formatNumber(dashboard?.metrics.total_packets || 0)"
          :hint="`累计处理 ${formatBytes(dashboard?.metrics.total_bytes || 0)}`"
          :series="metricsHistory.totalPackets"
          :series-min="0"
          :series-max="packetSparkMax"
          ambient-series
          no-top-line
          trend-placement="corner"
        />
        <MetricWidget
          label="平均代理延迟"
          :value="formatLatencyEnglish(dashboard?.metrics.average_proxy_latency_micros || 0)"
          :hint="`失败关闭次数 ${formatNumber(dashboard?.metrics.proxy_fail_close_rejections || 0)}`"
          :trend="metricTrends.latency"
          :series="metricsHistory.latency"
          :series-min="0"
          :series-max="latencySparkMax"
          ambient-series
          no-top-line
          trend-placement="corner"
        />
        <MetricWidget
          label="代理成功率"
          :value="successRate"
          :hint="`成功 ${formatNumber(dashboard?.metrics.proxy_successes || 0)} / 失败 ${formatNumber(dashboard?.metrics.proxy_failures || 0)}`"
          :trend="metricTrends.successRate"
          :progress="proxySuccessPercent"
          no-top-line
          trend-placement="corner"
        />
        <MetricWidget
          label="累计拦截次数"
          :value="formatNumber(dashboard?.metrics.blocked_packets || 0)"
          :hint="`四层 ${formatNumber(dashboard?.metrics.blocked_l4 || 0)} / HTTP ${formatNumber(dashboard?.metrics.blocked_l7 || 0)}`"
          :trend="metricTrends.blocked"
          no-top-line
          trend-placement="corner"
        />
      </section>

      <section
        class="grid gap-3 xl:grid-cols-[minmax(0,1.55fr)_minmax(360px,0.95fr)]"
      >
        <AdminEventMapSection
          :traffic-map="trafficMap"
          :traffic-events="trafficEvents"
        />

        <AdminNetworkPerformancePanel
          :rx-rate="dashboard?.metrics.system?.network_rx_bytes_per_sec || 0"
          :tx-rate="dashboard?.metrics.system?.network_tx_bytes_per_sec || 0"
          :rx-total="dashboard?.metrics.system?.network_rx_total_bytes || 0"
          :tx-total="dashboard?.metrics.system?.network_tx_total_bytes || 0"
          :timestamps="networkHistory.timestamps"
          :rx-series="networkHistory.rx"
          :tx-series="networkHistory.tx"
        />
      </section>

      <section
        class="rounded-xl border border-slate-200 bg-white px-3 py-2 shadow-sm"
      >
        <div
          class="grid grid-cols-1 divide-y divide-slate-100 md:grid-cols-2 md:divide-x md:divide-y-0 xl:grid-cols-4"
        >
          <div
            v-for="item in defenseMatrix"
            :key="item.label"
            class="min-w-0 px-0 py-2 first:pt-0 last:pb-0 md:px-3 md:py-0 md:first:pl-0 md:last:pr-0"
          >
            <div class="flex items-center justify-between gap-3">
              <p class="text-xs font-medium text-slate-500">{{ item.label }}</p>
              <StatusBadge :text="item.badge" :type="item.type" compact />
            </div>
            <p class="mt-2 truncate text-sm font-semibold text-slate-900">
              {{ item.value }}
            </p>
            <p class="mt-1 truncate text-xs text-slate-500" :title="item.hint">
              {{ item.hint }}
            </p>
            <div
              v-if="item.label === 'L7'"
              class="mt-2 grid grid-cols-2 gap-2 text-[11px]"
            >
              <div
                :class="`rounded-md border px-2 py-1 ${autoStateStyles[tlsTimeoutState]}`"
              >
                TLS
                {{
                  (
                    l7Stats?.auto_tuning
                      .last_observed_tls_handshake_timeout_rate_percent || 0
                  ).toFixed(2)
                }}%
              </div>
              <div
                :class="`rounded-md border px-2 py-1 ${autoStateStyles[bucketRejectState]}`"
              >
                拒绝
                {{
                  (
                    l7Stats?.auto_tuning
                      .last_observed_bucket_reject_rate_percent || 0
                  ).toFixed(2)
                }}%
              </div>
            </div>
            <div
              v-if="item.label === '存储'"
              class="mt-2 text-[11px] text-slate-500"
            >
              代理 {{ formatNumber(dashboard?.metrics.proxy_successes || 0) }}
              /
              {{ formatNumber(dashboard?.metrics.proxy_failures || 0) }}
              <span class="text-slate-300">·</span>
              失败关闭
              {{
                formatNumber(
                  dashboard?.metrics.proxy_fail_close_rejections || 0,
                )
              }}
            </div>
          </div>
        </div>
      </section>
    </div>
  </AppLayout>
</template>
