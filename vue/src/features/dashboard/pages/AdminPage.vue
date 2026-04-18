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
  aiAutomation,
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

const stateTextClass = {
  success: 'text-emerald-700',
  warning: 'text-amber-700',
  error: 'text-red-700',
  muted: 'text-slate-500',
} as const

const l7ModeLabel = (mode?: string) => {
  const labels: Record<string, string> = {
    active: '主动',
    observe: '观察',
    off: '关闭',
  }
  return labels[mode || ''] || '关闭'
}

const l4OverloadLabel = (level?: string) => {
  const labels: Record<string, string> = {
    normal: '正常',
    high: '偏高',
    critical: '严重',
  }
  return labels[level || ''] || '正常'
}

const controllerStateLabel = (state?: string) => {
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

const providerLabel = (value?: string) => {
  const labels: Record<string, string> = {
    local_rules: '本地规则',
    stub_model: '占位模型',
    openai_compatible: 'OpenAI兼容',
    xiaomi_mimo: '小米Mimo',
  }
  return labels[value || ''] || '未知'
}

const confidenceLabel = (value?: string) => {
  const labels: Record<string, string> = {
    high: '高',
    medium: '中',
    low: '低',
  }
  return labels[value || ''] || '未知'
}

const pressureLabel = (value?: string) => {
  const labels: Record<string, string> = {
    normal: '正常',
    elevated: '升高',
    high: '偏高',
    attack: '攻击',
  }
  return labels[value || ''] || '未知'
}

const aiActionLabel = (value?: string) => {
  const labels: Record<string, string> = {
    add_behavior_watch: '行为观察',
    add_temp_block: '临时封禁',
    increase_challenge: '增加挑战',
    increase_delay: '增加延迟',
    raise_identity_risk: '提高身份风险',
    tighten_host_cc: '收紧Host CC',
    tighten_route_cc: '收紧路由CC',
  }
  return labels[value || ''] || value || '未知动作'
}

const aiPolicyStatusLabel = (value?: string) => {
  const labels: Record<string, string> = {
    cold: '待命中',
    effective: '有效',
    needs_review: '需复核',
    observing: '观察中',
  }
  return labels[value || ''] || value || '观察中'
}

const formatPercent = (value?: number) => `${(value || 0).toFixed(0)}%`

const formatCompactDuration = (seconds?: number) => {
  const value = seconds || 0
  if (value < 60) return `${value}s`
  if (value < 3600) return `${Math.round(value / 60)}m`
  return `${(value / 3600).toFixed(1)}h`
}

const formatUnixTime = (value?: number | null) => {
  if (!value) return '暂无'
  return new Intl.DateTimeFormat('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(value * 1000))
}

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

const aiAutomationStatusType = computed(() => {
  if (!aiAutomation.value?.available) return 'warning' as const
  if (!aiAutomation.value.status.enabled) return 'muted' as const
  if (
    aiAutomation.value.status.force_local_rules_under_attack ||
    aiAutomation.value.provider === 'local_rules'
  ) {
    return 'info' as const
  }
  return 'success' as const
})

const aiAutomationStatusLabel = computed(() => {
  if (!aiAutomation.value?.available) return '数据不足'
  if (!aiAutomation.value.status.enabled) return '已关闭'
  if (
    aiAutomation.value.status.force_local_rules_under_attack ||
    aiAutomation.value.provider === 'local_rules'
  ) {
    return '本地兜底'
  }
  return '运行中'
})

const aiAutomationStats = computed(() => {
  const overview = aiAutomation.value
  return [
    {
      label: '活跃策略',
      value: `${formatNumber(overview?.active_policy_count || 0)}/${formatNumber(
        overview?.max_active_policy_count || 0,
      )}`,
    },
    {
      label: '采样事件',
      value: `${formatNumber(overview?.sampled_events || 0)}/${formatNumber(
        overview?.total_events || 0,
      )}`,
    },
    {
      label: '可信度',
      value: confidenceLabel(overview?.data_quality.analysis_confidence),
      class:
        overview?.data_quality.analysis_confidence === 'low'
          ? 'text-amber-700'
          : 'text-emerald-700',
    },
    {
      label: '持久覆盖',
      value: formatPercent(overview?.data_quality.persistence_coverage_ratio),
    },
  ]
})

const aiAutomationPressureRows = computed(() => [
  {
    label: '身份压力',
    value: aiAutomation.value?.current.identity_pressure_percent || 0,
    color: 'bg-blue-600',
  },
  {
    label: 'L7摩擦',
    value: aiAutomation.value?.current.l7_friction_pressure_percent || 0,
    color: 'bg-amber-500',
  },
  {
    label: '慢速攻击',
    value: aiAutomation.value?.current.slow_attack_pressure_percent || 0,
    color: 'bg-red-500',
  },
])

const aiTrendMax = computed(() =>
  Math.max(
    ...((aiAutomation.value?.trend_windows || []).map(
      (item) => item.total_events,
    ) || []),
    1,
  ),
)

const aiTriggerFacts = computed(() => {
  const overview = aiAutomation.value
  return [
    {
      label: '触发',
      value:
        overview?.status.last_trigger_reason ||
        overview?.unavailable_reason ||
        '暂无触发',
    },
    {
      label: '完成',
      value: formatUnixTime(overview?.status.last_completed_at),
    },
    {
      label: '周期',
      value: `${formatCompactDuration(
        overview?.status.interval_secs,
      )} / 冷却 ${formatCompactDuration(overview?.status.cooldown_secs)}`,
    },
  ]
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

const defenseMatrix = computed(() => {
  const metrics = dashboard.value?.metrics
  const l7Tuning = l7Stats.value?.auto_tuning
  const l4Overview = l4Stats.value?.behavior.overview
  const droppedStorageEvents =
    (metrics?.sqlite_dropped_security_events || 0) +
    (metrics?.sqlite_dropped_blocked_ips || 0)

  return [
    {
      label: 'CC',
      badge: ccTotal.value > 0 ? '活跃' : '无命中',
      type: ccTotal.value > 0 ? ('warning' as const) : ('muted' as const),
      stats: [
        {
          label: '挑战',
          value: formatNumber(metrics?.l7_cc_challenges || 0),
        },
        {
          label: '拦截',
          value: formatNumber(metrics?.l7_cc_blocks || 0),
          class: (metrics?.l7_cc_blocks || 0) > 0 ? 'text-red-700' : '',
        },
        {
          label: '延迟',
          value: formatNumber(metrics?.l7_cc_delays || 0),
          class: (metrics?.l7_cc_delays || 0) > 0 ? 'text-amber-700' : '',
        },
        {
          label: '放行',
          value: formatNumber(metrics?.l7_cc_verified_passes || 0),
          class: 'text-emerald-700',
        },
      ],
      summary: 'CC 挑战链路',
    },
    {
      label: 'L7',
      badge: l7ModeLabel(l7Tuning?.mode),
      type: l7ModeType.value,
      stats: [
        {
          label: '状态',
          value: controllerStateLabel(l7Tuning?.controller_state),
        },
        {
          label: 'TLS超时',
          value: `${(
            l7Tuning?.last_observed_tls_handshake_timeout_rate_percent || 0
          ).toFixed(2)}%`,
          class: stateTextClass[tlsTimeoutState.value],
        },
        {
          label: '桶拒绝',
          value: `${(
            l7Tuning?.last_observed_bucket_reject_rate_percent || 0
          ).toFixed(2)}%`,
          class: stateTextClass[bucketRejectState.value],
        },
        {
          label: '核心',
          value: formatNumber(
            l7Tuning?.detected_cpu_cores ||
              metrics?.system?.cpu_core_count ||
              0,
          ),
        },
      ],
      summary: l7Tuning?.last_adjust_reason || '最近无自动动作',
    },
    {
      label: 'L4',
      badge: l4OverloadLabel(l4OverloadLevel.value),
      type: l4OverloadType.value,
      stats: [
        {
          label: '桶数',
          value: formatNumber(l4Overview?.bucket_count || 0),
        },
        {
          label: '高风险',
          value: formatNumber(l4Overview?.high_risk_buckets || 0),
          class:
            (l4Overview?.high_risk_buckets || 0) > 0
              ? 'text-amber-700'
              : '',
        },
        {
          label: '丢弃',
          value: formatNumber(l4Overview?.dropped_events || 0),
          class:
            (l4Overview?.dropped_events || 0) > 0 ? 'text-red-700' : '',
        },
        {
          label: '预算拒绝',
          value: formatNumber(metrics?.l4_bucket_budget_rejections || 0),
          class:
            (metrics?.l4_bucket_budget_rejections || 0) > 0
              ? 'text-red-700'
              : '',
        },
      ],
      summary: '四层限速与过载',
    },
    {
      label: '存储',
      badge: metrics?.sqlite_enabled ? '持久化' : '未连接',
      type: metrics?.sqlite_enabled ? ('success' as const) : ('muted' as const),
      stats: [
        {
          label: '队列',
          value: `${formatNumber(
            metrics?.runtime_pressure_storage_queue_percent || 0,
          )}%`,
          class:
            (metrics?.runtime_pressure_storage_queue_percent || 0) >= 80
              ? 'text-amber-700'
              : '',
        },
        {
          label: '聚合',
          value: formatNumber(storageInsights.value.active_event_count),
        },
        {
          label: '长尾',
          value: formatNumber(storageInsights.value.long_tail_event_count),
        },
        {
          label: '丢弃',
          value: formatNumber(droppedStorageEvents),
          class: droppedStorageEvents > 0 ? 'text-red-700' : '',
        },
      ],
      summary: '事件写入与聚合',
    },
  ]
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
        class="rounded-xl border border-slate-200 bg-white px-3 py-2.5 shadow-sm"
      >
        <div
          class="grid grid-cols-1 divide-y divide-slate-100 md:grid-cols-2 md:divide-x md:divide-y-0 xl:grid-cols-4"
        >
          <div
            v-for="item in defenseMatrix"
            :key="item.label"
            class="relative min-w-0 px-0 py-2 pr-16 first:pt-0 last:pb-0 md:px-3 md:py-0 md:pr-16 md:first:pl-0"
          >
            <p class="truncate text-xs font-semibold text-slate-900">
              {{ item.label }}
            </p>
            <StatusBadge
              class="absolute right-0 top-2 md:right-3 md:top-0"
              :text="item.badge"
              :type="item.type"
              compact
            />
            <div class="mt-2 grid grid-cols-2 gap-x-4 gap-y-1.5">
              <div
                v-for="stat in item.stats"
                :key="stat.label"
                class="flex min-w-0 items-baseline justify-between gap-2 text-[11px]"
              >
                <span class="shrink-0 text-slate-500">{{ stat.label }}</span>
                <span
                  class="min-w-0 truncate text-right font-semibold text-slate-900"
                  :class="stat.class"
                  :title="stat.value"
                >
                  {{ stat.value }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  </AppLayout>
</template>
