<script setup lang="ts">
import { computed, defineAsyncComponent, ref, onMounted, onBeforeUnmount } from 'vue'
import AppLayout from '@/app/layout/AppLayout.vue'
import AdminDashboardAiAutomationPanel from '@/features/dashboard/components/AdminDashboardAiAutomationPanel.vue'
import AdminDashboardDefenseMatrix from '@/features/dashboard/components/AdminDashboardDefenseMatrix.vue'
import AdminDashboardPerformanceGrid from '@/features/dashboard/components/AdminDashboardPerformanceGrid.vue'
import { RefreshCw } from 'lucide-vue-next'
import { useAdminDashboardPage } from '@/features/dashboard/composables/useAdminDashboardPage'
import type { PerformanceCard } from '@/features/dashboard/components/AdminDashboardPerformanceGrid.vue'
import {
  aiPolicyDetailLine,
  aiPolicyStatusLabel,
  aiPolicyTitle,
  aiTriggerReasonLabel,
  confidenceLabel,
  controllerStateLabel,
  l4OverloadLabel,
  l7ModeLabel,
  pressureLabel,
  providerLabel,
  trendWindowLabel,
} from '@/features/dashboard/utils/dashboardLabels'

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

const aiPolicyFeedbackExpanded = ref(false)
const trafficMapMode = ref<'china' | 'global'>('china')

const trafficOverviewGridClass = computed(() =>
  trafficMapMode.value === 'china'
    ? 'xl:grid-cols-[minmax(300px,0.85fr)_minmax(0,1.7fr)]'
    : 'xl:grid-cols-[minmax(0,1.55fr)_minmax(360px,0.95fr)]',
)

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

const formatPolicyTime = (value?: number | null) => {
  if (!value) return '暂无'
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
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
  if (aiAutomation.value.provider === 'local_rules') {
    return 'info' as const
  }
  if (
    aiAutomation.value.runtime_pressure_level === 'attack' &&
    aiAutomation.value.status.force_local_rules_under_attack
  ) {
    return 'info' as const
  }
  return 'success' as const
})

const aiAutomationStatusLabel = computed(() => {
  if (!aiAutomation.value?.available) return '数据不足'
  if (!aiAutomation.value.status.enabled) return '已关闭'
  if (aiAutomation.value.provider === 'local_rules') return '本地规则'
  if (
    aiAutomation.value.runtime_pressure_level === 'attack' &&
    aiAutomation.value.status.force_local_rules_under_attack
  )
    return '攻击兜底'
  return '运行中'
})

const aiLastRunLabel = computed(() =>
  formatUnixTime(aiAutomation.value?.status.last_run_at),
)

const aiTriggerReasonValue = computed(() => {
  const overview = aiAutomation.value
  if (overview?.status.last_trigger_reason) {
    return aiTriggerReasonLabel(overview.status.last_trigger_reason)
  }
  if (overview?.unavailable_reason) {
    return aiTriggerReasonLabel(overview.unavailable_reason)
  }
  return '暂无触发'
})

const aiRunCycleValue = computed(() => {
  const overview = aiAutomation.value
  return `${formatCompactDuration(
    overview?.status.interval_secs,
  )} / 冷却 ${formatCompactDuration(overview?.status.cooldown_secs)}`
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
    {
      label: '触发原因',
      value: aiTriggerReasonValue.value,
    },
    {
      label: '运行周期',
      value: aiRunCycleValue.value,
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
    ...((aiAutomation.value?.trend_windows || []).map((item) =>
      Math.max(
        item.total_events,
        item.blocked_events,
        item.challenged_events,
        item.delayed_events,
      ),
    ) || []),
    1,
  ),
)

const aiTrendWindows = computed(() =>
  (aiAutomation.value?.trend_windows || []).map((window) => ({
    ...window,
    labelText: trendWindowLabel(window.label),
    bars: [
      {
        label: '事件',
        value: window.total_events,
        color: 'bg-blue-500',
      },
      {
        label: '拦截',
        value: window.blocked_events,
        color: 'bg-red-500',
      },
      {
        label: '挑战',
        value: window.challenged_events,
        color: 'bg-amber-500',
      },
      {
        label: '延迟',
        value: window.delayed_events,
        color: 'bg-cyan-500',
      },
    ],
  })),
)

const visibleAiPolicyFeedback = computed(() => {
  const feedback = aiAutomation.value?.recent_policy_feedback || []
  return aiPolicyFeedbackExpanded.value ? feedback : feedback.slice(0, 2)
})

const hiddenAiPolicyFeedbackCount = computed(() =>
  aiPolicyFeedbackExpanded.value
    ? 0
    : Math.max((aiAutomation.value?.recent_policy_feedback.length || 0) - 2, 0),
)

const smoothIoReadPercent = ref(0)
const smoothIoWritePercent = ref(0)
const smoothTotalPackets = ref(0)
const smoothLatencyMicros = ref(0)
let ioRafId: number | null = null

onMounted(() => {
  const animateIo = () => {
    const metrics = dashboard.value?.metrics
    const system = metrics?.system
    const ioRead = system?.process_disk_read_bytes_per_sec || 0
    const ioWrite = system?.process_disk_write_bytes_per_sec || 0

    const calcIoShockPercent = (rate: number) => {
      if (rate <= 0) return 0
      const maxRate = 50 * 1024 * 1024
      const ratio = Math.min(1, rate / maxRate)
      return Math.max(2, Math.pow(ratio, 0.3) * 100)
    }

    const targetRead = calcIoShockPercent(ioRead)
    const targetWrite = calcIoShockPercent(ioWrite)

    // IO 条形平滑插值
    smoothIoReadPercent.value += (targetRead - smoothIoReadPercent.value) * 0.08
    smoothIoWritePercent.value += (targetWrite - smoothIoWritePercent.value) * 0.08

    // 报文和延迟的数字平滑滚动
    const targetPackets = metrics?.total_packets || 0
    const targetLatency = metrics?.average_proxy_latency_micros || 0
    smoothTotalPackets.value += (targetPackets - smoothTotalPackets.value) * 0.08
    smoothLatencyMicros.value += (targetLatency - smoothLatencyMicros.value) * 0.08

    ioRafId = requestAnimationFrame(animateIo)
  }
  ioRafId = requestAnimationFrame(animateIo)
})

onBeforeUnmount(() => {
  if (ioRafId !== null) cancelAnimationFrame(ioRafId)
})

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
      readPercent: smoothIoReadPercent.value,
      writePercent: smoothIoWritePercent.value,
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
  const slowAttackHits =
    (metrics?.slow_attack_idle_timeouts || 0) +
    (metrics?.slow_attack_header_timeouts || 0) +
    (metrics?.slow_attack_body_timeouts || 0) +
    (metrics?.slow_attack_tls_handshake_hits || 0) +
    (metrics?.slow_attack_blocks || 0)
  const droppedStorageEvents =
    (metrics?.sqlite_dropped_security_events || 0) +
    (metrics?.sqlite_dropped_blocked_ips || 0)
  const ipAccessActions =
    (metrics?.l7_ip_access_alerts || 0) +
    (metrics?.l7_ip_access_challenges || 0) +
    (metrics?.l7_ip_access_blocks || 0)
  const ipAccessPasses =
    (metrics?.l7_ip_access_allows || 0) +
    (metrics?.l7_ip_access_verified_passes || 0)

  return [
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
            (l4Overview?.high_risk_buckets || 0) > 0 ? 'text-amber-700' : '',
        },
        {
          label: '丢弃',
          value: formatNumber(l4Overview?.dropped_events || 0),
          class: (l4Overview?.dropped_events || 0) > 0 ? 'text-red-700' : '',
        },
        {
          label: '预算拒绝',
          value: formatNumber(metrics?.l4_bucket_budget_rejections || 0),
          class:
            (metrics?.l4_bucket_budget_rejections || 0) > 0
              ? 'text-red-700'
              : '',
        },
        {
          label: '细粒度',
          value: formatNumber(metrics?.l4_fine_grained_buckets || 0),
        },
        {
          label: '代理降级',
          value: formatNumber(metrics?.trusted_proxy_l4_degrade_actions || 0),
          class:
            (metrics?.trusted_proxy_l4_degrade_actions || 0) > 0
              ? 'text-amber-700'
              : '',
        },
      ],
      summary: '四层限速与过载',
    },
    {
      label: 'L7',
      badge: l7ModeLabel(l7Tuning?.mode),
      type: l7ModeType.value,
      stats: [
        {
          label: '访问策略',
          value: formatNumber(ipAccessActions),
          class: ipAccessActions > 0 ? 'text-amber-700' : '',
        },
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
          label: '策略放行',
          value: formatNumber(ipAccessPasses),
          class: ipAccessPasses > 0 ? 'text-emerald-700' : '',
        },
        {
          label: '慢攻命中',
          value: formatNumber(slowAttackHits),
          class: slowAttackHits > 0 ? 'text-red-700' : '',
        },
      ],
      summary: l7Tuning?.last_adjust_reason || '最近无自动动作',
    },
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
        {
          label: '行为拦截',
          value: formatNumber(metrics?.l7_behavior_blocks || 0),
          class: (metrics?.l7_behavior_blocks || 0) > 0 ? 'text-red-700' : '',
        },
        {
          label: '行为延迟',
          value: formatNumber(metrics?.l7_behavior_delays || 0),
          class: (metrics?.l7_behavior_delays || 0) > 0 ? 'text-amber-700' : '',
        },
      ],
      summary: 'CC 挑战链路',
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
        {
          label: '已存事件',
          value: formatNumber(metrics?.persisted_security_events || 0),
        },
        {
          label: '封禁IP',
          value: formatNumber(metrics?.persisted_blocked_ips || 0),
        },
      ],
      summary: '事件写入与聚合',
    },
  ].map((item) => ({
    ...item,
    primaryStats: item.stats.slice(0, 2),
    secondaryStats: item.stats.slice(2),
  }))
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
      <AdminDashboardPerformanceGrid
        :cards="performanceCards"
        :total-packets="smoothTotalPackets"
        :total-bytes="dashboard?.metrics.total_bytes || 0"
        :total-packet-series="metricsHistory.totalPackets"
        :packet-spark-max="packetSparkMax"
        :latency-value="smoothLatencyMicros"
        :proxy-fail-close-rejections="
          dashboard?.metrics.proxy_fail_close_rejections || 0
        "
        :latency-trend="metricTrends.latency"
        :latency-series="metricsHistory.latency"
        :latency-spark-max="latencySparkMax"
        :success-rate="successRate"
        :proxy-successes="dashboard?.metrics.proxy_successes || 0"
        :proxy-failures="dashboard?.metrics.proxy_failures || 0"
        :success-rate-trend="metricTrends.successRate"
        :proxy-success-percent="proxySuccessPercent"
        :blocked-packets="dashboard?.metrics.blocked_packets || 0"
        :blocked-l4="dashboard?.metrics.blocked_l4 || 0"
        :blocked-l7="dashboard?.metrics.blocked_l7 || 0"
        :blocked-trend="metricTrends.blocked"
        :format-number="formatNumber"
        :format-bytes="formatBytes"
        :format-latency="formatLatencyEnglish"
      />

      <section class="grid gap-3 xl:grid transition-[grid-template-columns] duration-500 ease-in-out" :class="trafficOverviewGridClass">
        <AdminEventMapSection
          :traffic-map="trafficMap"
          :traffic-events="trafficEvents"
          :map-mode="trafficMapMode"
          @update:map-mode="trafficMapMode = $event"
        />

        <AdminNetworkPerformancePanel
          :rx-rate="dashboard?.metrics.system?.network_rx_bytes_per_sec || 0"
          :tx-rate="dashboard?.metrics.system?.network_tx_bytes_per_sec || 0"
          :rx-total="dashboard?.metrics.system?.network_rx_total_bytes || 0"
          :tx-total="dashboard?.metrics.system?.network_tx_total_bytes || 0"
          :timestamps="networkHistory.timestamps"
          :rx-series="networkHistory.rx"
          :tx-series="networkHistory.tx"
          :map-mode="trafficMapMode"
        />
      </section>

      <section
        class="grid gap-3 xl:grid-cols-[minmax(0,0.92fr)_minmax(430px,1.08fr)]"
      >
        <AdminDashboardDefenseMatrix :items="defenseMatrix" />

        <AdminDashboardAiAutomationPanel
          :overview="aiAutomation"
          :status-label="aiAutomationStatusLabel"
          :status-type="aiAutomationStatusType"
          :last-run-label="aiLastRunLabel"
          :stats="aiAutomationStats"
          :pressure-rows="aiAutomationPressureRows"
          :trend-windows="aiTrendWindows"
          :trend-max="aiTrendMax"
          :visible-policy-feedback="visibleAiPolicyFeedback"
          :hidden-policy-feedback-count="hiddenAiPolicyFeedbackCount"
          :policy-feedback-expanded="aiPolicyFeedbackExpanded"
          :provider-label="providerLabel"
          :pressure-label="pressureLabel"
          :format-percent="formatPercent"
          :clamp-percent="clampPercent"
          :format-number="formatNumber"
          :format-policy-time="formatPolicyTime"
          :ai-policy-title="aiPolicyTitle"
          :ai-policy-detail-line="aiPolicyDetailLine"
          :ai-policy-status-label="aiPolicyStatusLabel"
          @update:policy-feedback-expanded="
            aiPolicyFeedbackExpanded = $event
          "
        />
      </section>
    </div>
  </AppLayout>
</template>
