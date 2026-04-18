<script setup lang="ts">
import { computed, defineAsyncComponent } from 'vue'
import { RouterLink } from 'vue-router'
import AppLayout from '@/app/layout/AppLayout.vue'
import MetricWidget from '@/shared/ui/MetricWidget.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import {
  Activity,
  Database,
  Gauge,
  RefreshCw,
  Shield,
  ShieldCheck,
} from 'lucide-vue-next'
import { useAdminDashboardPage } from '@/features/dashboard/composables/useAdminDashboardPage'

const AdminEventMapSection = defineAsyncComponent(
  () => import('@/features/dashboard/components/AdminEventMapSection.vue'),
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
  formatBytes,
  formatNumber,
  formatLatency,
  successRate,
  requestStatus,
  adaptiveRuntime,
  adaptiveManaged,
  adaptivePressureType,
  runtimePressureType,
  storageInsights,
  storageDegradedReasons,
  formatShortTime,
  hotspotEventsRoute,
  summaryEventsRoute,
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

const runtimeDegraded = computed(
  () =>
    Boolean(dashboard.value?.metrics.runtime_pressure_drop_delay) ||
    Boolean(dashboard.value?.metrics.runtime_pressure_trim_event_persistence),
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

const overallStatus = computed(() => {
  if (!dashboard.value) {
    return {
      label: '等待数据',
      type: 'muted' as const,
      title: '边界态势初始化中',
      detail: '正在读取网关运行状态',
      tone: 'border-slate-200 bg-white',
    }
  }

  if (!dashboard.value.health.upstream_healthy) {
    return {
      label: '上游异常',
      type: 'error' as const,
      title: '上游代理不可用',
      detail: dashboard.value.health.upstream_last_error || '最近健康检查失败',
      tone: 'border-red-200 bg-red-50/70',
    }
  }

  const pressure = dashboard.value.metrics.runtime_pressure_level
  if (pressure === 'attack' || l4OverloadLevel.value === 'critical') {
    return {
      label: '攻击态',
      type: 'error' as const,
      title: '攻击压力已触发',
      detail: '运行时正在收紧处置策略',
      tone: 'border-red-200 bg-red-50/70',
    }
  }

  if (
    pressure === 'high' ||
    pressure === 'elevated' ||
    runtimeDegraded.value ||
    l4OverloadLevel.value === 'high' ||
    storageDegradedReasons.value.length > 0
  ) {
    return {
      label: '受压',
      type: 'warning' as const,
      title: '系统处于受压态',
      detail: runtimeDegraded.value ? '已启用运行时降级' : '关键指标高于常态',
      tone: 'border-amber-200 bg-amber-50/70',
    }
  }

  return {
    label: '正常',
    type: 'success' as const,
    title: '边界态势稳定',
    detail:
      ccTotal.value > 0 ? '防护有命中，主链运行正常' : '常态观测，未触发降级',
    tone: 'border-emerald-200 bg-emerald-50/70',
  }
})

const runtimeActionText = computed(() => {
  if (dashboard.value?.metrics.runtime_pressure_drop_delay) return '收紧 delay'
  if (dashboard.value?.metrics.runtime_pressure_trim_event_persistence)
    return '裁剪持久化'
  return '未降级'
})

const performanceCards = computed(() => [
  {
    label: 'CPU',
    value: `${(dashboard.value?.metrics.system?.cpu_usage_percent || 0).toFixed(1)}%`,
    hint: `${formatNumber(
      dashboard.value?.metrics.system?.cpu_core_count ||
        l7Stats.value?.auto_tuning.detected_cpu_cores ||
        0,
    )} cores`,
  },
  {
    label: '内存',
    value: `${(dashboard.value?.metrics.system?.memory_usage_percent || 0).toFixed(1)}%`,
    hint: `${formatBytes(
      dashboard.value?.metrics.system?.memory_used_bytes || 0,
    )} / ${formatBytes(dashboard.value?.metrics.system?.memory_total_bytes || 0)}`,
  },
  {
    label: '网络',
    value: `↓ ${formatBytes(
      dashboard.value?.metrics.system?.network_rx_bytes_per_sec || 0,
    )}/s`,
    hint: `↑ ${formatBytes(
      dashboard.value?.metrics.system?.network_tx_bytes_per_sec || 0,
    )}/s`,
  },
  {
    label: 'IO',
    value: `读 ${formatBytes(
      dashboard.value?.metrics.system?.process_disk_read_bytes_per_sec || 0,
    )}/s`,
    hint: `写 ${formatBytes(
      dashboard.value?.metrics.system?.process_disk_write_bytes_per_sec || 0,
    )}/s`,
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

    <div v-if="loading" class="flex h-72 items-center justify-center">
      <div
        class="flex flex-col items-center gap-3 rounded-xl border border-slate-200 bg-white px-4 py-5 shadow-sm"
      >
        <RefreshCw class="animate-spin text-blue-700" :size="30" />
        <p class="text-sm text-slate-500">正在载入边界态势</p>
      </div>
    </div>

    <div v-else class="space-y-3">
      <section
        class="grid gap-3 rounded-xl border p-3 shadow-sm xl:grid-cols-[minmax(260px,1fr)_minmax(520px,1.6fr)]"
        :class="overallStatus.tone"
      >
        <div class="flex min-w-0 items-center gap-3">
          <div
            class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-white/80 text-blue-700 shadow-sm"
          >
            <ShieldCheck :size="21" />
          </div>
          <div class="min-w-0">
            <div class="flex flex-wrap items-center gap-2">
              <h3 class="text-base font-semibold text-slate-950">
                {{ overallStatus.title }}
              </h3>
              <StatusBadge
                :text="overallStatus.label"
                :type="overallStatus.type"
                compact
              />
            </div>
            <p
              class="mt-1 truncate text-xs text-slate-600"
              :title="overallStatus.detail"
            >
              {{ overallStatus.detail }}
            </p>
          </div>
        </div>

        <div
          class="grid grid-cols-2 gap-2 text-xs text-slate-600 md:grid-cols-4"
        >
          <div
            v-for="card in performanceCards"
            :key="card.label"
            class="min-w-0 rounded-lg border border-white/70 bg-white/70 px-3 py-2"
          >
            <div class="flex items-center justify-between gap-2">
              <p class="font-medium text-slate-500">{{ card.label }}</p>
              <span class="h-1.5 w-1.5 rounded-full bg-slate-300"></span>
            </div>
            <p
              class="mt-1 truncate text-base font-semibold text-slate-950"
              :title="card.value"
            >
              {{ card.value }}
            </p>
            <p
              class="mt-0.5 truncate text-[11px] text-slate-500"
              :title="card.hint"
            >
              {{ card.hint }}
            </p>
          </div>
        </div>
      </section>

      <section class="grid grid-cols-2 gap-3 xl:grid-cols-4">
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
        <MetricWidget
          label="代理成功率"
          :value="successRate"
          :hint="`成功 ${formatNumber(dashboard?.metrics.proxy_successes || 0)} / 失败 ${formatNumber(dashboard?.metrics.proxy_failures || 0)}`"
          :icon="Database"
        />
      </section>

      <section
        class="grid gap-3 xl:grid-cols-[minmax(0,1.55fr)_minmax(360px,0.95fr)]"
      >
        <AdminEventMapSection
          :traffic-map="trafficMap"
          :traffic-events="trafficEvents"
        />

        <div class="rounded-xl border border-slate-200 bg-white p-3 shadow-sm">
          <div class="flex items-center justify-between gap-3">
            <div>
              <h3 class="text-sm font-semibold text-slate-900">当前关注</h3>
              <p class="mt-0.5 text-xs text-slate-500">异常、压力与处置入口</p>
            </div>
            <StatusBadge
              :text="overallStatus.label"
              :type="overallStatus.type"
              compact
            />
          </div>

          <div class="mt-3 divide-y divide-slate-100">
            <div class="grid grid-cols-[5rem_1fr_auto] items-center gap-3 py-2">
              <p class="text-xs text-slate-500">运行压力</p>
              <div class="min-w-0">
                <p class="truncate text-sm font-semibold text-slate-900">
                  {{ runtimeActionText }}
                </p>
                <p class="mt-0.5 text-xs text-slate-500">
                  队列
                  {{
                    formatNumber(
                      dashboard?.metrics
                        .runtime_pressure_storage_queue_percent || 0,
                    )
                  }}%
                </p>
              </div>
              <StatusBadge
                :text="dashboard?.metrics.runtime_pressure_level || 'normal'"
                :type="runtimePressureType"
                compact
              />
            </div>

            <div class="grid grid-cols-[5rem_1fr_auto] items-center gap-3 py-2">
              <p class="text-xs text-slate-500">存储退化</p>
              <div class="min-w-0">
                <p class="truncate text-sm font-semibold text-slate-900">
                  热点
                  {{ formatNumber(storageInsights.hotspot_sources.length) }}
                  / 长尾
                  {{ formatNumber(storageInsights.long_tail_event_count) }}
                </p>
                <p class="mt-0.5 truncate text-xs text-slate-500">
                  聚合 {{ formatNumber(storageInsights.active_bucket_count) }}
                  桶 /
                  {{ formatNumber(storageInsights.active_event_count) }} 事件
                </p>
              </div>
              <RouterLink
                :to="summaryEventsRoute"
                class="rounded-md border border-slate-200 px-2 py-1 text-xs text-slate-600 transition hover:border-blue-300 hover:text-blue-700"
              >
                摘要
              </RouterLink>
            </div>

            <div class="grid grid-cols-[5rem_1fr_auto] items-center gap-3 py-2">
              <p class="text-xs text-slate-500">CC 防护</p>
              <div class="min-w-0">
                <p class="truncate text-sm font-semibold text-slate-900">
                  挑战
                  {{ formatNumber(dashboard?.metrics.l7_cc_challenges || 0) }}
                  / 拦截
                  {{ formatNumber(dashboard?.metrics.l7_cc_blocks || 0) }}
                </p>
                <p class="mt-0.5 text-xs text-slate-500">
                  延迟
                  {{ formatNumber(dashboard?.metrics.l7_cc_delays || 0) }}
                  / 放行
                  {{
                    formatNumber(dashboard?.metrics.l7_cc_verified_passes || 0)
                  }}
                </p>
              </div>
              <StatusBadge
                :text="ccTotal > 0 ? '活跃' : '无命中'"
                :type="ccTotal > 0 ? 'warning' : 'muted'"
                compact
              />
            </div>

            <div class="grid grid-cols-[5rem_1fr_auto] items-center gap-3 py-2">
              <p class="text-xs text-slate-500">自适应</p>
              <div class="min-w-0">
                <p class="truncate text-sm font-semibold text-slate-900">
                  {{
                    adaptiveManaged && adaptiveRuntime
                      ? `${adaptiveRuntime.mode} / ${adaptiveRuntime.goal}`
                      : '未托管'
                  }}
                </p>
                <p class="mt-0.5 truncate text-xs text-slate-500">
                  {{
                    adaptiveRuntime?.reasons?.[0] || '按当前运行状态保持策略'
                  }}
                </p>
              </div>
              <StatusBadge
                :text="adaptiveRuntime?.system_pressure || 'normal'"
                :type="adaptivePressureType"
                compact
              />
            </div>

            <RouterLink
              v-if="storageInsights.hotspot_sources.length"
              :to="
                hotspotEventsRoute(
                  storageInsights.hotspot_sources[0].source_ip,
                  storageInsights.hotspot_sources[0].route,
                  storageInsights.hotspot_sources[0].time_window_start,
                  storageInsights.hotspot_sources[0].time_window_end,
                )
              "
              class="mt-3 block rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 transition hover:border-amber-300"
            >
              <div class="flex items-center justify-between gap-3">
                <p class="truncate text-sm font-semibold text-slate-900">
                  {{ storageInsights.hotspot_sources[0].source_ip }}
                </p>
                <p class="text-xs text-amber-700">
                  {{ formatNumber(storageInsights.hotspot_sources[0].count) }}
                  次
                </p>
              </div>
              <p class="mt-1 truncate text-xs text-amber-700/80">
                {{ storageInsights.hotspot_sources[0].action }} ·
                {{ storageInsights.hotspot_sources[0].route || '无路由' }} ·
                {{
                  formatShortTime(
                    storageInsights.hotspot_sources[0].time_window_start,
                  )
                }}
              </p>
            </RouterLink>
          </div>
        </div>
      </section>

      <section class="grid grid-cols-1 gap-3 lg:grid-cols-2 xl:grid-cols-4">
        <div class="rounded-xl border border-slate-200 bg-white p-3 shadow-sm">
          <div class="flex items-center justify-between gap-3">
            <p class="text-sm font-semibold text-slate-900">CC 防护</p>
            <StatusBadge
              :text="ccTotal > 0 ? '防护活跃' : '暂无命中'"
              :type="ccTotal > 0 ? 'warning' : 'muted'"
              compact
            />
          </div>
          <div class="mt-2 grid grid-cols-2 gap-x-3 gap-y-2 text-sm">
            <div>
              <p class="text-xs text-slate-500">挑战 / 硬拦截</p>
              <p class="font-semibold text-slate-900">
                {{ formatNumber(dashboard?.metrics.l7_cc_challenges || 0) }}
                /
                {{ formatNumber(dashboard?.metrics.l7_cc_blocks || 0) }}
              </p>
            </div>
            <div>
              <p class="text-xs text-slate-500">延迟 / 放行</p>
              <p class="font-semibold text-slate-900">
                {{ formatNumber(dashboard?.metrics.l7_cc_delays || 0) }}
                /
                {{
                  formatNumber(dashboard?.metrics.l7_cc_verified_passes || 0)
                }}
              </p>
            </div>
          </div>
        </div>

        <div class="rounded-xl border border-slate-200 bg-white p-3 shadow-sm">
          <div class="flex items-center justify-between gap-3">
            <p class="text-sm font-semibold text-slate-900">L7 自动调优</p>
            <StatusBadge
              :text="l7Stats?.auto_tuning.mode || 'off'"
              :type="l7ModeType"
              compact
            />
          </div>
          <div class="mt-2 grid grid-cols-2 gap-x-3 gap-y-2 text-sm">
            <div>
              <p class="text-xs text-slate-500">控制器状态</p>
              <p class="truncate font-semibold text-slate-900">
                {{ l7Stats?.auto_tuning.controller_state || 'unknown' }}
              </p>
            </div>
            <div>
              <p class="text-xs text-slate-500">最近动作</p>
              <p
                class="truncate font-semibold text-slate-900"
                :title="l7Stats?.auto_tuning.last_adjust_reason || ''"
              >
                {{ l7Stats?.auto_tuning.last_adjust_reason || 'none' }}
              </p>
            </div>
            <div
              :class="`rounded-md border px-2 py-1.5 ${autoStateStyles[tlsTimeoutState]}`"
            >
              <p class="text-xs text-slate-500">握手超时率</p>
              <p class="font-semibold text-slate-900">
                {{
                  (
                    l7Stats?.auto_tuning
                      .last_observed_tls_handshake_timeout_rate_percent || 0
                  ).toFixed(2)
                }}%
              </p>
            </div>
            <div
              :class="`rounded-md border px-2 py-1.5 ${autoStateStyles[bucketRejectState]}`"
            >
              <p class="text-xs text-slate-500">预算拒绝率</p>
              <p class="font-semibold text-slate-900">
                {{
                  (
                    l7Stats?.auto_tuning
                      .last_observed_bucket_reject_rate_percent || 0
                  ).toFixed(2)
                }}%
              </p>
            </div>
          </div>
        </div>

        <div class="rounded-xl border border-slate-200 bg-white p-3 shadow-sm">
          <div class="flex items-center justify-between gap-3">
            <p class="text-sm font-semibold text-slate-900">L4 自动防护</p>
            <StatusBadge
              :text="l4OverloadLevel"
              :type="l4OverloadType"
              compact
            />
          </div>
          <div class="mt-2 grid grid-cols-2 gap-x-3 gap-y-2 text-sm">
            <div>
              <p class="text-xs text-slate-500">Bucket 总数</p>
              <p class="font-semibold text-slate-900">
                {{ formatNumber(l4Stats?.behavior.overview.bucket_count || 0) }}
              </p>
            </div>
            <div>
              <p class="text-xs text-slate-500">高风险 Bucket</p>
              <p class="font-semibold text-slate-900">
                {{
                  formatNumber(
                    l4Stats?.behavior.overview.high_risk_buckets || 0,
                  )
                }}
              </p>
            </div>
            <div>
              <p class="text-xs text-slate-500">事件丢弃</p>
              <p class="font-semibold text-slate-900">
                {{
                  formatNumber(l4Stats?.behavior.overview.dropped_events || 0)
                }}
              </p>
            </div>
            <div>
              <p class="text-xs text-slate-500">预算拒绝累计</p>
              <p class="font-semibold text-slate-900">
                {{
                  formatNumber(
                    dashboard?.metrics.l4_bucket_budget_rejections || 0,
                  )
                }}
              </p>
            </div>
          </div>
        </div>

        <div class="rounded-xl border border-slate-200 bg-white p-3 shadow-sm">
          <div class="flex items-center justify-between gap-3">
            <p class="text-sm font-semibold text-slate-900">存储与代理</p>
            <StatusBadge
              :text="dashboard?.metrics.sqlite_enabled ? '持久化' : '未连接'"
              :type="dashboard?.metrics.sqlite_enabled ? 'success' : 'muted'"
              compact
            />
          </div>
          <div class="mt-2 grid grid-cols-2 gap-x-3 gap-y-2 text-sm">
            <div>
              <p class="text-xs text-slate-500">代理成功 / 失败</p>
              <p class="font-semibold text-slate-900">
                {{ formatNumber(dashboard?.metrics.proxy_successes || 0) }}
                /
                {{ formatNumber(dashboard?.metrics.proxy_failures || 0) }}
              </p>
            </div>
            <div>
              <p class="text-xs text-slate-500">失败关闭</p>
              <p class="font-semibold text-slate-900">
                {{
                  formatNumber(
                    dashboard?.metrics.proxy_fail_close_rejections || 0,
                  )
                }}
              </p>
            </div>
            <div>
              <p class="text-xs text-slate-500">聚合事件</p>
              <p class="font-semibold text-slate-900">
                {{ formatNumber(storageInsights.active_event_count) }}
              </p>
            </div>
            <div>
              <p class="text-xs text-slate-500">长尾事件</p>
              <p class="font-semibold text-slate-900">
                {{ formatNumber(storageInsights.long_tail_event_count) }}
              </p>
            </div>
          </div>
        </div>
      </section>
    </div>
  </AppLayout>
</template>
