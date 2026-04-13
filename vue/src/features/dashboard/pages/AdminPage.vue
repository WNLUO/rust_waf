<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { fetchBlockedIps, fetchSecurityEvents } from '@/shared/api/events'
import { fetchRulesList } from '@/shared/api/rules'
import { fetchHealth, fetchMetrics } from '@/shared/api/system'
import type {
  DashboardPayload,
  SecurityEventsResponse,
  BlockedIpsResponse,
} from '@/shared/types'
import AppLayout from '@/app/layout/AppLayout.vue'
import MetricWidget from '@/shared/ui/MetricWidget.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import CyberCard from '@/shared/ui/CyberCard.vue'
import AdminEventMapSection from '@/features/dashboard/components/AdminEventMapSection.vue'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
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
const loading = ref(true)
const refreshing = ref(false)
const error = ref('')
const lastUpdated = ref<number | null>(null)
const refreshTimer = ref<number | null>(null)

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
  if (refreshing.value) return '实时同步中...'
  if (lastUpdated.value) {
    return `上次刷新：${new Intl.DateTimeFormat('zh-CN', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).format(new Date(lastUpdated.value))}`
  }
  return '等待首次同步，当前为手动刷新'
})

const fetchData = async (showLoader = false) => {
  if (showLoader) loading.value = true
  refreshing.value = true
  try {
    const [health, metrics, rules, events, blockedIps] = await Promise.all([
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
    ])

    dashboard.value = {
      health,
      metrics,
      rules,
      events: events || emptyEventsResponse(),
      blockedIps: blockedIps || emptyBlockedResponse(),
    }

    pushHistory('totalPackets', metrics.total_packets)
    pushHistory(
      'blockRate',
      metrics.total_packets
        ? Number(
            ((metrics.blocked_packets / metrics.total_packets) * 100).toFixed(
              2,
            ),
          )
        : 0,
    )
    pushHistory('latency', metrics.average_proxy_latency_micros)
    lastUpdated.value = Date.now()
    error.value = ''
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取控制台数据失败'
  } finally {
    if (showLoader) loading.value = false
    refreshing.value = false
  }
}

onMounted(() => {
  fetchData(true)
})

onBeforeUnmount(() => {
  if (refreshTimer.value) {
    clearInterval(refreshTimer.value)
  }
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
        <MetricWidget
          label="启用规则"
          :value="dashboard?.metrics.active_rules || 0"
          :hint="`规则总数 ${formatNumber(dashboard?.rules.rules.length || 0)} / 成功率 ${successRate}`"
          :icon="Database"
        />
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

      <section class="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        <AdminEventMapSection
          :metrics="dashboard?.metrics"
          :events="dashboard?.events.events || []"
        />

        <CyberCard title="运行摘要" sub-title="落库、代理与健康检查核心数据">
          <div class="grid gap-4">
            <div class="rounded-xl border border-amber-200 bg-amber-50/70 p-4">
              <div class="flex items-center justify-between">
                <p class="text-sm text-amber-700">L7 CC 防护摘要</p>
                <StatusBadge
                  :text="
                    (dashboard?.metrics.l7_cc_challenges || 0) +
                      (dashboard?.metrics.l7_cc_blocks || 0) >
                    0
                      ? '近期开启动作'
                      : '暂无处置'
                  "
                  :type="
                    (dashboard?.metrics.l7_cc_challenges || 0) +
                      (dashboard?.metrics.l7_cc_blocks || 0) >
                    0
                      ? 'warning'
                      : 'muted'
                  "
                />
              </div>
              <div class="mt-4 grid grid-cols-2 gap-4 text-sm">
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

            <div class="rounded-xl bg-slate-50 p-4">
              <div class="flex items-center justify-between">
                <p class="text-sm text-slate-500">代理结果</p>
                <ArrowUpRight :size="18" class="text-blue-700" />
              </div>
              <div class="mt-4 grid grid-cols-2 gap-4">
                <div>
                  <p class="text-xs text-slate-500">成功</p>
                  <p class="mt-1 text-2xl font-semibold text-stone-900">
                    {{ formatNumber(dashboard?.metrics.proxy_successes || 0) }}
                  </p>
                </div>
                <div>
                  <p class="text-xs text-slate-500">失败</p>
                  <p class="mt-1 text-2xl font-semibold text-red-600">
                    {{ formatNumber(dashboard?.metrics.proxy_failures || 0) }}
                  </p>
                </div>
              </div>
            </div>

            <div class="grid gap-4 md:grid-cols-2">
              <div class="rounded-xl border border-slate-200 p-4">
                <p class="text-xs text-slate-500">健康检查成功</p>
                <p class="mt-2 text-2xl font-semibold text-emerald-600">
                  {{
                    formatNumber(
                      dashboard?.metrics.upstream_healthcheck_successes || 0,
                    )
                  }}
                </p>
              </div>
              <div class="rounded-xl border border-slate-200 p-4">
                <p class="text-xs text-slate-500">健康检查失败</p>
                <p class="mt-2 text-2xl font-semibold text-red-600">
                  {{
                    formatNumber(
                      dashboard?.metrics.upstream_healthcheck_failures || 0,
                    )
                  }}
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
