<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { fetchBlockedIps, fetchHealth, fetchMetrics, fetchRulesList, fetchSecurityEvents } from '../lib/api'
import type { DashboardPayload, SecurityEventsResponse, BlockedIpsResponse, SecurityEventItem } from '../lib/types'
import AppLayout from '../components/layout/AppLayout.vue'
import MetricWidget from '../components/ui/MetricWidget.vue'
import StatusBadge from '../components/ui/StatusBadge.vue'
import CyberCard from '../components/ui/CyberCard.vue'
import { useFormatters } from '../composables/useFormatters'
import { Activity, Database, Gauge, RefreshCw, Shield, ArrowUpRight } from 'lucide-vue-next'

const dashboard = ref<DashboardPayload | null>(null)
const loading = ref(true)
const refreshing = ref(false)
const error = ref('')
const lastUpdated = ref<number | null>(null)
const refreshTimer = ref<number | null>(null)

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

const { formatBytes, formatNumber, formatLatency, formatTimestamp } = useFormatters()

const urlLikePattern = /^(localhost|\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d+)?(?:[/?#]|$)/i

const formatSiteLabel = (value: string | null | undefined): string => {
  const raw = value?.trim()
  if (!raw) return ''

  const hasProtocol = /^[a-z][a-z\d+.-]*:\/\//i.test(raw)
  const looksLikeUrl = hasProtocol || urlLikePattern.test(raw)
  if (!looksLikeUrl) return raw

  try {
    const parsed = new URL(hasProtocol ? raw : `https://${raw}`)
    return hasProtocol ? `${parsed.protocol}//${parsed.hostname}` : parsed.hostname
  } catch {
    return raw
      .replace(/^([a-z][a-z\d+.-]*:\/\/[^/:?#]+).*/i, '$1')
      .replace(/^([^/:?#]+).*/i, '$1')
  }
}

const eventSiteLabel = (event: SecurityEventItem): string =>
  formatSiteLabel(event.provider_site_name) || formatSiteLabel(event.provider_site_domain)

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
  return '等待首次同步'
})

const fetchData = async (showLoader = false) => {
  if (showLoader) loading.value = true
  refreshing.value = true
  try {
    const [health, metrics, rules, events, blockedIps] = await Promise.all([
      fetchHealth(),
      fetchMetrics(),
      fetchRulesList(),
      fetchSecurityEvents({ limit: 8, sort_direction: 'desc', sort_by: 'created_at' }),
      fetchBlockedIps({ limit: 8, active_only: true, sort_direction: 'desc', sort_by: 'blocked_at' }),
    ])

    dashboard.value = {
      health,
      metrics,
      rules,
      events: events || emptyEventsResponse(),
      blockedIps: blockedIps || emptyBlockedResponse(),
    }

    pushHistory('totalPackets', metrics.total_packets)
    pushHistory('blockRate', metrics.total_packets ? Number(((metrics.blocked_packets / metrics.total_packets) * 100).toFixed(2)) : 0)
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
  refreshTimer.value = window.setInterval(() => fetchData(), 5000)
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
        <span class="text-xs text-cyber-muted whitespace-nowrap">{{ requestStatus }}</span>
        <button
          @click="fetchData()"
          class="inline-flex items-center gap-2 rounded-full border border-cyber-border bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong disabled:opacity-60"
          :disabled="refreshing"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
          同步
        </button>
      </div>
    </template>

    <div v-if="loading" class="flex h-72 items-center justify-center">
      <div class="flex flex-col items-center gap-4 rounded-2xl border border-cyber-border/60 bg-white px-8 py-10 shadow-sm">
        <RefreshCw class="animate-spin text-cyber-accent-strong" :size="30" />
        <p class="text-sm text-cyber-muted">正在载入边界态势</p>
      </div>
    </div>

    <div v-else class="space-y-8">
      <div
        v-if="error"
        class="rounded-[24px] border border-cyber-error/25 bg-cyber-error/8 px-5 py-4 text-sm text-cyber-error shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

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
          :hint="`四层 ${formatNumber(dashboard?.metrics.blocked_l4 || 0)} / 七层 ${formatNumber(dashboard?.metrics.blocked_l7 || 0)}`"
          :icon="Shield"
          trend="up"
          :series="metricsHistory.blockRate"
        />
        <MetricWidget
          label="平均代理延迟"
          :value="formatLatency(dashboard?.metrics.average_proxy_latency_micros || 0)"
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

      <section class="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <CyberCard title="最新安全事件" sub-title="便于值班人员快速扫读当前威胁态势">
          <div class="space-y-4">
            <div
              v-for="event in dashboard?.events.events.slice(0, 5)"
              :key="event.id"
              class="rounded-[24px] border border-cyber-border/60 bg-white/70 p-4"
            >
              <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div class="flex items-center gap-3">
                  <StatusBadge :text="event.layer.toUpperCase()" :type="event.action === 'block' ? 'error' : 'warning'" />
                  <p class="text-sm font-medium text-stone-900">{{ event.reason }}</p>
                </div>
                <span class="text-xs text-cyber-muted">{{ formatTimestamp(event.created_at) }}</span>
              </div>
              <div class="mt-3 grid gap-2 text-sm text-stone-700 md:grid-cols-2">
                <p>来源地址：{{ event.source_ip }}:{{ event.source_port }}</p>
                <p>目标地址：{{ event.dest_ip }}:{{ event.dest_port }}</p>
                <p>协议：{{ event.protocol }}</p>
                <p>请求：{{ event.http_method || '无' }} {{ event.uri || '' }}</p>
                <p v-if="eventSiteLabel(event)" class="md:col-span-2">
                  归属站点：{{ eventSiteLabel(event) }}
                </p>
              </div>
            </div>
            <p v-if="!dashboard?.events.events.length" class="text-sm text-cyber-muted">暂无安全事件。</p>
          </div>
        </CyberCard>

        <CyberCard title="运行摘要" sub-title="落库、代理与健康检查核心数据">
          <div class="grid gap-4">
            <div class="rounded-[24px] bg-cyber-surface-strong p-4">
              <div class="flex items-center justify-between">
                <p class="text-sm text-cyber-muted">代理结果</p>
                <ArrowUpRight :size="18" class="text-cyber-accent-strong" />
              </div>
              <div class="mt-4 grid grid-cols-2 gap-4">
                <div>
                  <p class="text-xs text-cyber-muted">成功</p>
                  <p class="mt-1 text-2xl font-semibold text-stone-900">{{ formatNumber(dashboard?.metrics.proxy_successes || 0) }}</p>
                </div>
                <div>
                  <p class="text-xs text-cyber-muted">失败</p>
                  <p class="mt-1 text-2xl font-semibold text-cyber-error">{{ formatNumber(dashboard?.metrics.proxy_failures || 0) }}</p>
                </div>
              </div>
            </div>

            <div class="grid gap-4 md:grid-cols-2">
              <div class="rounded-[24px] border border-cyber-border/60 p-4">
                <p class="text-xs text-cyber-muted">健康检查成功</p>
                <p class="mt-2 text-2xl font-semibold text-cyber-success">
                  {{ formatNumber(dashboard?.metrics.upstream_healthcheck_successes || 0) }}
                </p>
              </div>
              <div class="rounded-[24px] border border-cyber-border/60 p-4">
                <p class="text-xs text-cyber-muted">健康检查失败</p>
                <p class="mt-2 text-2xl font-semibold text-cyber-error">
                  {{ formatNumber(dashboard?.metrics.upstream_healthcheck_failures || 0) }}
                </p>
              </div>
            </div>

            <div class="rounded-[24px] border border-cyber-border/60 p-4">
              <p class="text-xs text-cyber-muted">本地数据库状态</p>
              <div class="mt-3 flex items-center justify-between">
                <p class="text-lg font-semibold text-stone-900">
                  {{ dashboard?.metrics.sqlite_enabled ? '已启用' : '未启用' }}
                </p>
                <StatusBadge :text="dashboard?.metrics.sqlite_enabled ? '持久化可用' : '未连接'" :type="dashboard?.metrics.sqlite_enabled ? 'success' : 'muted'" />
              </div>
            </div>
          </div>
        </CyberCard>
      </section>
    </div>
  </AppLayout>
</template>
