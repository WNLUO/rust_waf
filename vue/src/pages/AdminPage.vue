<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  createRule,
  deleteRule,
  fetchBlockedIps,
  fetchHealth,
  fetchMetrics,
  fetchRulesList,
  fetchSecurityEvents,
  markSecurityEventHandled,
  unblockIp,
  updateRule,
} from '../lib/api'
import type {
  DashboardPayload,
  RuleDraft,
  RuleItem,
  SecurityEventItem,
  SecurityEventsResponse,
  BlockedIpsResponse,
} from '../lib/types'
import AppLayout from '../components/layout/AppLayout.vue'
import MetricWidget from '../components/ui/MetricWidget.vue'
import StatusBadge from '../components/ui/StatusBadge.vue'
import CyberCard from '../components/ui/CyberCard.vue'
import { useFormatters } from '../composables/useFormatters'
import {
  Shield,
  Ban,
  Plus,
  Trash2,
  Edit3,
  Save,
  X,
  RefreshCw,
  Database,
  Gauge,
  Radar,
  ArrowUpRight,
  Activity,
  Copy,
  Check,
  Search,
} from 'lucide-vue-next'

type AdminView = 'overview' | 'rules' | 'events' | 'blocked'

const route = useRoute()
const router = useRouter()
const dashboard = ref<DashboardPayload | null>(null)
const loading = ref(true)
const refreshing = reactive({
  core: false,
  events: false,
  blocked: false,
})
const error = ref('')
const isRuleModalOpen = ref(false)
const lastUpdated = ref<number | null>(null)
const filtersReady = ref(false)
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

const { formatBytes, formatNumber, formatLatency, formatTimestamp, severityLabel, actionLabel, layerLabel, timeRemaining } =
  useFormatters()

const viewPaths: Record<AdminView, string> = {
  overview: '/admin',
  rules: '/admin/rules',
  events: '/admin/events',
  blocked: '/admin/blocked',
}

const viewLabels: Record<AdminView, string> = {
  overview: '总览',
  rules: '规则中心',
  events: '事件记录',
  blocked: '封禁名单',
}

const activeView = computed<AdminView>(() => {
  switch (route.path) {
    case '/admin/rules':
      return 'rules'
    case '/admin/events':
      return 'events'
    case '/admin/blocked':
      return 'blocked'
    default:
      return 'overview'
  }
})

const ruleForm = reactive<RuleDraft>({
  id: '',
  name: '',
  enabled: true,
  layer: 'l7',
  pattern: '',
  action: 'block',
  severity: 'high',
})

const ruleFilters = reactive({
  search: '',
  layer: 'all',
  action: 'all',
  severity: 'all',
  status: 'all',
})

const eventsFilters = reactive({
  layer: 'all',
  action: 'all',
  blocked_only: false,
  handled: 'all' as 'all' | 'handled' | 'unhandled',
  sort_by: 'created_at',
  sort_direction: 'desc' as 'asc' | 'desc',
})

const blockedFilters = reactive({
  active_only: true,
  sort_by: 'blocked_at',
  sort_direction: 'desc' as 'asc' | 'desc',
})

const eventsQueryParams = computed(() => ({
  limit: 8,
  sort_by: eventsFilters.sort_by,
  sort_direction: eventsFilters.sort_direction,
  blocked_only: eventsFilters.blocked_only,
  layer: eventsFilters.layer === 'all' ? undefined : eventsFilters.layer,
  action: eventsFilters.action === 'all' ? undefined : eventsFilters.action,
  handled_only:
    eventsFilters.handled === 'all'
      ? undefined
      : eventsFilters.handled === 'handled'
        ? true
        : false,
}))

const blockedQueryParams = computed(() => ({
  limit: 8,
  active_only: blockedFilters.active_only,
  sort_by: blockedFilters.sort_by,
  sort_direction: blockedFilters.sort_direction,
}))

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

const healthSummary = computed(() => {
  if (!dashboard.value) return '正在读取运行状态'
  return dashboard.value.health.upstream_healthy ? '上游服务连接正常' : '上游服务需要关注'
})

const successRate = computed(() => {
  const metrics = dashboard.value?.metrics
  if (!metrics) return '暂无'
  const total = metrics.proxy_successes + metrics.proxy_failures
  if (total === 0) return '暂无'
  return `${((metrics.proxy_successes / total) * 100).toFixed(1)}%`
})

const blockRate = computed(() => {
  const metrics = dashboard.value?.metrics
  if (!metrics || metrics.total_packets === 0) return '0%'
  return `${((metrics.blocked_packets / metrics.total_packets) * 100).toFixed(2)}%`
})

const lastPersistedText = computed(() => formatTimestamp(dashboard.value?.metrics.last_persisted_event_at))
const lastRuleUpdateText = computed(() => formatTimestamp(dashboard.value?.metrics.last_rule_update_at))

const overviewMoments = computed(() => {
  if (!dashboard.value) return []
  return [
    {
      title: '最近持久化',
      value: lastPersistedText.value,
      desc: `已落库事件 ${formatNumber(dashboard.value.metrics.persisted_security_events)}`,
    },
    {
      title: '规则更新时间',
      value: lastRuleUpdateText.value,
      desc: `当前启用规则 ${formatNumber(dashboard.value.metrics.active_rules)}`,
    },
    {
      title: '封禁名单规模',
      value: formatNumber(dashboard.value.blockedIps.total),
      desc: `持久化封禁 ${formatNumber(dashboard.value.metrics.persisted_blocked_ips)}`,
    },
  ]
})

const requestStatus = computed(() => {
  if (refreshing.core || refreshing.events || refreshing.blocked) return '实时同步中...'
  if (lastUpdated.value) {
    return `上次刷新：${new Intl.DateTimeFormat('zh-CN', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).format(new Date(lastUpdated.value))}`
  }
  return '等待首次同步'
})

const filteredRules = computed(() => {
  const rules = dashboard.value?.rules.rules ?? []
  return rules.filter((rule) => {
    if (ruleFilters.layer !== 'all' && rule.layer !== ruleFilters.layer) return false
    if (ruleFilters.action !== 'all' && rule.action !== ruleFilters.action) return false
    if (ruleFilters.severity !== 'all' && rule.severity !== ruleFilters.severity) return false
    if (ruleFilters.status !== 'all') {
      const shouldEnable = ruleFilters.status === 'enabled'
      if (rule.enabled !== shouldEnable) return false
    }
    if (ruleFilters.search) {
      const keyword = ruleFilters.search.trim().toLowerCase()
      if (
        !rule.name.toLowerCase().includes(keyword) &&
        !rule.id.toLowerCase().includes(keyword) &&
        !rule.pattern.toLowerCase().includes(keyword)
      ) {
        return false
      }
    }
    return true
  })
})

const refreshCore = async (showLoader = false) => {
  if (showLoader) loading.value = true
  refreshing.core = true
  try {
    const [health, metrics, rules] = await Promise.all([fetchHealth(), fetchMetrics(), fetchRulesList()])
    const existingEvents = dashboard.value?.events ?? emptyEventsResponse()
    const existingBlocked = dashboard.value?.blockedIps ?? emptyBlockedResponse()
    dashboard.value = {
      health,
      metrics,
      events: existingEvents,
      blockedIps: existingBlocked,
      rules,
    }
    pushHistory('totalPackets', metrics.total_packets)
    const rate = metrics.total_packets ? (metrics.blocked_packets / metrics.total_packets) * 100 : 0
    pushHistory('blockRate', Number(rate.toFixed(2)))
    pushHistory('latency', metrics.average_proxy_latency_micros)
    lastUpdated.value = Date.now()
    error.value = ''
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取控制台数据失败'
  } finally {
    if (showLoader) loading.value = false
    refreshing.core = false
  }
}

const refreshEvents = async (suppressSpinner = false) => {
  if (!dashboard.value) return
  if (!suppressSpinner) refreshing.events = true
  try {
    const events = await fetchSecurityEvents(eventsQueryParams.value)
    dashboard.value = { ...dashboard.value, events }
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取事件失败'
  } finally {
    if (!suppressSpinner) refreshing.events = false
  }
}

const refreshBlockedIps = async (suppressSpinner = false) => {
  if (!dashboard.value) return
  if (!suppressSpinner) refreshing.blocked = true
  try {
    const blockedIps = await fetchBlockedIps(blockedQueryParams.value)
    dashboard.value = { ...dashboard.value, blockedIps }
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取封禁名单失败'
  } finally {
    if (!suppressSpinner) refreshing.blocked = false
  }
}

const refreshRules = async () => {
  if (!dashboard.value) return
  try {
    const rules = await fetchRulesList()
    dashboard.value = { ...dashboard.value, rules }
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取规则失败'
  }
}

const fetchData = async (arg?: boolean | Event) => {
  const showLoader = typeof arg === 'boolean' ? arg : false
  await refreshCore(showLoader)
  await Promise.all([refreshEvents(true), refreshBlockedIps(true)])
  filtersReady.value = true
}

onMounted(() => {
  fetchData(true)
  refreshTimer.value = window.setInterval(() => refreshCore(), 5000)
})

onBeforeUnmount(() => {
  if (refreshTimer.value) {
    clearInterval(refreshTimer.value)
  }
})

watch(
  () => ({ ...eventsFilters }),
  () => {
    if (!filtersReady.value) return
    refreshEvents()
  },
  { deep: true },
)

watch(
  () => ({ ...blockedFilters }),
  () => {
    if (!filtersReady.value) return
    refreshBlockedIps()
  },
  { deep: true },
)

const openView = (view: AdminView) => {
  router.push(viewPaths[view])
}

const openCreateRule = () => {
  Object.assign(ruleForm, {
    id: '',
    name: '',
    enabled: true,
    layer: 'l7',
    pattern: '',
    action: 'block',
    severity: 'high',
  })
  isRuleModalOpen.value = true
}

const handleCreateOrUpdateRule = async () => {
  try {
    if (ruleForm.id) {
      await updateRule(ruleForm)
    } else {
      await createRule(ruleForm)
    }
    isRuleModalOpen.value = false
    await refreshRules()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '规则保存失败'
  }
}

const openEditRule = (rule: RuleItem) => {
  Object.assign(ruleForm, {
    id: rule.id,
    name: rule.name,
    enabled: rule.enabled,
    layer: rule.layer,
    pattern: rule.pattern,
    action: rule.action,
    severity: rule.severity,
  })
  isRuleModalOpen.value = true
}

const toggleRuleStatus = async (rule: RuleItem) => {
  try {
    await updateRule({
      ...rule,
      enabled: !rule.enabled,
    })
    await refreshRules()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '更新规则状态失败'
  }
}

const handleDeleteRule = async (id: string) => {
  if (!window.confirm('确认删除这条规则吗？')) return
  try {
    await deleteRule(id)
    await refreshRules()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '规则删除失败'
  }
}

const handleUnblock = async (id: number) => {
  try {
    await unblockIp(id)
    await refreshBlockedIps()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '解除封禁失败'
  }
}

const toggleEventHandled = async (event: SecurityEventItem) => {
  try {
    await markSecurityEventHandled(event.id, !event.handled)
    await refreshEvents()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '更新事件状态失败'
  }
}

const copyToClipboard = async (text: string) => {
  try {
    await navigator.clipboard?.writeText(text)
  } catch {
    // fall back silently
  }
}
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <div class="flex items-center gap-3">
        <span class="text-xs text-cyber-muted whitespace-nowrap">{{ requestStatus }}</span>
        <button
          @click="fetchData"
          class="inline-flex items-center gap-2 rounded-full border border-cyber-border bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong disabled:opacity-60"
          :disabled="refreshing.core"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': refreshing.core }" />
          同步
        </button>
      </div>
    </template>
    <div v-if="loading" class="flex h-72 items-center justify-center">
      <div class="flex flex-col items-center gap-4 rounded-[28px] border border-white/80 bg-white/75 px-8 py-10 shadow-cyber">
        <RefreshCw class="animate-spin text-cyber-accent-strong" :size="30" />
        <p class="text-sm tracking-[0.2em] text-cyber-muted">正在载入边界态势</p>
      </div>
    </div>

    <div v-else class="space-y-8">
      <div
        v-if="error"
        class="rounded-[24px] border border-cyber-error/25 bg-cyber-error/8 px-5 py-4 text-sm text-cyber-error shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

      <section class="grid gap-6 lg:grid-cols-[1.4fr_0.9fr]">
        <div class="rounded-[34px] border border-white/85 bg-[linear-gradient(140deg,rgba(255,250,244,0.92),rgba(244,239,231,0.96))] p-7 shadow-[0_26px_80px_rgba(90,60,30,0.10)]">
          <div class="flex flex-col gap-5 md:flex-row md:items-start md:justify-between">
            <div>
              <p class="text-sm tracking-[0.22em] text-cyber-accent-strong">{{ viewLabels[activeView] }}</p>
              <h2 class="mt-3 font-display text-4xl font-semibold text-stone-900">安全网关运行看板</h2>
              <p class="mt-4 max-w-2xl text-sm leading-7 text-stone-700">
                用更适合中文场景的布局把攻击、规则、封禁和上游健康放在同一张工作台里，便于持续值守和快速处置。
              </p>
            </div>

            <div class="rounded-full border border-white/80 bg-white/70 px-4 py-2 text-xs text-cyber-muted shadow-sm">
              {{ requestStatus }}
            </div>
          </div>

          <div class="mt-8 grid gap-4 md:grid-cols-3">
            <div
              v-for="item in overviewMoments"
              :key="item.title"
              class="rounded-[26px] border border-white/70 bg-white/72 p-5"
            >
              <p class="text-xs tracking-[0.18em] text-cyber-muted">{{ item.title }}</p>
              <p class="mt-3 text-lg font-semibold text-stone-900">{{ item.value }}</p>
              <p class="mt-2 text-sm text-stone-700">{{ item.desc }}</p>
            </div>
          </div>
        </div>

        <CyberCard title="服务健康" :sub-title="healthSummary">
          <div class="space-y-5">
            <div class="flex items-center justify-between rounded-[24px] bg-cyber-surface-strong p-4">
              <div class="flex items-center gap-4">
                <div class="flex h-12 w-12 items-center justify-center rounded-2xl bg-white text-cyber-accent-strong">
                  <Radar :size="22" />
                </div>
                <div>
                  <p class="text-sm text-cyber-muted">上游连接状态</p>
                  <p class="mt-1 text-lg font-semibold text-stone-900">
                    {{ dashboard?.health.status === 'healthy' ? '健康' : '降级' }}
                  </p>
                </div>
              </div>
              <StatusBadge
                :text="dashboard?.health.upstream_healthy ? '正常' : '异常'"
                :type="dashboard?.health.upstream_healthy ? 'success' : 'error'"
              />
            </div>

            <div class="grid grid-cols-2 gap-4">
              <div class="rounded-[22px] border border-cyber-border/60 p-4">
                <p class="text-xs tracking-[0.18em] text-cyber-muted">代理成功率</p>
                <p class="mt-3 text-2xl font-semibold text-cyber-success">{{ successRate }}</p>
              </div>
              <div class="rounded-[22px] border border-cyber-border/60 p-4">
                <p class="text-xs tracking-[0.18em] text-cyber-muted">拦截占比</p>
                <p class="mt-3 text-2xl font-semibold text-cyber-accent-strong">{{ blockRate }}</p>
              </div>
            </div>

            <div class="rounded-[22px] border border-cyber-border/60 bg-white/80 p-4">
              <p class="text-xs tracking-[0.18em] text-cyber-muted">最近检查</p>
              <p class="mt-2 text-sm text-stone-800">{{ formatTimestamp(dashboard?.health.upstream_last_check_at) }}</p>
              <p v-if="dashboard?.health.upstream_last_error" class="mt-3 text-sm leading-6 text-cyber-error">
                最近错误：{{ dashboard.health.upstream_last_error }}
              </p>
              <p v-else class="mt-3 text-sm text-stone-700">最近一次检查未发现上游异常。</p>
            </div>
          </div>
        </CyberCard>
      </section>

      <div class="flex flex-wrap gap-3">
        <button
          v-for="view in (['overview', 'rules', 'events', 'blocked'] as AdminView[])"
          :key="view"
          @click="openView(view)"
          class="rounded-full border px-5 py-2.5 text-sm transition"
          :class="
            activeView === view
              ? 'border-cyber-accent bg-cyber-accent text-white shadow-cyber'
              : 'border-cyber-border bg-white/72 text-cyber-muted hover:border-cyber-accent/40 hover:text-cyber-accent-strong'
          "
        >
          {{ viewLabels[view] }}
        </button>
      </div>

      <section v-if="activeView === 'overview'" class="space-y-6">
        <div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
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
            :hint="`规则总数 ${formatNumber(dashboard?.rules.rules.length || 0)}`"
            :icon="Database"
          />
        </div>

        <div class="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
          <CyberCard title="最新安全事件" sub-title="便于值班人员快速扫读当前威胁态势">
            <div class="space-y-4">
              <div
                v-for="event in dashboard?.events.events.slice(0, 5)"
                :key="event.id"
                class="rounded-[24px] border border-cyber-border/60 bg-white/70 p-4"
              >
                <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                  <div class="flex items-center gap-3">
                    <StatusBadge
                      :text="`${layerLabel(event.layer)} ${actionLabel(event.action)}`"
                      :type="event.action === 'block' ? 'error' : 'warning'"
                    />
                    <p class="text-sm font-medium text-stone-900">{{ event.reason }}</p>
                  </div>
                  <span class="text-xs text-cyber-muted">{{ formatTimestamp(event.created_at) }}</span>
                </div>
                <div class="mt-3 grid gap-2 text-sm text-stone-700 md:grid-cols-2">
                  <p>来源地址：{{ event.source_ip }}:{{ event.source_port }}</p>
                  <p>目标地址：{{ event.dest_ip }}:{{ event.dest_port }}</p>
                  <p>协议：{{ event.protocol }}</p>
                  <p>请求：{{ event.http_method || '无' }} {{ event.uri || '' }}</p>
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
        </div>
      </section>

      <section v-if="activeView === 'rules'" class="space-y-6">
        <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <h2 class="text-2xl font-semibold text-stone-900">规则中心</h2>
            <p class="mt-2 text-sm text-cyber-muted">统一查看和维护四层、七层规则。</p>
          </div>
          <button
            @click="openCreateRule"
            class="inline-flex items-center gap-2 self-start rounded-full bg-cyber-accent px-5 py-3 text-sm font-semibold text-white shadow-cyber transition hover:-translate-y-0.5"
          >
            <Plus :size="16" />
            新建规则
          </button>
        </div>

        <div class="flex flex-wrap gap-3 rounded-[28px] border border-white/70 bg-white/60 p-4">
          <label class="flex flex-1 min-w-[200px] items-center gap-2 rounded-[20px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-cyber-muted">
            <Search :size="14" />
            <input
              v-model="ruleFilters.search"
              type="text"
              class="w-full bg-transparent text-stone-800 outline-none"
              placeholder="搜索名称 / ID / 匹配内容"
            />
          </label>
          <select v-model="ruleFilters.layer" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
            <option value="all">全部层级</option>
            <option value="l4">四层</option>
            <option value="l7">七层</option>
          </select>
          <select v-model="ruleFilters.action" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
            <option value="all">全部动作</option>
            <option value="block">拦截</option>
            <option value="allow">放行</option>
            <option value="alert">告警</option>
            <option value="log">记录</option>
          </select>
          <select v-model="ruleFilters.severity" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
            <option value="all">全部级别</option>
            <option value="low">低</option>
            <option value="medium">中</option>
            <option value="high">高</option>
            <option value="critical">紧急</option>
          </select>
          <select v-model="ruleFilters.status" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
            <option value="all">全部状态</option>
            <option value="enabled">启用</option>
            <option value="disabled">停用</option>
          </select>
        </div>

        <div class="overflow-hidden rounded-[30px] border border-white/80 bg-white/78 shadow-[0_16px_44px_rgba(90,60,30,0.08)]">
          <div class="overflow-x-auto">
            <table class="min-w-full border-collapse text-left">
              <thead class="bg-cyber-surface-strong text-sm text-cyber-muted">
                <tr>
                  <th class="px-6 py-4 font-medium">状态</th>
                  <th class="px-6 py-4 font-medium">规则名称</th>
                  <th class="px-6 py-4 font-medium">层级</th>
                  <th class="px-6 py-4 font-medium">级别</th>
                  <th class="px-6 py-4 font-medium">动作</th>
                  <th class="px-6 py-4 font-medium">匹配内容</th>
                  <th class="px-6 py-4 text-right font-medium">操作</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="rule in filteredRules"
                  :key="rule.id"
                  class="border-t border-cyber-border/50 text-sm text-stone-800 transition hover:bg-[#fff8ef]"
                >
                  <td class="px-6 py-4">
                    <StatusBadge :text="rule.enabled ? '启用' : '停用'" :type="rule.enabled ? 'success' : 'muted'" compact />
                  </td>
                  <td class="px-6 py-4 font-semibold">{{ rule.name }}</td>
                  <td class="px-6 py-4">{{ layerLabel(rule.layer) }}</td>
                  <td class="px-6 py-4">{{ severityLabel(rule.severity) }}</td>
                  <td class="px-6 py-4">{{ actionLabel(rule.action) }}</td>
                  <td class="max-w-[360px] px-6 py-4 font-mono text-xs text-cyber-muted">{{ rule.pattern }}</td>
                  <td class="px-6 py-4">
                    <div class="flex justify-end gap-2">
                      <button
                        @click="openEditRule(rule)"
                        class="inline-flex items-center gap-1 rounded-full border border-cyber-border px-3 py-2 text-xs text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong"
                      >
                        <Edit3 :size="14" />
                        编辑
                      </button>
                      <button
                        @click="toggleRuleStatus(rule)"
                        class="inline-flex items-center gap-1 rounded-full border border-cyber-border px-3 py-2 text-xs text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong"
                      >
                        <Check :size="14" />
                        {{ rule.enabled ? '停用' : '启用' }}
                      </button>
                      <button
                        @click="handleDeleteRule(rule.id)"
                        class="inline-flex items-center gap-1 rounded-full border border-cyber-error/20 px-3 py-2 text-xs text-cyber-error transition hover:bg-cyber-error/8"
                      >
                        <Trash2 :size="14" />
                        删除
                      </button>
                    </div>
                  </td>
                </tr>
                <tr v-if="!dashboard?.rules.rules.length">
                  <td colspan="7" class="px-6 py-10 text-center text-sm text-cyber-muted">当前还没有配置规则。</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section v-if="activeView === 'events'" class="space-y-6">
        <div>
          <h2 class="text-2xl font-semibold text-stone-900">事件记录</h2>
          <p class="mt-2 text-sm text-cyber-muted">展示最近的安全事件，帮助判断攻击来源与处置效果。</p>
        </div>

        <div class="flex flex-wrap gap-3 rounded-[28px] border border-white/70 bg-white/60 p-4">
          <select v-model="eventsFilters.layer" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
            <option value="all">全部层级</option>
            <option value="l4">四层</option>
            <option value="l7">七层</option>
          </select>
          <select v-model="eventsFilters.action" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
            <option value="all">全部动作</option>
            <option value="block">拦截</option>
            <option value="allow">放行</option>
            <option value="alert">告警</option>
            <option value="log">记录</option>
          </select>
          <label class="inline-flex items-center gap-2 rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
            <input v-model="eventsFilters.blocked_only" type="checkbox" class="accent-[var(--color-cyber-accent)]" />
            仅显示拦截
          </label>
          <select v-model="eventsFilters.handled" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
            <option value="all">全部状态</option>
            <option value="unhandled">仅未处理</option>
            <option value="handled">仅已处理</option>
          </select>
          <select v-model="eventsFilters.sort_by" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
            <option value="created_at">时间排序</option>
            <option value="source_ip">按来源 IP</option>
            <option value="dest_port">按目标端口</option>
          </select>
          <select v-model="eventsFilters.sort_direction" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
            <option value="desc">降序</option>
            <option value="asc">升序</option>
          </select>
        </div>

        <div class="grid gap-4">
          <article
            v-for="event in dashboard?.events.events"
            :key="event.id"
            class="rounded-[30px] border border-white/80 bg-white/78 p-6 shadow-[0_14px_40px_rgba(90,60,30,0.07)] transition"
            :class="{ 'opacity-65': event.handled }"
          >
            <div class="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
              <div class="space-y-3">
                <div class="flex flex-wrap items-center gap-3">
                  <StatusBadge
                    :text="layerLabel(event.layer)"
                    :type="event.layer === 'l7' ? 'info' : 'warning'"
                  />
                  <StatusBadge
                    :text="actionLabel(event.action)"
                    :type="event.action === 'block' ? 'error' : 'warning'"
                  />
                  <StatusBadge v-if="event.handled" text="已处理" type="success" compact />
                  <span class="text-sm font-medium text-stone-900">{{ event.reason }}</span>
                </div>
                <div class="grid gap-2 text-sm text-stone-700 md:grid-cols-2">
                  <p>来源：{{ event.source_ip }}:{{ event.source_port }}</p>
                  <p>目标：{{ event.dest_ip }}:{{ event.dest_port }}</p>
                  <p>协议：{{ event.protocol }}</p>
                  <p>请求方法：{{ event.http_method || '无' }}</p>
                  <p class="md:col-span-2">访问路径：{{ event.uri || '无' }}</p>
                </div>
              </div>
              <div class="rounded-[20px] bg-cyber-surface-strong px-4 py-3 text-sm text-cyber-muted">
                {{ formatTimestamp(event.created_at) }}
              </div>
            </div>
            <div class="mt-4 flex flex-wrap gap-3 text-xs text-cyber-muted">
              <button
                class="inline-flex items-center gap-1 rounded-full border border-cyber-border/60 px-3 py-1 text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong"
                @click="copyToClipboard(`${event.source_ip}`)"
              >
                <Copy :size="12" />
                复制来源 IP
              </button>
              <button
                class="inline-flex items-center gap-1 rounded-full border border-cyber-border/60 px-3 py-1 text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong"
                @click="copyToClipboard(event.uri || '')"
              >
                <Copy :size="12" />
                复制 URL
              </button>
              <button
                class="inline-flex items-center gap-1 rounded-full border border-cyber-border/60 px-3 py-1 text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong"
                @click="toggleEventHandled(event)"
              >
                <Check :size="12" />
                {{ event.handled ? '标记未处理' : '标记已处理' }}
              </button>
            </div>
          </article>
          <p v-if="!dashboard?.events.events.length" class="text-sm text-cyber-muted">当前没有可显示的安全事件。</p>
        </div>
      </section>

      <section v-if="activeView === 'blocked'" class="space-y-6">
        <div>
          <h2 class="text-2xl font-semibold text-stone-900">封禁名单</h2>
          <p class="mt-2 text-sm text-cyber-muted">这里集中展示当前封禁的来源地址与封禁原因。</p>
        </div>

        <div class="flex flex-wrap gap-3 rounded-[28px] border border-white/70 bg-white/60 p-4">
          <label class="inline-flex items-center gap-2 rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
            <input v-model="blockedFilters.active_only" type="checkbox" class="accent-[var(--color-cyber-accent)]" />
            仅显示有效封禁
          </label>
          <select v-model="blockedFilters.sort_by" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
            <option value="blocked_at">按封禁时间</option>
            <option value="expires_at">按到期时间</option>
            <option value="ip">按 IP</option>
          </select>
          <select v-model="blockedFilters.sort_direction" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
            <option value="desc">降序</option>
            <option value="asc">升序</option>
          </select>
        </div>

        <div class="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
          <article
            v-for="ip in dashboard?.blockedIps.blocked_ips"
            :key="ip.id"
            class="rounded-[30px] border border-white/80 bg-white/78 p-6 shadow-[0_14px_40px_rgba(90,60,30,0.07)]"
          >
            <div class="flex items-start justify-between gap-4">
              <div class="flex h-12 w-12 items-center justify-center rounded-2xl bg-cyber-error/10 text-cyber-error">
                <Ban :size="22" />
              </div>
              <button
                @click="handleUnblock(ip.id)"
                class="rounded-full border border-cyber-success/20 px-3 py-2 text-xs text-cyber-success transition hover:bg-cyber-success/10"
              >
                解除封禁
              </button>
            </div>

            <h3 class="mt-5 font-mono text-2xl font-semibold text-stone-900">{{ ip.ip }}</h3>
            <p class="mt-3 text-sm text-cyber-muted">封禁时间：{{ formatTimestamp(ip.blocked_at) }}</p>
            <p class="mt-2 text-sm text-cyber-muted">到期时间：{{ formatTimestamp(ip.expires_at) }}</p>
            <p class="mt-1 text-xs text-cyber-muted">剩余：{{ timeRemaining(ip.expires_at) }}</p>

            <div class="mt-5 rounded-[22px] bg-cyber-surface-strong p-4">
              <p class="text-xs tracking-[0.18em] text-cyber-muted">封禁原因</p>
              <p class="mt-2 text-sm leading-6 text-stone-800">{{ ip.reason }}</p>
            </div>
          </article>
          <p v-if="!dashboard?.blockedIps.blocked_ips.length" class="text-sm text-cyber-muted">当前没有处于封禁状态的地址。</p>
        </div>
      </section>
    </div>

    <div v-if="isRuleModalOpen" class="fixed inset-0 z-[100] flex items-stretch justify-end">
      <div class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm" @click="isRuleModalOpen = false"></div>
      <div class="relative h-full w-full max-w-xl overflow-y-auto border-l border-cyber-border/70 bg-[#fffaf4] p-8 shadow-[0_24px_80px_rgba(60,40,20,0.24)]">
        <div class="flex items-center justify-between">
          <div>
            <p class="text-sm tracking-[0.18em] text-cyber-accent-strong">{{ ruleForm.id ? '编辑规则' : '新建规则' }}</p>
            <h3 class="mt-2 text-3xl font-semibold text-stone-900">{{ ruleForm.id ? '调整现有策略' : '创建新的防护策略' }}</h3>
          </div>
          <button
            @click="isRuleModalOpen = false"
            class="flex h-10 w-10 items-center justify-center rounded-full border border-cyber-border bg-white/75 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong"
          >
            <X :size="18" />
          </button>
        </div>

        <form @submit.prevent="handleCreateOrUpdateRule" class="mt-8 space-y-6">
          <div class="space-y-2">
            <label class="text-sm text-cyber-muted">规则名称</label>
            <input
              v-model="ruleForm.name"
              type="text"
              class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent"
              placeholder="例如：数据库注入拦截"
              required
            />
          </div>

          <div class="grid gap-4 md:grid-cols-3">
            <div class="space-y-2">
              <label class="text-sm text-cyber-muted">层级</label>
              <select
                v-model="ruleForm.layer"
                class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent"
              >
                <option value="l4">四层</option>
                <option value="l7">七层</option>
              </select>
            </div>

            <div class="space-y-2">
              <label class="text-sm text-cyber-muted">级别</label>
              <select
                v-model="ruleForm.severity"
                class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent"
              >
                <option value="low">低</option>
                <option value="medium">中</option>
                <option value="high">高</option>
              </select>
            </div>

            <div class="space-y-2">
              <label class="text-sm text-cyber-muted">动作</label>
              <select
                v-model="ruleForm.action"
                class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent"
              >
                <option value="block">拦截</option>
                <option value="allow">放行</option>
                <option value="log">记录</option>
              </select>
            </div>
          </div>

          <div class="space-y-2">
            <label class="text-sm text-cyber-muted">匹配内容</label>
            <textarea
              v-model="ruleForm.pattern"
              rows="6"
              class="w-full rounded-[24px] border border-cyber-border bg-white px-4 py-3 font-mono text-sm outline-none transition focus:border-cyber-accent"
              placeholder="可以填写正则表达式、地址段范围或其他匹配模式"
              required
            ></textarea>
          </div>

          <label class="flex items-center gap-3 rounded-[24px] border border-cyber-border/70 bg-white/70 p-4">
            <input v-model="ruleForm.enabled" type="checkbox" class="h-4 w-4 accent-[var(--color-cyber-accent)]" />
            <span class="text-sm text-stone-800">保存后立即启用这条规则</span>
          </label>

          <button
            type="submit"
            class="inline-flex w-full items-center justify-center gap-2 rounded-full bg-cyber-accent px-6 py-4 text-base font-semibold text-white shadow-cyber transition hover:-translate-y-0.5"
          >
            <Save :size="18" />
            保存规则
          </button>
        </form>
      </div>
    </div>
  </AppLayout>
</template>

<style>
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}

::-webkit-scrollbar-track {
  background: rgba(219, 200, 176, 0.35);
}

::-webkit-scrollbar-thumb {
  background: rgba(179, 84, 30, 0.42);
  border-radius: 999px;
}

::-webkit-scrollbar-thumb:hover {
  background: rgba(127, 47, 18, 0.55);
}
</style>
