<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { RouterLink } from 'vue-router'
import AppLayout from '../components/layout/AppLayout.vue'
import CyberCard from '../components/ui/CyberCard.vue'
import MetricWidget from '../components/ui/MetricWidget.vue'
import StatusBadge from '../components/ui/StatusBadge.vue'
import { useFormatters } from '../composables/useFormatters'
import {
  fetchL7Config,
  fetchL7Stats,
  fetchRulesList,
  fetchSecurityEvents,
  updateL7Config,
} from '../lib/api'
import type {
  L7ConfigPayload,
  L7StatsPayload,
  RuleItem,
  SecurityEventItem,
} from '../lib/types'
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  RefreshCw,
  Save,
  Shield,
  TimerReset,
} from 'lucide-vue-next'

type L7ConfigForm = Omit<
  L7ConfigPayload,
  | 'runtime_enabled'
  | 'bloom_enabled'
  | 'bloom_false_positive_verification'
  | 'runtime_profile'
  | 'listen_addrs'
  | 'upstream_endpoint'
  | 'http3_enabled'
  | 'http3_listen_addr'
>

const { actionLabel, formatLatency, formatNumber, formatTimestamp } = useFormatters()

const loading = ref(true)
const refreshing = ref(false)
const saving = ref(false)
const error = ref('')
const successMessage = ref('')
const stats = ref<L7StatsPayload | null>(null)
const rules = ref<RuleItem[]>([])
const events = ref<SecurityEventItem[]>([])
const statsTimer = ref<number | null>(null)
const lastUpdated = ref<number | null>(null)
const meta = ref({
  runtime_enabled: false,
  bloom_enabled: false,
  bloom_false_positive_verification: false,
  runtime_profile: 'minimal',
  listen_addrs: [] as string[],
  upstream_endpoint: '',
  http3_enabled: false,
  http3_listen_addr: '',
})

const configForm = reactive<L7ConfigForm>({
  http_inspection_enabled: true,
  max_request_size: 8192,
  real_ip_headers: [],
  trusted_proxy_cidrs: [],
  first_byte_timeout_ms: 2000,
  read_idle_timeout_ms: 5000,
  tls_handshake_timeout_ms: 3000,
  proxy_connect_timeout_ms: 1500,
  proxy_write_timeout_ms: 3000,
  proxy_read_timeout_ms: 10000,
  upstream_healthcheck_enabled: true,
  upstream_healthcheck_interval_secs: 5,
  upstream_healthcheck_timeout_ms: 1000,
  upstream_failure_mode: 'fail_open',
  bloom_filter_scale: 1,
  http2_enabled: false,
  http2_max_concurrent_streams: 100,
  http2_max_frame_size: 16384,
  http2_enable_priorities: true,
  http2_initial_window_size: 65535,
})

const numberInputClass =
  'mt-2 w-full rounded-[18px] border border-cyber-border/70 bg-white px-4 py-3 text-sm text-stone-800 outline-none transition focus:border-cyber-accent/40'

const listFieldClass =
  'mt-2 min-h-[120px] w-full rounded-[18px] border border-cyber-border/70 bg-white px-4 py-3 text-sm text-stone-800 outline-none transition focus:border-cyber-accent/40'

const clampInteger = (value: number, min: number, max: number, fallback: number) => {
  const normalized = Number.isFinite(value) ? Math.round(value) : fallback
  return Math.min(Math.max(normalized, min), max)
}

const clampFloat = (value: number, min: number, max: number, fallback: number) => {
  const normalized = Number.isFinite(value) ? value : fallback
  return Math.min(Math.max(Number(normalized.toFixed(2)), min), max)
}

const applyConfig = (payload: L7ConfigPayload) => {
  configForm.http_inspection_enabled = payload.http_inspection_enabled
  configForm.max_request_size = payload.max_request_size
  configForm.real_ip_headers = [...payload.real_ip_headers]
  configForm.trusted_proxy_cidrs = [...payload.trusted_proxy_cidrs]
  configForm.first_byte_timeout_ms = payload.first_byte_timeout_ms
  configForm.read_idle_timeout_ms = payload.read_idle_timeout_ms
  configForm.tls_handshake_timeout_ms = payload.tls_handshake_timeout_ms
  configForm.proxy_connect_timeout_ms = payload.proxy_connect_timeout_ms
  configForm.proxy_write_timeout_ms = payload.proxy_write_timeout_ms
  configForm.proxy_read_timeout_ms = payload.proxy_read_timeout_ms
  configForm.upstream_healthcheck_enabled = payload.upstream_healthcheck_enabled
  configForm.upstream_healthcheck_interval_secs = payload.upstream_healthcheck_interval_secs
  configForm.upstream_healthcheck_timeout_ms = payload.upstream_healthcheck_timeout_ms
  configForm.upstream_failure_mode = payload.upstream_failure_mode
  configForm.bloom_filter_scale = payload.bloom_filter_scale
  configForm.http2_enabled = payload.http2_enabled
  configForm.http2_max_concurrent_streams = payload.http2_max_concurrent_streams
  configForm.http2_max_frame_size = payload.http2_max_frame_size
  configForm.http2_enable_priorities = payload.http2_enable_priorities
  configForm.http2_initial_window_size = payload.http2_initial_window_size

  meta.value = {
    runtime_enabled: payload.runtime_enabled,
    bloom_enabled: payload.bloom_enabled,
    bloom_false_positive_verification: payload.bloom_false_positive_verification,
    runtime_profile: payload.runtime_profile,
    listen_addrs: [...payload.listen_addrs],
    upstream_endpoint: payload.upstream_endpoint,
    http3_enabled: payload.http3_enabled,
    http3_listen_addr: payload.http3_listen_addr,
  }
}

const refreshAll = async (showLoader = false) => {
  if (showLoader) loading.value = true
  refreshing.value = true

  try {
    const [configPayload, statsPayload, rulesPayload, eventsPayload] = await Promise.all([
      fetchL7Config(),
      fetchL7Stats(),
      fetchRulesList(),
      fetchSecurityEvents({
        layer: 'l7',
        limit: 6,
        sort_by: 'created_at',
        sort_direction: 'desc',
      }),
    ])

    applyConfig(configPayload)
    stats.value = statsPayload
    rules.value = rulesPayload.rules
    events.value = eventsPayload.events
    lastUpdated.value = Date.now()
    error.value = ''
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取 L7 管理信息失败'
  } finally {
    if (showLoader) loading.value = false
    refreshing.value = false
  }
}

const refreshStats = async () => {
  try {
    stats.value = await fetchL7Stats()
    lastUpdated.value = Date.now()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '刷新 L7 统计失败'
  }
}

const saveConfig = async () => {
  saving.value = true
  error.value = ''
  successMessage.value = ''

  try {
    configForm.max_request_size = clampInteger(configForm.max_request_size, 1024, 16_777_216, 8192)
    configForm.first_byte_timeout_ms = clampInteger(configForm.first_byte_timeout_ms, 100, 60_000, 2000)
    configForm.read_idle_timeout_ms = clampInteger(configForm.read_idle_timeout_ms, 100, 300_000, 5000)
    configForm.tls_handshake_timeout_ms = clampInteger(configForm.tls_handshake_timeout_ms, 500, 60_000, 3000)
    configForm.proxy_connect_timeout_ms = clampInteger(configForm.proxy_connect_timeout_ms, 100, 60_000, 1500)
    configForm.proxy_write_timeout_ms = clampInteger(configForm.proxy_write_timeout_ms, 100, 300_000, 3000)
    configForm.proxy_read_timeout_ms = clampInteger(configForm.proxy_read_timeout_ms, 100, 300_000, 10000)
    configForm.upstream_healthcheck_interval_secs = clampInteger(configForm.upstream_healthcheck_interval_secs, 1, 86_400, 5)
    configForm.upstream_healthcheck_timeout_ms = clampInteger(configForm.upstream_healthcheck_timeout_ms, 100, 60_000, 1000)
    configForm.bloom_filter_scale = clampFloat(configForm.bloom_filter_scale, 0.1, 4, 1)
    configForm.http2_max_concurrent_streams = clampInteger(configForm.http2_max_concurrent_streams, 1, 10_000, 100)
    configForm.http2_max_frame_size = clampInteger(configForm.http2_max_frame_size, 1024, 16_777_216, 16384)
    configForm.http2_initial_window_size = clampInteger(configForm.http2_initial_window_size, 1024, 16_777_216, 65535)

    const response = await updateL7Config({ ...configForm })
    successMessage.value = response.message
    await refreshAll()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '保存 L7 配置失败'
  } finally {
    saving.value = false
  }
}

const realIpHeadersText = computed({
  get: () => configForm.real_ip_headers.join('\n'),
  set: (value: string) => {
    configForm.real_ip_headers = value
      .split(/[\n,]/)
      .map((item) => item.trim())
      .filter(Boolean)
  },
})

const trustedProxyCidrsText = computed({
  get: () => configForm.trusted_proxy_cidrs.join('\n'),
  set: (value: string) => {
    configForm.trusted_proxy_cidrs = value
      .split(/[\n,]/)
      .map((item) => item.trim())
      .filter(Boolean)
  },
})

const l7Rules = computed(() => rules.value.filter((rule) => rule.layer === 'l7'))
const enabledL7Rules = computed(() => l7Rules.value.filter((rule) => rule.enabled).length)
const blockL7Rules = computed(() => l7Rules.value.filter((rule) => rule.action === 'block').length)
const proxySuccessRate = computed(() => {
  const total = (stats.value?.proxy_successes ?? 0) + (stats.value?.proxy_failures ?? 0)
  if (!total) return '暂无'
  return `${(((stats.value?.proxy_successes ?? 0) / total) * 100).toFixed(1)}%`
})
const lastUpdatedLabel = computed(() => {
  if (!lastUpdated.value) return '等待首次拉取'
  return `上次刷新：${new Intl.DateTimeFormat('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(lastUpdated.value))}`
})
const runtimeStatus = computed(() => stats.value?.enabled ?? meta.value.runtime_enabled)
const runtimeProfileLabel = computed(() =>
  meta.value.runtime_profile === 'standard' ? 'standard' : 'minimal',
)
const upstreamStatusText = computed(() =>
  stats.value?.upstream_healthy ? '健康' : '异常',
)
const upstreamStatusType = computed(() =>
  stats.value?.upstream_healthy ? 'success' : 'error',
)
const failureModeLabel = computed(() =>
  configForm.upstream_failure_mode === 'fail_close' ? '故障关闭' : '故障放行',
)
const protocolTags = computed(() => [
  { text: 'HTTP/1.1 常驻', type: 'info' as const },
  { text: configForm.http2_enabled ? 'HTTP/2 已启用' : 'HTTP/2 未启用', type: configForm.http2_enabled ? ('success' as const) : ('muted' as const) },
  { text: meta.value.http3_enabled ? 'HTTP/3 已启用' : 'HTTP/3 未启用', type: meta.value.http3_enabled ? ('success' as const) : ('muted' as const) },
])

onMounted(async () => {
  await refreshAll(true)
  statsTimer.value = window.setInterval(() => {
    refreshStats()
  }, 5000)
})

onBeforeUnmount(() => {
  if (statsTimer.value) {
    clearInterval(statsTimer.value)
  }
})
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <div class="flex items-center gap-3">
        <span class="text-xs text-cyber-muted whitespace-nowrap">{{ lastUpdatedLabel }}</span>
        <button
          @click="refreshAll()"
          class="inline-flex items-center gap-2 rounded-full border border-cyber-border bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong disabled:opacity-60"
          :disabled="refreshing"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
          刷新
        </button>
        <button
          @click="saveConfig"
          class="inline-flex items-center gap-2 rounded-full bg-cyber-accent px-4 py-1.5 text-xs font-semibold text-white shadow-cyber transition hover:-translate-y-0.5 disabled:opacity-60"
          :disabled="saving || loading"
        >
          <Save :size="14" />
          {{ saving ? '保存中...' : '保存配置' }}
        </button>
      </div>
    </template>

    <div v-if="loading" class="flex h-72 items-center justify-center">
      <div class="flex flex-col items-center gap-4 rounded-[28px] border border-white/80 bg-white/75 px-8 py-10 shadow-cyber">
        <RefreshCw class="animate-spin text-cyber-accent-strong" :size="30" />
        <p class="text-sm tracking-[0.2em] text-cyber-muted">正在载入 L7 管理面板</p>
      </div>
    </div>

    <div v-else class="space-y-8">
      <section class="rounded-[34px] border border-white/85 bg-[linear-gradient(140deg,rgba(255,250,244,0.92),rgba(244,239,231,0.96))] p-7 shadow-[0_26px_80px_rgba(90,60,30,0.10)]">
        <div class="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
          <div class="max-w-3xl">
            <p class="text-sm tracking-[0.22em] text-cyber-accent-strong">L7 管理</p>
            <h2 class="mt-3 font-display text-4xl font-semibold text-stone-900">七层检测、代理与请求链路控制台</h2>
            <p class="mt-4 text-sm leading-7 text-stone-700">
              这里聚焦 HTTP 请求路径上的运行态与配置态，方便你同时看七层检测开关、代理健康、协议支持和最近安全事件。
            </p>
          </div>
          <div class="flex flex-wrap gap-3">
            <StatusBadge :text="runtimeStatus ? '运行中' : '未启用'" :type="runtimeStatus ? 'success' : 'warning'" />
            <StatusBadge :text="`配置档位 ${runtimeProfileLabel}`" type="info" />
            <StatusBadge :text="meta.bloom_enabled ? 'Bloom 已启用' : 'Bloom 未启用'" :type="meta.bloom_enabled ? 'info' : 'muted'" />
            <StatusBadge
              :text="meta.bloom_false_positive_verification ? '误判校验开启' : '误判校验关闭'"
              :type="meta.bloom_false_positive_verification ? 'success' : 'muted'"
            />
          </div>
        </div>
      </section>

      <div
        class="rounded-[26px] border border-amber-300/60 bg-amber-50/90 px-5 py-4 text-sm text-amber-900 shadow-[0_18px_38px_rgba(180,120,20,0.08)]"
      >
        <div class="flex items-start gap-3">
          <AlertTriangle class="mt-0.5 shrink-0 text-amber-600" :size="18" />
          <div class="space-y-1">
            <p class="font-semibold">当前页面优先提供运行态与配置态管理。</p>
            <p>
              七层规则已可在规则中心维护，但后端的专用 L7 规则执行链路仍在继续完善，因此这里先把规则状态作为摘要展示，避免误导成“已完全闭环”。
            </p>
          </div>
        </div>
      </div>

      <div
        v-if="error"
        class="rounded-[24px] border border-cyber-error/25 bg-cyber-error/8 px-5 py-4 text-sm text-cyber-error shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

      <div
        v-if="successMessage"
        class="rounded-[24px] border border-emerald-300/60 bg-emerald-50 px-5 py-4 text-sm text-emerald-800 shadow-[0_14px_30px_rgba(16,185,129,0.08)]"
      >
        {{ successMessage }}
      </div>

      <section class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricWidget
          label="七层累计拦截"
          :value="formatNumber(stats?.blocked_requests || 0)"
          hint="来自 L7 请求路径的累计阻断次数"
          :icon="Shield"
          trend="up"
        />
        <MetricWidget
          label="代理请求总数"
          :value="formatNumber(stats?.proxied_requests || 0)"
          :hint="`成功 ${formatNumber(stats?.proxy_successes || 0)} / 失败 ${formatNumber(stats?.proxy_failures || 0)}`"
          :icon="Activity"
        />
        <MetricWidget
          label="代理成功率"
          :value="proxySuccessRate"
          :hint="`失败关闭拒绝 ${formatNumber(stats?.proxy_fail_close_rejections || 0)}`"
          :icon="ArrowUpRight"
        />
        <MetricWidget
          label="平均代理延迟"
          :value="formatLatency(stats?.average_proxy_latency_micros || 0)"
          hint="仅统计成功代理请求"
          :icon="TimerReset"
          trend="down"
        />
      </section>

      <section class="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <CyberCard title="协议支持" sub-title="L7 协议与监听入口摘要">
          <div class="space-y-4">
            <div class="flex flex-wrap gap-3">
              <StatusBadge
                v-for="item in protocolTags"
                :key="item.text"
                :text="item.text"
                :type="item.type"
              />
            </div>
            <div class="grid gap-3 md:grid-cols-2">
              <div class="rounded-[22px] bg-cyber-surface-strong p-4">
                <p class="text-xs tracking-[0.18em] text-cyber-muted">监听地址</p>
                <div class="mt-3 space-y-2 text-sm text-stone-800">
                  <p v-for="addr in meta.listen_addrs" :key="addr">{{ addr }}</p>
                  <p v-if="!meta.listen_addrs.length" class="text-cyber-muted">暂无监听入口</p>
                </div>
              </div>
              <div class="rounded-[22px] bg-cyber-surface-strong p-4">
                <p class="text-xs tracking-[0.18em] text-cyber-muted">HTTP/3 监听</p>
                <p class="mt-3 text-sm text-stone-800">
                  {{ meta.http3_enabled ? meta.http3_listen_addr || '已启用' : '未启用 HTTP/3' }}
                </p>
              </div>
            </div>
            <div class="grid gap-3 md:grid-cols-3">
              <div class="rounded-[22px] border border-cyber-border/60 bg-white/80 p-4">
                <p class="text-xs tracking-[0.18em] text-cyber-muted">HTTP/2 最大并发流</p>
                <p class="mt-3 text-2xl font-semibold text-stone-900">{{ formatNumber(configForm.http2_max_concurrent_streams) }}</p>
              </div>
              <div class="rounded-[22px] border border-cyber-border/60 bg-white/80 p-4">
                <p class="text-xs tracking-[0.18em] text-cyber-muted">HTTP/2 最大帧</p>
                <p class="mt-3 text-2xl font-semibold text-stone-900">{{ formatNumber(configForm.http2_max_frame_size) }}</p>
              </div>
              <div class="rounded-[22px] border border-cyber-border/60 bg-white/80 p-4">
                <p class="text-xs tracking-[0.18em] text-cyber-muted">初始窗口</p>
                <p class="mt-3 text-2xl font-semibold text-stone-900">{{ formatNumber(configForm.http2_initial_window_size) }}</p>
              </div>
            </div>
          </div>
        </CyberCard>

        <CyberCard title="代理链路摘要" sub-title="上游地址、健康状态与真实来源解析">
          <div class="space-y-4">
            <div class="flex flex-wrap gap-3">
              <StatusBadge :text="`上游 ${upstreamStatusText}`" :type="upstreamStatusType" />
              <StatusBadge :text="`失败模式 ${failureModeLabel}`" type="warning" />
              <StatusBadge
                :text="configForm.upstream_healthcheck_enabled ? '健康检查开启' : '健康检查关闭'"
                :type="configForm.upstream_healthcheck_enabled ? 'success' : 'muted'"
              />
            </div>
            <div class="rounded-[22px] bg-cyber-surface-strong p-4">
              <p class="text-xs tracking-[0.18em] text-cyber-muted">TCP 上游</p>
              <p class="mt-3 text-sm text-stone-800">{{ meta.upstream_endpoint || '未配置上游转发地址' }}</p>
            </div>
            <div class="grid gap-3 md:grid-cols-2">
              <div class="rounded-[22px] border border-cyber-border/60 bg-white/80 p-4">
                <p class="text-xs tracking-[0.18em] text-cyber-muted">真实 IP 头优先级</p>
                <p class="mt-3 text-sm leading-7 text-stone-800">
                  {{ configForm.real_ip_headers.length ? configForm.real_ip_headers.join(' -> ') : '未配置' }}
                </p>
              </div>
              <div class="rounded-[22px] border border-cyber-border/60 bg-white/80 p-4">
                <p class="text-xs tracking-[0.18em] text-cyber-muted">可信代理网段</p>
                <p class="mt-3 text-sm leading-7 text-stone-800">
                  {{ configForm.trusted_proxy_cidrs.length ? configForm.trusted_proxy_cidrs.join('，') : '未配置，默认仅信任直连对端' }}
                </p>
              </div>
            </div>
            <div class="rounded-[22px] border border-cyber-border/60 bg-white/80 p-4">
              <p class="text-xs tracking-[0.18em] text-cyber-muted">最近健康检查</p>
              <p class="mt-3 text-sm text-stone-800">
                {{ stats?.upstream_last_check_at ? formatTimestamp(stats.upstream_last_check_at) : '暂无检查记录' }}
              </p>
              <p v-if="stats?.upstream_last_error" class="mt-2 text-sm text-cyber-error">
                最近错误：{{ stats.upstream_last_error }}
              </p>
            </div>
          </div>
        </CyberCard>
      </section>

      <section class="rounded-[30px] border border-white/80 bg-white/78 p-6 shadow-[0_18px_48px_rgba(90,60,30,0.08)]">
        <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <p class="text-sm tracking-[0.2em] text-cyber-accent-strong">L7 配置</p>
            <h3 class="mt-2 text-2xl font-semibold text-stone-900">七层检测与代理参数</h3>
          </div>
          <div class="flex flex-wrap gap-3">
            <StatusBadge :text="configForm.http_inspection_enabled ? 'HTTP 检测开启' : 'HTTP 检测关闭'" :type="configForm.http_inspection_enabled ? 'success' : 'warning'" />
            <StatusBadge :text="configForm.http2_enabled ? 'HTTP/2 已启用' : 'HTTP/2 未启用'" :type="configForm.http2_enabled ? 'info' : 'muted'" />
          </div>
        </div>

        <div class="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <label class="rounded-[24px] border border-cyber-border/60 bg-cyber-surface-strong px-4 py-4 text-sm text-stone-800">
            <span class="flex items-center justify-between gap-3">
              <span class="font-medium">启用 HTTP 检测</span>
              <input v-model="configForm.http_inspection_enabled" type="checkbox" class="h-4 w-4 accent-[var(--color-cyber-accent)]" />
            </span>
            <span class="mt-2 block text-xs leading-6 text-cyber-muted">关闭后七层检测实例不会介入请求决策。</span>
          </label>
          <label class="rounded-[24px] border border-cyber-border/60 bg-cyber-surface-strong px-4 py-4 text-sm text-stone-800">
            <span class="flex items-center justify-between gap-3">
              <span class="font-medium">启用 HTTP/2</span>
              <input v-model="configForm.http2_enabled" type="checkbox" class="h-4 w-4 accent-[var(--color-cyber-accent)]" />
            </span>
            <span class="mt-2 block text-xs leading-6 text-cyber-muted">启用后可处理 h2 / TLS ALPN 路由到的请求。</span>
          </label>
          <label class="rounded-[24px] border border-cyber-border/60 bg-cyber-surface-strong px-4 py-4 text-sm text-stone-800">
            <span class="flex items-center justify-between gap-3">
              <span class="font-medium">启用上游健康检查</span>
              <input v-model="configForm.upstream_healthcheck_enabled" type="checkbox" class="h-4 w-4 accent-[var(--color-cyber-accent)]" />
            </span>
            <span class="mt-2 block text-xs leading-6 text-cyber-muted">关闭后故障状态仅来自实时代理结果，不再主动探测。</span>
          </label>
          <div class="rounded-[24px] border border-cyber-border/60 bg-cyber-surface-strong px-4 py-4 text-sm text-stone-800">
            <p class="font-medium">上游失败模式</p>
            <select v-model="configForm.upstream_failure_mode" class="mt-3 w-full rounded-[16px] border border-cyber-border bg-white px-3 py-2.5 text-sm outline-none transition focus:border-cyber-accent">
              <option value="fail_open">fail_open</option>
              <option value="fail_close">fail_close</option>
            </select>
            <p class="mt-2 text-xs leading-6 text-cyber-muted">上游不可用时选择放行还是拒绝请求。</p>
          </div>
        </div>

        <div class="mt-6 grid gap-5 md:grid-cols-2 xl:grid-cols-4">
          <label class="text-sm text-stone-700">
            最大请求体大小
            <input v-model.number="configForm.max_request_size" type="number" min="1024" :class="numberInputClass" />
          </label>
          <label class="text-sm text-stone-700">
            首字节超时(ms)
            <input v-model.number="configForm.first_byte_timeout_ms" type="number" min="100" :class="numberInputClass" />
          </label>
          <label class="text-sm text-stone-700">
            空闲读取超时(ms)
            <input v-model.number="configForm.read_idle_timeout_ms" type="number" min="100" :class="numberInputClass" />
          </label>
          <label class="text-sm text-stone-700">
            TLS 握手超时(ms)
            <input v-model.number="configForm.tls_handshake_timeout_ms" type="number" min="500" :class="numberInputClass" />
          </label>
          <label class="text-sm text-stone-700">
            代理连接超时(ms)
            <input v-model.number="configForm.proxy_connect_timeout_ms" type="number" min="100" :class="numberInputClass" />
          </label>
          <label class="text-sm text-stone-700">
            代理写超时(ms)
            <input v-model.number="configForm.proxy_write_timeout_ms" type="number" min="100" :class="numberInputClass" />
          </label>
          <label class="text-sm text-stone-700">
            代理读超时(ms)
            <input v-model.number="configForm.proxy_read_timeout_ms" type="number" min="100" :class="numberInputClass" />
          </label>
          <label class="text-sm text-stone-700">
            Bloom 缩放系数
            <input v-model.number="configForm.bloom_filter_scale" type="number" min="0.1" step="0.1" :class="numberInputClass" />
          </label>
          <label class="text-sm text-stone-700">
            健康检查间隔(s)
            <input v-model.number="configForm.upstream_healthcheck_interval_secs" type="number" min="1" :class="numberInputClass" />
          </label>
          <label class="text-sm text-stone-700">
            健康检查超时(ms)
            <input v-model.number="configForm.upstream_healthcheck_timeout_ms" type="number" min="100" :class="numberInputClass" />
          </label>
          <label class="text-sm text-stone-700">
            HTTP/2 最大并发流
            <input v-model.number="configForm.http2_max_concurrent_streams" type="number" min="1" :class="numberInputClass" />
          </label>
          <label class="text-sm text-stone-700">
            HTTP/2 最大帧
            <input v-model.number="configForm.http2_max_frame_size" type="number" min="1024" :class="numberInputClass" />
          </label>
          <label class="text-sm text-stone-700 md:col-span-2">
            HTTP/2 初始窗口
            <input v-model.number="configForm.http2_initial_window_size" type="number" min="1024" :class="numberInputClass" />
          </label>
          <label class="text-sm text-stone-700 md:col-span-2">
            HTTP/2 优先级支持
            <span class="mt-2 flex items-center gap-3 rounded-[18px] border border-cyber-border/70 bg-white px-4 py-3">
              <input v-model="configForm.http2_enable_priorities" type="checkbox" class="h-4 w-4 accent-[var(--color-cyber-accent)]" />
              <span class="text-sm text-stone-800">允许使用优先级信息处理 HTTP/2 请求</span>
            </span>
          </label>
        </div>

        <div class="mt-6 grid gap-5 xl:grid-cols-2">
          <label class="text-sm text-stone-700">
            真实来源 IP 头
            <textarea v-model="realIpHeadersText" :class="listFieldClass" placeholder="每行一个，例如 x-forwarded-for" />
          </label>
          <label class="text-sm text-stone-700">
            可信代理网段
            <textarea v-model="trustedProxyCidrsText" :class="listFieldClass" placeholder="每行一个，例如 203.0.113.0/24" />
          </label>
        </div>
      </section>

      <section class="grid gap-6 xl:grid-cols-[1fr_1fr]">
        <CyberCard title="最近 L7 事件" sub-title="只展示七层安全事件">
          <div class="space-y-4">
            <div
              v-for="event in events"
              :key="event.id"
              class="rounded-[24px] border border-cyber-border/60 bg-white/75 p-4"
            >
              <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div class="flex items-center gap-3">
                  <StatusBadge :text="actionLabel(event.action)" :type="event.action === 'block' ? 'error' : 'warning'" />
                  <p class="text-sm font-medium text-stone-900">{{ event.reason }}</p>
                </div>
                <span class="text-xs text-cyber-muted">{{ formatTimestamp(event.created_at) }}</span>
              </div>
              <div class="mt-3 grid gap-2 text-sm text-stone-700 md:grid-cols-2">
                <p>来源：{{ event.source_ip }}:{{ event.source_port }}</p>
                <p>目标：{{ event.dest_ip }}:{{ event.dest_port }}</p>
                <p>请求：{{ event.http_method || '-' }} {{ event.uri || '' }}</p>
                <p>版本：{{ event.http_version || '-' }}</p>
              </div>
            </div>
            <p v-if="!events.length" class="text-sm text-cyber-muted">暂无七层事件。</p>
          </div>
          <template #header-action>
            <RouterLink
              to="/admin/events"
              class="inline-flex items-center gap-2 text-sm text-cyber-accent-strong transition hover:text-cyber-accent"
            >
              查看全部
            </RouterLink>
          </template>
        </CyberCard>

        <CyberCard title="L7 规则摘要" sub-title="规则中心中的七层策略概览">
          <div class="grid gap-4 md:grid-cols-3">
            <div class="rounded-[24px] bg-cyber-surface-strong p-4">
              <p class="text-xs tracking-[0.18em] text-cyber-muted">七层规则总数</p>
              <p class="mt-3 text-3xl font-semibold text-stone-900">{{ formatNumber(l7Rules.length) }}</p>
            </div>
            <div class="rounded-[24px] bg-cyber-surface-strong p-4">
              <p class="text-xs tracking-[0.18em] text-cyber-muted">已启用规则</p>
              <p class="mt-3 text-3xl font-semibold text-stone-900">{{ formatNumber(enabledL7Rules) }}</p>
            </div>
            <div class="rounded-[24px] bg-cyber-surface-strong p-4">
              <p class="text-xs tracking-[0.18em] text-cyber-muted">拦截动作规则</p>
              <p class="mt-3 text-3xl font-semibold text-stone-900">{{ formatNumber(blockL7Rules) }}</p>
            </div>
          </div>

          <div class="mt-5 space-y-3">
            <div
              v-for="rule in l7Rules.slice(0, 5)"
              :key="rule.id"
              class="rounded-[20px] border border-cyber-border/60 bg-white/70 px-4 py-4"
            >
              <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <p class="font-medium text-stone-900">{{ rule.name }}</p>
                  <p class="mt-1 font-mono text-xs text-cyber-muted">{{ rule.pattern }}</p>
                </div>
                <div class="flex flex-wrap gap-2">
                  <StatusBadge :text="rule.enabled ? '启用' : '停用'" :type="rule.enabled ? 'success' : 'muted'" compact />
                  <StatusBadge :text="actionLabel(rule.action)" :type="rule.action === 'block' ? 'error' : 'warning'" compact />
                </div>
              </div>
            </div>
            <p v-if="!l7Rules.length" class="text-sm text-cyber-muted">当前还没有七层规则。</p>
          </div>

          <template #header-action>
            <RouterLink
              to="/admin/rules"
              class="inline-flex items-center gap-2 text-sm text-cyber-accent-strong transition hover:text-cyber-accent"
            >
              前往规则中心
            </RouterLink>
          </template>
        </CyberCard>
      </section>
    </div>
  </AppLayout>
</template>
