<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import AppLayout from '../components/layout/AppLayout.vue'
import L4SectionNav from '../components/l4/L4SectionNav.vue'
import CyberCard from '../components/ui/CyberCard.vue'
import MetricWidget from '../components/ui/MetricWidget.vue'
import StatusBadge from '../components/ui/StatusBadge.vue'
import { useFormatters } from '../composables/useFormatters'
import { fetchL4Config, fetchL4Stats, updateL4Config } from '../lib/api'
import type { L4ConfigPayload, L4StatsPayload } from '../lib/types'
import {
  Activity,
  Ban,
  Database,
  RefreshCw,
  Save,
  ServerCog,
  Shield,
} from 'lucide-vue-next'

type L4ConfigForm = Omit<
  L4ConfigPayload,
  | 'runtime_enabled'
  | 'bloom_enabled'
  | 'bloom_false_positive_verification'
  | 'runtime_profile'
>

const { formatBytes, formatNumber } = useFormatters()

const loading = ref(true)
const refreshing = ref(false)
const saving = ref(false)
const error = ref('')
const successMessage = ref('')
const stats = ref<L4StatsPayload | null>(null)
const statsTimer = ref<number | null>(null)
const lastUpdated = ref<number | null>(null)
const meta = ref({
  runtime_enabled: false,
  bloom_enabled: false,
  bloom_false_positive_verification: false,
  runtime_profile: 'minimal',
})

const configForm = reactive<L4ConfigForm>({
  ddos_protection_enabled: true,
  advanced_ddos_enabled: false,
  connection_rate_limit: 100,
  syn_flood_threshold: 50,
  max_tracked_ips: 4096,
  max_blocked_ips: 1024,
  state_ttl_secs: 300,
  bloom_filter_scale: 1,
})

const numberInputClass =
  'mt-2 w-full rounded-[18px] border border-slate-200 bg-white px-4 py-3 text-sm text-stone-800 outline-none transition focus:border-blue-500/40'

const clampInteger = (
  value: number,
  min: number,
  max: number,
  fallback: number,
) => {
  const normalized = Number.isFinite(value) ? Math.round(value) : fallback
  return Math.min(Math.max(normalized, min), max)
}

const clampFloat = (
  value: number,
  min: number,
  max: number,
  fallback: number,
) => {
  const normalized = Number.isFinite(value) ? value : fallback
  return Math.min(Math.max(Number(normalized.toFixed(2)), min), max)
}

const applyConfig = (payload: L4ConfigPayload) => {
  configForm.ddos_protection_enabled = payload.ddos_protection_enabled
  configForm.advanced_ddos_enabled = payload.advanced_ddos_enabled
  configForm.connection_rate_limit = payload.connection_rate_limit
  configForm.syn_flood_threshold = payload.syn_flood_threshold
  configForm.max_tracked_ips = payload.max_tracked_ips
  configForm.max_blocked_ips = payload.max_blocked_ips
  configForm.state_ttl_secs = payload.state_ttl_secs
  configForm.bloom_filter_scale = payload.bloom_filter_scale

  meta.value = {
    runtime_enabled: payload.runtime_enabled,
    bloom_enabled: payload.bloom_enabled,
    bloom_false_positive_verification:
      payload.bloom_false_positive_verification,
    runtime_profile: payload.runtime_profile,
  }
}

const refreshAll = async (showLoader = false) => {
  if (showLoader) loading.value = true
  refreshing.value = true

  try {
    const [configPayload, statsPayload] = await Promise.all([
      fetchL4Config(),
      fetchL4Stats(),
    ])
    applyConfig(configPayload)
    stats.value = statsPayload
    lastUpdated.value = Date.now()
    error.value = ''
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取 L4 管理信息失败'
  } finally {
    if (showLoader) loading.value = false
    refreshing.value = false
  }
}

const refreshStats = async () => {
  try {
    stats.value = await fetchL4Stats()
    lastUpdated.value = Date.now()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '刷新 L4 统计失败'
  }
}

const saveConfig = async () => {
  saving.value = true
  error.value = ''
  successMessage.value = ''

  try {
    configForm.connection_rate_limit = clampInteger(
      configForm.connection_rate_limit,
      1,
      1_000_000,
      100,
    )
    configForm.syn_flood_threshold = clampInteger(
      configForm.syn_flood_threshold,
      1,
      1_000_000,
      50,
    )
    configForm.max_tracked_ips = clampInteger(
      configForm.max_tracked_ips,
      1,
      1_000_000,
      4096,
    )
    configForm.max_blocked_ips = clampInteger(
      configForm.max_blocked_ips,
      1,
      1_000_000,
      1024,
    )
    configForm.state_ttl_secs = clampInteger(
      configForm.state_ttl_secs,
      60,
      86_400,
      300,
    )
    configForm.bloom_filter_scale = clampFloat(
      configForm.bloom_filter_scale,
      0.1,
      4,
      1,
    )

    const response = await updateL4Config({ ...configForm })
    successMessage.value = response.message
    await refreshAll()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '保存 L4 配置失败'
  } finally {
    saving.value = false
  }
}

const runtimeStatus = computed(
  () => stats.value?.enabled ?? meta.value.runtime_enabled,
)
const runtimeProfileLabel = computed(() =>
  meta.value.runtime_profile === 'standard' ? 'standard' : 'minimal',
)
const lastUpdatedLabel = computed(() => {
  if (!lastUpdated.value) return '等待首次拉取'
  return `上次刷新：${new Intl.DateTimeFormat('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(lastUpdated.value))}`
})
const topPorts = computed(() => stats.value?.per_port_stats ?? [])
const bloomPanels = computed(() => {
  const bloomStats = stats.value?.bloom_stats
  if (!bloomStats) return []

  return [
    { label: 'IPv4 命中', value: bloomStats.ipv4_filter },
    { label: 'IPv6 命中', value: bloomStats.ipv6_filter },
    { label: 'IP:Port 命中', value: bloomStats.ip_port_filter },
  ]
})
const falsePositivePanels = computed(() => {
  const falsePositiveStats = stats.value?.false_positive_stats
  if (!falsePositiveStats) return []

  return [
    { label: 'IPv4 精确校验集', value: falsePositiveStats.ipv4_exact_size },
    { label: 'IPv6 精确校验集', value: falsePositiveStats.ipv6_exact_size },
    {
      label: 'IP:Port 精确校验集',
      value: falsePositiveStats.ip_port_exact_size,
    },
  ]
})
const blockedCapacityRatio = computed(() => {
  const maxBlocked = configForm.max_blocked_ips
  if (!maxBlocked) return 0
  return (stats.value?.connections.blocked_connections ?? 0) / maxBlocked
})
const blockedCapacityLabel = computed(() => {
  if (!configForm.max_blocked_ips) return '未配置上限'
  return `${Math.min(blockedCapacityRatio.value * 100, 999).toFixed(1)}%`
})
const blockedCapacityTone = computed(() => {
  if (blockedCapacityRatio.value >= 0.85) return 'error'
  if (blockedCapacityRatio.value >= 0.6) return 'warning'
  return 'success'
})

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
        <span class="text-xs text-slate-500 whitespace-nowrap">{{
          lastUpdatedLabel
        }}</span>
        <button
          @click="refreshAll()"
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
          :disabled="refreshing"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
          刷新
        </button>
        <button
          @click="saveConfig"
          class="inline-flex items-center gap-2 rounded-full bg-blue-600 px-4 py-1.5 text-xs font-semibold text-white shadow-sm transition hover:-translate-y-0.5 disabled:opacity-60"
          :disabled="saving || loading"
        >
          <Save :size="14" />
          {{ saving ? '保存中...' : '保存配置' }}
        </button>
      </div>
    </template>

    <div v-if="loading" class="flex h-72 items-center justify-center">
      <div
        class="flex flex-col items-center gap-4 rounded-2xl border border-slate-200 bg-white px-4 py-6 shadow-sm"
      >
        <RefreshCw class="animate-spin text-blue-700" :size="30" />
        <p class="text-sm text-slate-500">正在载入 L4 管理面板</p>
      </div>
    </div>

    <div v-else class="space-y-4">
      <L4SectionNav />

      <section
        class="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm"
      >
        <div
          class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between"
        >
          <div class="max-w-3xl">
            <p class="text-sm tracking-wider text-blue-700">L4 管理</p>
          </div>
          <div class="flex flex-wrap gap-3">
            <StatusBadge
              :text="runtimeStatus ? '运行中' : '未启用'"
              :type="runtimeStatus ? 'success' : 'warning'"
            />
            <StatusBadge
              :text="`配置档位 ${runtimeProfileLabel}`"
              type="info"
            />
            <StatusBadge
              :text="meta.bloom_enabled ? 'Bloom 已启用' : 'Bloom 未启用'"
              :type="meta.bloom_enabled ? 'info' : 'muted'"
            />
            <StatusBadge
              :text="
                meta.bloom_false_positive_verification
                  ? '误判校验开启'
                  : '误判校验关闭'
              "
              :type="
                meta.bloom_false_positive_verification ? 'success' : 'muted'
              "
            />
          </div>
        </div>
      </section>

      <div
        v-if="error"
        class="rounded-xl border border-red-500/25 bg-red-500/8 px-4 py-3 text-sm text-red-600 shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

      <div
        v-if="successMessage"
        class="rounded-xl border border-emerald-300/60 bg-emerald-50 px-4 py-3 text-sm text-emerald-800 shadow-[0_14px_30px_rgba(16,185,129,0.08)]"
      >
        {{ successMessage }}
      </div>

      <section class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricWidget
          label="活跃连接"
          :value="formatNumber(stats?.connections.active_connections || 0)"
          :hint="`累计连接 ${formatNumber(stats?.connections.total_connections || 0)}`"
          :icon="Activity"
        />
        <MetricWidget
          label="当前封禁数"
          :value="formatNumber(stats?.connections.blocked_connections || 0)"
          :hint="`限流命中 ${formatNumber(stats?.connections.rate_limit_hits || 0)}`"
          :icon="Ban"
          trend="up"
        />
        <MetricWidget
          label="DDoS 事件"
          :value="formatNumber(stats?.ddos_events || 0)"
          :hint="`防御动作 ${formatNumber(stats?.defense_actions || 0)}`"
          :icon="Shield"
          trend="up"
        />
        <MetricWidget
          label="端口观测数"
          :value="formatNumber(topPorts.length)"
          :hint="`协议异常 ${formatNumber(stats?.protocol_anomalies || 0)} / 流量计数 ${formatNumber(stats?.traffic || 0)}`"
          :icon="Database"
        />
      </section>

      <section class="grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
        <CyberCard
          title="L4 防护配置"
          sub-title="保存到数据库后，重启服务即可让新配置接管运行时实例。"
        >
          <div class="grid gap-3 md:grid-cols-2">
            <label
              class="rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm text-stone-700"
            >
              <div class="flex items-center justify-between gap-4">
                <div>
                  <p class="font-medium text-stone-900">启用 DDoS 防护</p>
                  <p class="mt-1 text-xs leading-6 text-slate-500">
                    关闭后仍会保留页面配置，但运行时不会做 DDoS 判定。
                  </p>
                </div>
                <input
                  v-model="configForm.ddos_protection_enabled"
                  type="checkbox"
                  class="h-5 w-5 accent-blue-600"
                />
              </div>
            </label>

            <label
              class="rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm text-stone-700"
            >
              <div class="flex items-center justify-between gap-4">
                <div>
                  <p class="font-medium text-stone-900">高级 DDoS 判定</p>
                  <p class="mt-1 text-xs leading-6 text-slate-500">
                    额外使用更长窗口观测持续连接洪泛。
                  </p>
                </div>
                <input
                  v-model="configForm.advanced_ddos_enabled"
                  type="checkbox"
                  class="h-5 w-5 accent-blue-600"
                />
              </div>
            </label>

            <label class="text-sm text-stone-700">
              <span class="font-medium text-stone-900">每秒连接速率阈值</span>
              <input
                v-model.number="configForm.connection_rate_limit"
                type="number"
                min="1"
                step="1"
                :class="numberInputClass"
              />
              <p class="mt-2 text-xs text-slate-500">
                超过阈值后，连接限流器会拒绝来源地址的新连接。
              </p>
            </label>

            <label class="text-sm text-stone-700">
              <span class="font-medium text-stone-900">SYN / 突发阈值</span>
              <input
                v-model.number="configForm.syn_flood_threshold"
                type="number"
                min="1"
                step="1"
                :class="numberInputClass"
              />
              <p class="mt-2 text-xs text-slate-500">
                用于判定 1 秒窗口内是否出现连接洪泛。
              </p>
            </label>

            <label class="text-sm text-stone-700">
              <span class="font-medium text-stone-900">跟踪 IP 上限</span>
              <input
                v-model.number="configForm.max_tracked_ips"
                type="number"
                min="1"
                step="1"
                :class="numberInputClass"
              />
              <p class="mt-2 text-xs text-slate-500">
                连接跟踪器能同时维护的来源地址数量。
              </p>
            </label>

            <label class="text-sm text-stone-700">
              <span class="font-medium text-stone-900">封禁表上限</span>
              <input
                v-model.number="configForm.max_blocked_ips"
                type="number"
                min="1"
                step="1"
                :class="numberInputClass"
              />
              <p class="mt-2 text-xs text-slate-500">
                本地限流器允许同时保留的封禁 IP 数量。
              </p>
            </label>

            <label class="text-sm text-stone-700">
              <span class="font-medium text-stone-900">状态保留时长（秒）</span>
              <input
                v-model.number="configForm.state_ttl_secs"
                type="number"
                min="60"
                step="1"
                :class="numberInputClass"
              />
              <p class="mt-2 text-xs text-slate-500">
                连接窗口、限流计数和过期封禁的清理周期参考值。
              </p>
            </label>

            <label class="text-sm text-stone-700">
              <span class="font-medium text-stone-900">Bloom 缩放系数</span>
              <input
                v-model.number="configForm.bloom_filter_scale"
                type="number"
                min="0.1"
                step="0.1"
                :class="numberInputClass"
              />
              <p class="mt-2 text-xs text-slate-500">
                影响四层 Bloom Filter 的容量规模，实际值会按运行档位归一化。
              </p>
            </label>
          </div>
        </CyberCard>

        <div class="space-y-6">
          <CyberCard
            title="运行摘要"
            sub-title="帮助你快速确认当前实例到底在按什么模式跑。"
          >
            <div class="space-y-4 text-sm text-stone-700">
              <div class="rounded-xl border border-slate-200 p-4">
                <div class="flex items-center justify-between gap-4">
                  <div>
                    <p class="text-xs tracking-wide text-slate-500">
                      当前运行状态
                    </p>
                    <p class="mt-2 text-lg font-semibold text-stone-900">
                      {{
                        runtimeStatus
                          ? 'L4 检测实例已加载'
                          : 'L4 检测实例未加载'
                      }}
                    </p>
                  </div>
                  <ServerCog class="text-blue-700" :size="22" />
                </div>
                <p class="mt-3 leading-6 text-slate-500">
                  运行时统计来自内存中的 L4
                  Inspector，保存配置后如果不重启，这里的统计仍然对应旧参数。
                </p>
              </div>

              <div class="grid gap-4 sm:grid-cols-2">
                <div class="rounded-xl border border-slate-200 p-4">
                  <p class="text-xs tracking-wide text-slate-500">运行档位</p>
                  <p class="mt-2 text-lg font-semibold text-stone-900">
                    {{ runtimeProfileLabel }}
                  </p>
                </div>
                <div class="rounded-xl border border-slate-200 p-4">
                  <p class="text-xs tracking-wide text-slate-500">Bloom 状态</p>
                  <p class="mt-2 text-lg font-semibold text-stone-900">
                    {{ meta.bloom_enabled ? '已启用' : '未启用' }}
                  </p>
                </div>
                <div class="rounded-xl border border-slate-200 p-4">
                  <p class="text-xs tracking-wide text-slate-500">误判校验</p>
                  <p class="mt-2 text-lg font-semibold text-stone-900">
                    {{
                      meta.bloom_false_positive_verification ? '开启' : '关闭'
                    }}
                  </p>
                </div>
                <div class="rounded-xl border border-slate-200 p-4">
                  <p class="text-xs tracking-wide text-slate-500">
                    配置生效方式
                  </p>
                  <p class="mt-2 text-lg font-semibold text-stone-900">
                    保存后重启
                  </p>
                </div>
              </div>
            </div>
          </CyberCard>

          <CyberCard
            title="Bloom 摘要"
            sub-title="如果四层 Bloom 已启用，这里能直接看到三个过滤器的命中概览。"
          >
            <div v-if="bloomPanels.length" class="space-y-4">
              <div
                v-for="item in bloomPanels"
                :key="item.label"
                class="rounded-xl border border-slate-200 bg-slate-50 p-4"
              >
                <div class="flex items-center justify-between gap-4">
                  <p class="text-sm font-medium text-stone-900">
                    {{ item.label }}
                  </p>
                  <StatusBadge
                    :text="`${(item.value.hit_rate * 100).toFixed(2)}%`"
                    type="info"
                    compact
                  />
                </div>
                <div class="mt-3 grid grid-cols-2 gap-3 text-xs text-slate-500">
                  <p>过滤器大小：{{ formatNumber(item.value.filter_size) }}</p>
                  <p>哈希函数：{{ formatNumber(item.value.hash_functions) }}</p>
                  <p>插入次数：{{ formatNumber(item.value.insert_count) }}</p>
                  <p>命中次数：{{ formatNumber(item.value.hit_count) }}</p>
                </div>
              </div>
            </div>
            <div
              v-else
              class="rounded-xl border border-dashed border-slate-200 bg-slate-50 p-5 text-sm leading-6 text-slate-500"
            >
              当前没有可展示的 Bloom 运行统计。通常是因为运行中的 L4 实例未启用
              Bloom，或四层检测尚未加载。
            </div>
          </CyberCard>

          <CyberCard
            title="误判校验"
            sub-title="后端已经返回精确校验统计，这里补上展示，方便判断 Bloom 校验成本。"
          >
            <div v-if="falsePositivePanels.length" class="space-y-4">
              <div
                v-for="item in falsePositivePanels"
                :key="item.label"
                class="rounded-xl border border-slate-200 bg-slate-50 p-4"
              >
                <div class="flex items-center justify-between gap-4">
                  <p class="text-sm font-medium text-stone-900">
                    {{ item.label }}
                  </p>
                  <StatusBadge
                    :text="
                      meta.bloom_false_positive_verification
                        ? '校验开启'
                        : '校验关闭'
                    "
                    :type="
                      meta.bloom_false_positive_verification
                        ? 'success'
                        : 'muted'
                    "
                    compact
                  />
                </div>
                <p class="mt-3 text-2xl font-semibold text-stone-900">
                  {{ formatNumber(item.value) }}
                </p>
                <p class="mt-2 text-xs leading-6 text-slate-500">
                  表示当前运行态里为了降低 Bloom 误判而维护的精确集合大小。
                </p>
              </div>
            </div>
            <div
              v-else
              class="rounded-xl border border-dashed border-slate-200 bg-slate-50 p-5 text-sm leading-6 text-slate-500"
            >
              当前没有误判校验统计。通常意味着 Bloom
              未启用，或者运行实例还没有积累到可展示的校验数据。
            </div>
          </CyberCard>
        </div>
      </section>

      <CyberCard
        title="端口维度统计"
        sub-title="优先按拦截量、DDoS 事件和连接量排序，便于快速看出热点端口。"
        no-padding
      >
        <div v-if="topPorts.length" class="overflow-x-auto">
          <table class="min-w-full border-collapse text-left">
            <thead class="bg-slate-50 text-sm text-slate-500">
              <tr>
                <th class="px-4 py-3 font-medium">目标端口</th>
                <th class="px-4 py-3 font-medium">连接数</th>
                <th class="px-4 py-3 font-medium">拦截数</th>
                <th class="px-4 py-3 font-medium">DDoS 事件</th>
                <th class="px-4 py-3 font-medium">处理字节</th>
                <th class="px-4 py-3 font-medium">关注度</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="item in topPorts"
                :key="item.port"
                class="border-t border-slate-200 text-sm text-stone-800 transition hover:bg-[#fff8ef]"
              >
                <td class="px-4 py-3 font-mono font-semibold">
                  {{ item.port }}
                </td>
                <td class="px-4 py-3">{{ formatNumber(item.connections) }}</td>
                <td class="px-4 py-3">{{ formatNumber(item.blocks) }}</td>
                <td class="px-4 py-3">{{ formatNumber(item.ddos_events) }}</td>
                <td class="px-4 py-3">
                  {{ formatNumber(item.bytes_processed) }}
                </td>
                <td class="px-4 py-3">
                  <StatusBadge
                    :text="
                      item.blocks > 0 || item.ddos_events > 0
                        ? '重点关注'
                        : '流量观测'
                    "
                    :type="
                      item.blocks > 0 || item.ddos_events > 0
                        ? 'warning'
                        : 'muted'
                    "
                    compact
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="px-4 py-6 text-center text-sm text-slate-500">
          当前还没有端口级统计数据，通常意味着运行中的 L4 检测尚未接收到流量。
        </div>
      </CyberCard>

      <section class="grid gap-4 lg:grid-cols-3">
        <CyberCard
          title="限流阈值"
          sub-title="用于快速复核当前保存的关键阈值。"
        >
          <div class="space-y-3 text-sm text-stone-700">
            <div
              class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
            >
              <span>每秒连接阈值</span>
              <span class="font-mono font-semibold text-stone-900">{{
                formatNumber(configForm.connection_rate_limit)
              }}</span>
            </div>
            <div
              class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
            >
              <span>突发判定阈值</span>
              <span class="font-mono font-semibold text-stone-900">{{
                formatNumber(configForm.syn_flood_threshold)
              }}</span>
            </div>
          </div>
        </CyberCard>

        <CyberCard
          title="容量上限"
          sub-title="帮助判断跟踪表和封禁表的容量预估。"
        >
          <div class="space-y-3 text-sm text-stone-700">
            <div
              class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
            >
              <span>跟踪 IP 上限</span>
              <span class="font-mono font-semibold text-stone-900">{{
                formatNumber(configForm.max_tracked_ips)
              }}</span>
            </div>
            <div
              class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
            >
              <span>封禁表上限</span>
              <span class="font-mono font-semibold text-stone-900">{{
                formatNumber(configForm.max_blocked_ips)
              }}</span>
            </div>
            <div
              class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
            >
              <span>当前封禁占用</span>
              <div class="flex items-center gap-2">
                <span class="font-mono font-semibold text-stone-900">
                  {{
                    formatNumber(stats?.connections.blocked_connections || 0)
                  }}
                  / {{ formatNumber(configForm.max_blocked_ips) }}
                </span>
                <StatusBadge
                  :text="blockedCapacityLabel"
                  :type="blockedCapacityTone"
                  compact
                />
              </div>
            </div>
          </div>
        </CyberCard>

        <CyberCard
          title="清理策略"
          sub-title="维护任务会按这个 TTL 回收过期状态。"
        >
          <div class="space-y-3 text-sm text-stone-700">
            <div
              class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
            >
              <span>状态 TTL</span>
              <span class="font-mono font-semibold text-stone-900"
                >{{ formatNumber(configForm.state_ttl_secs) }} 秒</span
              >
            </div>
            <div
              class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
            >
              <span>Bloom 缩放</span>
              <span class="font-mono font-semibold text-stone-900">{{
                configForm.bloom_filter_scale.toFixed(2)
              }}</span>
            </div>
            <div
              class="flex items-center justify-between rounded-[18px] bg-slate-50 px-4 py-3"
            >
              <span>端口画像累计流量</span>
              <span class="font-mono font-semibold text-stone-900">
                {{
                  formatBytes(
                    topPorts.reduce(
                      (sum, item) => sum + item.bytes_processed,
                      0,
                    ),
                  )
                }}
              </span>
            </div>
          </div>
        </CyberCard>
      </section>
    </div>
  </AppLayout>
</template>
