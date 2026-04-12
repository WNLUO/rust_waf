<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import AppLayout from '@/app/layout/AppLayout.vue'
import L4SectionNav from '@/features/l4/components/L4SectionNav.vue'
import CyberCard from '@/shared/ui/CyberCard.vue'
import MetricWidget from '@/shared/ui/MetricWidget.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import { fetchL4Stats } from '@/shared/api/l4'
import type { L4PortStatItem, L4StatsPayload } from '@/shared/types'
import { Activity, AlertTriangle, Database, RefreshCw } from 'lucide-vue-next'

const { formatNumber } = useFormatters()

const loading = ref(true)
const refreshing = ref(false)
const error = ref('')
const stats = ref<L4StatsPayload | null>(null)
const refreshTimer = ref<number | null>(null)

useFlashMessages({
  error,
  errorTitle: '端口画像',
  errorDuration: 5600,
})

const filters = reactive({
  search: '',
  focus: 'all' as 'all' | 'blocked' | 'ddos' | 'connections',
  sort_by: 'blocks' as
    | 'blocks'
    | 'connections'
    | 'ddos_events'
    | 'bytes_processed'
    | 'port',
  sort_direction: 'desc' as 'asc' | 'desc',
})

const loadStats = async (showLoader = false) => {
  if (showLoader) loading.value = true
  refreshing.value = true
  try {
    stats.value = await fetchL4Stats()
    error.value = ''
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取端口画像失败'
  } finally {
    if (showLoader) loading.value = false
    refreshing.value = false
  }
}

const sortedPorts = computed(() => {
  const items = [...(stats.value?.per_port_stats ?? [])].filter((item) => {
    if (filters.focus === 'blocked' && item.blocks <= 0) return false
    if (filters.focus === 'ddos' && item.ddos_events <= 0) return false
    if (filters.focus === 'connections' && item.connections <= 0) return false
    if (filters.search.trim()) {
      const keyword = filters.search.trim().toLowerCase()
      return item.port.toLowerCase().includes(keyword)
    }
    return true
  })

  items.sort((left, right) => {
    const direction = filters.sort_direction === 'asc' ? 1 : -1
    const compare = (() => {
      switch (filters.sort_by) {
        case 'connections':
          return left.connections - right.connections
        case 'ddos_events':
          return left.ddos_events - right.ddos_events
        case 'bytes_processed':
          return left.bytes_processed - right.bytes_processed
        case 'port':
          return left.port.localeCompare(right.port, 'zh-CN', {
            numeric: true,
          })
        case 'blocks':
        default:
          return left.blocks - right.blocks
      }
    })()

    if (typeof compare === 'number') return compare * direction
    return 0
  })

  return items
})

const topByConnections = computed(
  () =>
    [...(stats.value?.per_port_stats ?? [])].sort(
      (left, right) => right.connections - left.connections,
    )[0] ?? null,
)
const topByBlocks = computed(
  () =>
    [...(stats.value?.per_port_stats ?? [])].sort(
      (left, right) => right.blocks - left.blocks,
    )[0] ?? null,
)
const ddosPorts = computed(() =>
  (stats.value?.per_port_stats ?? []).filter((item) => item.ddos_events > 0),
)
const totalBytes = computed(() =>
  (stats.value?.per_port_stats ?? []).reduce(
    (sum, item) => sum + item.bytes_processed,
    0,
  ),
)

const focusBadge = (item: L4PortStatItem) => {
  if (item.ddos_events > 0) return { text: 'DDoS 热点', type: 'error' as const }
  if (item.blocks > 0) return { text: '拦截热点', type: 'warning' as const }
  return { text: '流量观测', type: 'muted' as const }
}

onMounted(async () => {
  await loadStats(true)
  refreshTimer.value = window.setInterval(() => {
    loadStats()
  }, 5000)
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
      <button
        class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
        :disabled="refreshing"
        @click="loadStats()"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
        刷新画像
      </button>
    </template>

    <div class="space-y-6">
      <L4SectionNav />

      <section
        class="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm"
      >
        <p class="text-sm tracking-wider text-blue-700">端口画像</p>
        <h2 class="mt-3 font-sans text-4xl font-semibold text-stone-900">
          按端口观察连接、拦截与 DDoS 热点
        </h2>
        <p class="mt-4 max-w-3xl text-sm leading-7 text-stone-700">
          这里直接读取 L4 Inspector
          的端口级统计，适合值班时快速定位被重点扫描、被频繁拦截或出现洪泛特征的入口端口。
        </p>
      </section>

      <section class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricWidget
          label="观测端口数"
          :value="formatNumber(stats?.per_port_stats.length || 0)"
          :hint="`运行中端口画像条目 ${formatNumber(sortedPorts.length)}`"
          :icon="Database"
        />
        <MetricWidget
          label="最热连接端口"
          :value="topByConnections?.port || '暂无'"
          :hint="
            topByConnections
              ? `连接 ${formatNumber(topByConnections.connections)}`
              : '暂无数据'
          "
          :icon="Activity"
        />
        <MetricWidget
          label="最高拦截端口"
          :value="topByBlocks?.port || '暂无'"
          :hint="
            topByBlocks
              ? `拦截 ${formatNumber(topByBlocks.blocks)}`
              : '暂无数据'
          "
          :icon="AlertTriangle"
          trend="up"
        />
        <MetricWidget
          label="DDoS 端口数"
          :value="formatNumber(ddosPorts.length)"
          :hint="`累计字节 ${formatNumber(totalBytes)}`"
          :icon="RefreshCw"
        />
      </section>

      <section class="grid gap-4 xl:grid-cols-[0.95fr_1.05fr]">
        <CyberCard title="热点摘要" sub-title="帮助你先盯最值得看的几个端口。">
          <div class="space-y-4">
            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <p class="text-xs tracking-wide text-slate-500">连接最活跃</p>
              <p class="mt-2 text-2xl font-semibold text-stone-900">
                {{
                  topByConnections ? `${topByConnections.port} 端口` : '暂无'
                }}
              </p>
              <p class="mt-2 text-sm text-slate-500">
                {{
                  topByConnections
                    ? `累计连接 ${formatNumber(topByConnections.connections)}`
                    : '还没有足够的端口统计数据。'
                }}
              </p>
            </div>
            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <p class="text-xs tracking-wide text-slate-500">拦截最密集</p>
              <p class="mt-2 text-2xl font-semibold text-stone-900">
                {{ topByBlocks ? `${topByBlocks.port} 端口` : '暂无' }}
              </p>
              <p class="mt-2 text-sm text-slate-500">
                {{
                  topByBlocks
                    ? `拦截 ${formatNumber(topByBlocks.blocks)} 次 / DDoS ${formatNumber(topByBlocks.ddos_events)} 次`
                    : '暂无拦截热点。'
                }}
              </p>
            </div>
            <div class="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <p class="text-xs tracking-wide text-slate-500">DDoS 命中端口</p>
              <div class="mt-3 flex flex-wrap gap-2">
                <StatusBadge
                  v-for="item in ddosPorts.slice(0, 8)"
                  :key="item.port"
                  :text="`${item.port} / ${item.ddos_events}`"
                  type="error"
                  compact
                />
                <span v-if="!ddosPorts.length" class="text-sm text-slate-500"
                  >暂无 DDoS 热点。</span
                >
              </div>
            </div>
          </div>
        </CyberCard>

        <CyberCard title="筛选与排序" sub-title="按关注场景切换视角。">
          <div class="grid gap-4 md:grid-cols-2">
            <label class="text-sm text-stone-700">
              <span class="font-medium text-stone-900">搜索端口</span>
              <input
                v-model="filters.search"
                type="text"
                class="mt-2 w-full rounded-[18px] border border-slate-200 bg-white px-4 py-3 text-sm text-stone-800 outline-none transition focus:border-blue-500/40"
                placeholder="例如 22 / 443 / 8080"
              />
            </label>
            <label class="text-sm text-stone-700">
              <span class="font-medium text-stone-900">聚焦视角</span>
              <select
                v-model="filters.focus"
                class="mt-2 w-full rounded-[18px] border border-slate-200 bg-white px-4 py-3 text-sm text-stone-800 outline-none transition focus:border-blue-500/40"
              >
                <option value="all">全部端口</option>
                <option value="blocked">仅拦截热点</option>
                <option value="ddos">仅 DDoS 热点</option>
                <option value="connections">仅有连接流量</option>
              </select>
            </label>
            <label class="text-sm text-stone-700">
              <span class="font-medium text-stone-900">排序字段</span>
              <select
                v-model="filters.sort_by"
                class="mt-2 w-full rounded-[18px] border border-slate-200 bg-white px-4 py-3 text-sm text-stone-800 outline-none transition focus:border-blue-500/40"
              >
                <option value="blocks">按拦截数</option>
                <option value="connections">按连接数</option>
                <option value="ddos_events">按 DDoS 事件</option>
                <option value="bytes_processed">按处理字节</option>
                <option value="port">按端口号</option>
              </select>
            </label>
            <label class="text-sm text-stone-700">
              <span class="font-medium text-stone-900">排序方向</span>
              <select
                v-model="filters.sort_direction"
                class="mt-2 w-full rounded-[18px] border border-slate-200 bg-white px-4 py-3 text-sm text-stone-800 outline-none transition focus:border-blue-500/40"
              >
                <option value="desc">降序</option>
                <option value="asc">升序</option>
              </select>
            </label>
          </div>
        </CyberCard>
      </section>

      <div
        class="overflow-hidden rounded-xl border border-white/80 bg-white/78 shadow-[0_16px_44px_rgba(90,60,30,0.08)]"
      >
        <div class="overflow-x-auto">
          <table class="min-w-full border-collapse text-left">
            <thead class="bg-slate-50 text-sm text-slate-500">
              <tr>
                <th class="px-4 py-3 font-medium">目标端口</th>
                <th class="px-4 py-3 font-medium">连接数</th>
                <th class="px-4 py-3 font-medium">拦截数</th>
                <th class="px-4 py-3 font-medium">DDoS 事件</th>
                <th class="px-4 py-3 font-medium">处理字节</th>
                <th class="px-4 py-3 font-medium">画像标签</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="item in sortedPorts"
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
                    :text="focusBadge(item).text"
                    :type="focusBadge(item).type"
                    compact
                  />
                </td>
              </tr>
              <tr v-if="!sortedPorts.length && !loading">
                <td
                  colspan="6"
                  class="px-4 py-6 text-center text-sm text-slate-500"
                >
                  当前筛选条件下没有端口画像数据。
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </AppLayout>
</template>
