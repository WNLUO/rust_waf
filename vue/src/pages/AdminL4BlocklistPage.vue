<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import AppLayout from '../components/layout/AppLayout.vue'
import L4SectionNav from '../components/l4/L4SectionNav.vue'
import StatusBadge from '../components/ui/StatusBadge.vue'
import { useFormatters } from '../composables/useFormatters'
import { useFlashMessages } from '../composables/useNotifications'
import {
  fetchBlockedIps,
  fetchL4Config,
  fetchL4Stats,
  unblockIp,
} from '../lib/api'
import type {
  BlockedIpItem,
  BlockedIpsResponse,
  L4ConfigPayload,
  L4StatsPayload,
} from '../lib/types'
import { Ban, RefreshCw, Search, Shield } from 'lucide-vue-next'

const { formatTimestamp, timeRemaining } = useFormatters()
const PAGE_SIZE = 24

const loading = ref(true)
const refreshing = ref(false)
const mutatingId = ref<number | null>(null)
const error = ref('')
const successMessage = ref('')
const filtersReady = ref(false)
const page = ref(1)
const searchTimer = ref<number | null>(null)
const blockedPayload = ref<BlockedIpsResponse>({
  total: 0,
  limit: PAGE_SIZE,
  offset: 0,
  blocked_ips: [],
})
const l4Config = ref<L4ConfigPayload | null>(null)
const l4Stats = ref<L4StatsPayload | null>(null)

const filters = reactive({
  search: '',
  scope: 'local' as 'local' | 'all' | 'safeline',
  active_only: true,
  sort_by: 'blocked_at',
  sort_direction: 'desc' as 'asc' | 'desc',
})

const isLocalBlockedIp = (item: BlockedIpItem) =>
  !item.provider || item.provider === 'local'

const filteredBlockedIps = computed(() => blockedPayload.value.blocked_ips)
const matchedTotal = computed(() => blockedPayload.value.total)
const localBlockedCount = computed(
  () => filteredBlockedIps.value.filter(isLocalBlockedIp).length,
)
const remoteBlockedCount = computed(
  () =>
    filteredBlockedIps.value.filter((item) => !isLocalBlockedIp(item)).length,
)
const totalPages = computed(() => {
  const limit = blockedPayload.value.limit || PAGE_SIZE
  return Math.max(1, Math.ceil((blockedPayload.value.total || 0) / limit))
})
const rangeStart = computed(() =>
  matchedTotal.value ? blockedPayload.value.offset + 1 : 0,
)
const rangeEnd = computed(
  () => blockedPayload.value.offset + filteredBlockedIps.value.length,
)
const canGoPrev = computed(() => page.value > 1)
const canGoNext = computed(() => page.value < totalPages.value)
const capacityUsage = computed(() => {
  const maxBlocked = l4Config.value?.max_blocked_ips ?? 0
  if (!maxBlocked) return '暂无'
  const current = l4Stats.value?.connections.blocked_connections ?? 0
  return `${current} / ${maxBlocked}`
})
const scopeSummary = computed(() => {
  if (filters.scope === 'local') return '当前只看本地 L4 限流与 DDoS 封禁记录。'
  if (filters.scope === 'safeline')
    return '当前只看雷池回流或远端来源封禁记录。'
  return '当前同时查看本地封禁与远端回流封禁。'
})

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: 'L4 黑名单',
  successTitle: 'L4 黑名单',
  errorDuration: 5600,
  successDuration: 3200,
})

const loadPageData = async (showLoader = false) => {
  if (showLoader) loading.value = true
  refreshing.value = true
  try {
    const [blocked, config, stats] = await Promise.all([
      fetchBlockedIps({
        limit: PAGE_SIZE,
        offset: (page.value - 1) * PAGE_SIZE,
        source_scope:
          filters.scope === 'local'
            ? 'local'
            : filters.scope === 'all'
              ? 'all'
              : 'remote',
        provider: filters.scope === 'safeline' ? 'safeline' : undefined,
        keyword: filters.search.trim() || undefined,
        active_only: filters.active_only,
        sort_by: filters.sort_by,
        sort_direction: filters.sort_direction,
      }),
      fetchL4Config(),
      fetchL4Stats(),
    ])
    blockedPayload.value = blocked
    const nextTotalPages = Math.max(
      1,
      Math.ceil((blocked.total || 0) / (blocked.limit || PAGE_SIZE)),
    )
    if (page.value > nextTotalPages) {
      page.value = nextTotalPages
      return
    }
    l4Config.value = config
    l4Stats.value = stats
    error.value = ''
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取 L4 黑名单失败'
  } finally {
    if (showLoader) loading.value = false
    refreshing.value = false
  }
}

const handleUnblock = async (id: number) => {
  mutatingId.value = id
  error.value = ''
  successMessage.value = ''
  try {
    await unblockIp(id)
    successMessage.value = `封禁记录 ${id} 已解除。`
    await loadPageData()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '解除封禁失败'
  } finally {
    mutatingId.value = null
  }
}

onMounted(async () => {
  await loadPageData(true)
  filtersReady.value = true
})

onBeforeUnmount(() => {
  if (searchTimer.value) {
    window.clearTimeout(searchTimer.value)
  }
})

watch(
  () => [
    filters.scope,
    filters.active_only,
    filters.sort_by,
    filters.sort_direction,
  ],
  () => {
    if (!filtersReady.value) return
    if (page.value !== 1) {
      page.value = 1
      return
    }
    loadPageData()
  },
)

watch(
  () => page.value,
  () => {
    if (!filtersReady.value) return
    loadPageData()
  },
)

watch(
  () => filters.search,
  () => {
    if (searchTimer.value) {
      window.clearTimeout(searchTimer.value)
    }
    searchTimer.value = window.setTimeout(() => {
      if (!filtersReady.value) return
      if (page.value !== 1) {
        page.value = 1
        return
      }
      loadPageData()
    }, 250)
  },
)
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
        :disabled="refreshing"
        @click="loadPageData()"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
        刷新名单
      </button>
    </template>

    <div class="space-y-6">
      <L4SectionNav />

      <section
        class="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm"
      >
        <div
          class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between"
        >
          <div>
            <p class="text-sm tracking-wider text-blue-700">L4 黑名单</p>
            <h2 class="mt-3 font-sans text-4xl font-semibold text-stone-900">
              本地封禁与联动封禁统一视图
            </h2>
            <p class="mt-4 max-w-3xl text-sm leading-7 text-stone-700">
              这个页面默认优先看本地 L4
              连接限流器产生的封禁项，同时保留查看远端回流封禁的能力，方便你判断当前封禁容量和清理节奏。
            </p>
            <p class="mt-3 text-xs leading-6 text-slate-500">
              {{ scopeSummary }}
            </p>
          </div>
          <StatusBadge :text="`封禁容量 ${capacityUsage}`" type="info" />
        </div>
      </section>

      <section class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <p class="text-xs tracking-wider text-slate-500">筛选命中总数</p>
          <p class="mt-3 text-3xl font-semibold text-stone-900">
            {{ matchedTotal }}
          </p>
        </div>
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <p class="text-xs tracking-wider text-slate-500">当前页本地封禁</p>
          <p class="mt-3 text-3xl font-semibold text-stone-900">
            {{ localBlockedCount }}
          </p>
        </div>
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <p class="text-xs tracking-wider text-slate-500">当前页远端回流</p>
          <p class="mt-3 text-3xl font-semibold text-stone-900">
            {{ remoteBlockedCount }}
          </p>
        </div>
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <p class="text-xs tracking-wider text-slate-500">运行时封禁计数</p>
          <p class="mt-3 text-3xl font-semibold text-stone-900">
            {{ l4Stats?.connections.blocked_connections ?? 0 }}
          </p>
        </div>
      </section>

      <div
        class="flex flex-wrap gap-3 rounded-[28px] border border-white/70 bg-white/60 p-4"
      >
        <label
          class="flex min-w-[220px] flex-1 items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-500"
        >
          <Search :size="14" />
          <input
            v-model="filters.search"
            type="text"
            class="w-full bg-transparent text-stone-800 outline-none"
            placeholder="搜索 IP / 原因 / 来源（后端模糊匹配）"
          />
        </label>
        <select
          v-model="filters.scope"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="local">仅本地 L4</option>
          <option value="all">全部来源</option>
          <option value="safeline">仅雷池</option>
        </select>
        <label
          class="inline-flex items-center gap-2 rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <input
            v-model="filters.active_only"
            type="checkbox"
            class="accent-blue-600"
          />
          仅显示有效封禁
        </label>
        <select
          v-model="filters.sort_by"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="blocked_at">按封禁时间</option>
          <option value="expires_at">按到期时间</option>
          <option value="ip">按 IP</option>
        </select>
        <select
          v-model="filters.sort_direction"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="desc">降序</option>
          <option value="asc">升序</option>
        </select>
        <div
          class="flex items-center rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-xs text-slate-500"
        >
          {{ matchedTotal }} 条命中，当前显示 {{ rangeStart }} - {{ rangeEnd }}
        </div>
      </div>

      <div v-if="loading" class="text-sm text-slate-500">
        正在加载 L4 黑名单...
      </div>

      <div v-else class="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        <article
          v-for="item in filteredBlockedIps"
          :key="item.id"
          class="rounded-xl border border-white/80 bg-white/78 p-4 shadow-[0_14px_40px_rgba(90,60,30,0.07)]"
        >
          <div class="flex items-start justify-between gap-4">
            <div
              class="flex h-12 w-12 items-center justify-center rounded-2xl bg-red-500/10 text-red-600"
            >
              <Ban :size="22" />
            </div>
            <StatusBadge
              :text="
                isLocalBlockedIp(item) ? '本地 L4' : item.provider || '外部来源'
              "
              :type="isLocalBlockedIp(item) ? 'warning' : 'muted'"
              compact
            />
          </div>

          <h3 class="mt-3 font-mono text-2xl font-semibold text-stone-900">
            {{ item.ip }}
          </h3>
          <p class="mt-3 text-sm text-slate-500">
            封禁时间：{{ formatTimestamp(item.blocked_at) }}
          </p>
          <p class="mt-2 text-sm text-slate-500">
            到期时间：{{ formatTimestamp(item.expires_at) }}
          </p>
          <p class="mt-1 text-xs text-slate-500">
            剩余：{{ timeRemaining(item.expires_at) }}
          </p>

          <div class="mt-3 rounded-xl bg-slate-50 p-4">
            <p class="text-xs tracking-wide text-slate-500">封禁原因</p>
            <p class="mt-2 text-sm leading-6 text-stone-800">
              {{ item.reason }}
            </p>
          </div>

          <div class="mt-3 flex items-center justify-between gap-3">
            <div class="text-xs text-slate-500">
              <p>记录 ID：{{ item.id }}</p>
              <p v-if="item.provider_remote_id">
                远端 ID：{{ item.provider_remote_id }}
              </p>
            </div>
            <button
              :disabled="mutatingId === item.id"
              class="inline-flex items-center gap-2 rounded-full border border-emerald-500/20 px-3 py-2 text-xs text-emerald-600 transition hover:bg-emerald-500/10 disabled:opacity-60"
              @click="handleUnblock(item.id)"
            >
              <Shield :size="13" />
              {{ mutatingId === item.id ? '处理中...' : '解除封禁' }}
            </button>
          </div>
        </article>
        <p v-if="!filteredBlockedIps.length" class="text-sm text-slate-500">
          当前筛选条件下没有可显示的 L4 黑名单记录。
        </p>
      </div>

      <div
        v-if="matchedTotal > 0"
        class="flex flex-col gap-3 rounded-[28px] border border-white/70 bg-white/60 px-4 py-3 md:flex-row md:items-center md:justify-between"
      >
        <div class="text-sm text-slate-500">
          第 {{ page }} / {{ totalPages }} 页，共
          {{ matchedTotal }} 条，当前显示 {{ rangeStart }} - {{ rangeEnd }}。
        </div>
        <div class="flex items-center gap-3">
          <button
            :disabled="!canGoPrev || refreshing"
            class="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 disabled:opacity-60"
            @click="page -= 1"
          >
            上一页
          </button>
          <button
            :disabled="!canGoNext || refreshing"
            class="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 disabled:opacity-60"
            @click="page += 1"
          >
            下一页
          </button>
        </div>
      </div>
    </div>
  </AppLayout>
</template>
