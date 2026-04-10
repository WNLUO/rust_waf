<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import AppLayout from '../components/layout/AppLayout.vue'
import L4SectionNav from '../components/l4/L4SectionNav.vue'
import StatusBadge from '../components/ui/StatusBadge.vue'
import { useFormatters } from '../composables/useFormatters'
import { fetchBlockedIps, fetchL4Config, fetchL4Stats, unblockIp } from '../lib/api'
import type { BlockedIpItem, BlockedIpsResponse, L4ConfigPayload, L4StatsPayload } from '../lib/types'
import { Ban, RefreshCw, Search, Shield } from 'lucide-vue-next'

const { formatTimestamp, timeRemaining } = useFormatters()

const loading = ref(true)
const refreshing = ref(false)
const mutatingId = ref<number | null>(null)
const error = ref('')
const successMessage = ref('')
const filtersReady = ref(false)
const blockedPayload = ref<BlockedIpsResponse>({ total: 0, limit: 0, offset: 0, blocked_ips: [] })
const l4Config = ref<L4ConfigPayload | null>(null)
const l4Stats = ref<L4StatsPayload | null>(null)

const filters = reactive({
  search: '',
  scope: 'local' as 'local' | 'all' | 'safeline',
  active_only: true,
  sort_by: 'blocked_at',
  sort_direction: 'desc' as 'asc' | 'desc',
})

const isLocalBlockedIp = (item: BlockedIpItem) => !item.provider || item.provider === 'local'

const filteredBlockedIps = computed(() =>
  blockedPayload.value.blocked_ips.filter((item) => {
    if (filters.search.trim()) {
      const keyword = filters.search.trim().toLowerCase()
      const provider = item.provider?.toLowerCase() ?? ''
      if (
        !item.ip.toLowerCase().includes(keyword) &&
        !item.reason.toLowerCase().includes(keyword) &&
        !provider.includes(keyword)
      ) {
        return false
      }
    }
    return true
  }),
)

const localBlockedCount = computed(() => filteredBlockedIps.value.filter(isLocalBlockedIp).length)
const remoteBlockedCount = computed(
  () => filteredBlockedIps.value.filter((item) => item.provider === 'safeline').length,
)
const capacityUsage = computed(() => {
  const maxBlocked = l4Config.value?.max_blocked_ips ?? 0
  if (!maxBlocked) return '暂无'
  const current = l4Stats.value?.connections.blocked_connections ?? 0
  return `${current} / ${maxBlocked}`
})

const loadPageData = async (showLoader = false) => {
  if (showLoader) loading.value = true
  refreshing.value = true
  try {
    const [blocked, config, stats] = await Promise.all([
      fetchBlockedIps({
        limit: 50,
        source_scope:
          filters.scope === 'local' ? 'local' : filters.scope === 'all' ? 'all' : 'remote',
        provider: filters.scope === 'safeline' ? 'safeline' : undefined,
        active_only: filters.active_only,
        sort_by: filters.sort_by,
        sort_direction: filters.sort_direction,
      }),
      fetchL4Config(),
      fetchL4Stats(),
    ])
    blockedPayload.value = blocked
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

watch(
  () => ({
    active_only: filters.active_only,
    sort_by: filters.sort_by,
    sort_direction: filters.sort_direction,
  }),
  () => {
    if (!filtersReady.value) return
    loadPageData()
  },
  { deep: true },
)
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        @click="loadPageData()"
        class="inline-flex items-center gap-2 rounded-full border border-cyber-border bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong disabled:opacity-60"
        :disabled="refreshing"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
        刷新名单
      </button>
    </template>

    <div class="space-y-6">
      <L4SectionNav />

      <section class="rounded-[34px] border border-white/85 bg-[linear-gradient(140deg,rgba(255,250,244,0.92),rgba(244,239,231,0.96))] p-7 shadow-[0_26px_80px_rgba(90,60,30,0.10)]">
        <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p class="text-sm tracking-[0.22em] text-cyber-accent-strong">L4 黑名单</p>
            <h2 class="mt-3 font-display text-4xl font-semibold text-stone-900">本地封禁与联动封禁统一视图</h2>
            <p class="mt-4 max-w-3xl text-sm leading-7 text-stone-700">
              这个页面默认优先看本地 L4 连接限流器产生的封禁项，同时保留查看远端回流封禁的能力，方便你判断当前封禁容量和清理节奏。
            </p>
          </div>
          <StatusBadge :text="`封禁容量 ${capacityUsage}`" type="info" />
        </div>
      </section>

      <section class="grid gap-4 md:grid-cols-3">
        <div class="rounded-[28px] border border-white/80 bg-white/75 p-5 shadow-[0_16px_44px_rgba(90,60,30,0.08)]">
          <p class="text-xs tracking-[0.2em] text-cyber-muted">本地封禁</p>
          <p class="mt-3 text-3xl font-semibold text-stone-900">{{ localBlockedCount }}</p>
        </div>
        <div class="rounded-[28px] border border-white/80 bg-white/75 p-5 shadow-[0_16px_44px_rgba(90,60,30,0.08)]">
          <p class="text-xs tracking-[0.2em] text-cyber-muted">雷池回流</p>
          <p class="mt-3 text-3xl font-semibold text-stone-900">{{ remoteBlockedCount }}</p>
        </div>
        <div class="rounded-[28px] border border-white/80 bg-white/75 p-5 shadow-[0_16px_44px_rgba(90,60,30,0.08)]">
          <p class="text-xs tracking-[0.2em] text-cyber-muted">运行时封禁计数</p>
          <p class="mt-3 text-3xl font-semibold text-stone-900">{{ l4Stats?.connections.blocked_connections ?? 0 }}</p>
        </div>
      </section>

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

      <div class="flex flex-wrap gap-3 rounded-[28px] border border-white/70 bg-white/60 p-4">
        <label class="flex min-w-[220px] flex-1 items-center gap-2 rounded-[20px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-cyber-muted">
          <Search :size="14" />
          <input
            v-model="filters.search"
            type="text"
            class="w-full bg-transparent text-stone-800 outline-none"
            placeholder="搜索 IP / 原因 / 来源"
          />
        </label>
        <select v-model="filters.scope" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <option value="local">仅本地 L4</option>
          <option value="all">全部来源</option>
          <option value="safeline">仅雷池</option>
        </select>
        <label class="inline-flex items-center gap-2 rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <input v-model="filters.active_only" type="checkbox" class="accent-[var(--color-cyber-accent)]" />
          仅显示有效封禁
        </label>
        <select v-model="filters.sort_by" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <option value="blocked_at">按封禁时间</option>
          <option value="expires_at">按到期时间</option>
          <option value="ip">按 IP</option>
        </select>
        <select v-model="filters.sort_direction" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <option value="desc">降序</option>
          <option value="asc">升序</option>
        </select>
      </div>

      <div v-if="loading" class="text-sm text-cyber-muted">正在加载 L4 黑名单...</div>

      <div v-else class="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
        <article
          v-for="item in filteredBlockedIps"
          :key="item.id"
          class="rounded-[30px] border border-white/80 bg-white/78 p-6 shadow-[0_14px_40px_rgba(90,60,30,0.07)]"
        >
          <div class="flex items-start justify-between gap-4">
            <div class="flex h-12 w-12 items-center justify-center rounded-2xl bg-cyber-error/10 text-cyber-error">
              <Ban :size="22" />
            </div>
            <StatusBadge
              :text="isLocalBlockedIp(item) ? '本地 L4' : item.provider || '外部来源'"
              :type="isLocalBlockedIp(item) ? 'warning' : 'muted'"
              compact
            />
          </div>

          <h3 class="mt-5 font-mono text-2xl font-semibold text-stone-900">{{ item.ip }}</h3>
          <p class="mt-3 text-sm text-cyber-muted">封禁时间：{{ formatTimestamp(item.blocked_at) }}</p>
          <p class="mt-2 text-sm text-cyber-muted">到期时间：{{ formatTimestamp(item.expires_at) }}</p>
          <p class="mt-1 text-xs text-cyber-muted">剩余：{{ timeRemaining(item.expires_at) }}</p>

          <div class="mt-5 rounded-[22px] bg-cyber-surface-strong p-4">
            <p class="text-xs tracking-[0.18em] text-cyber-muted">封禁原因</p>
            <p class="mt-2 text-sm leading-6 text-stone-800">{{ item.reason }}</p>
          </div>

          <div class="mt-5 flex items-center justify-between gap-3">
            <div class="text-xs text-cyber-muted">
              <p>记录 ID：{{ item.id }}</p>
              <p v-if="item.provider_remote_id">远端 ID：{{ item.provider_remote_id }}</p>
            </div>
            <button
              @click="handleUnblock(item.id)"
              :disabled="mutatingId === item.id"
              class="inline-flex items-center gap-2 rounded-full border border-cyber-success/20 px-3 py-2 text-xs text-cyber-success transition hover:bg-cyber-success/10 disabled:opacity-60"
            >
              <Shield :size="13" />
              {{ mutatingId === item.id ? '处理中...' : '解除封禁' }}
            </button>
          </div>
        </article>
        <p v-if="!filteredBlockedIps.length" class="text-sm text-cyber-muted">当前筛选条件下没有可显示的 L4 黑名单记录。</p>
      </div>
    </div>
  </AppLayout>
</template>
