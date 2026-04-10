<script setup lang="ts">
import { onMounted, reactive, ref, watch } from 'vue'
import { fetchBlockedIps, unblockIp } from '../lib/api'
import type { BlockedIpsResponse } from '../lib/types'
import AppLayout from '../components/layout/AppLayout.vue'
import { useFormatters } from '../composables/useFormatters'
import { Ban, RefreshCw } from 'lucide-vue-next'

const { formatTimestamp, timeRemaining } = useFormatters()
const loading = ref(true)
const refreshing = ref(false)
const filtersReady = ref(false)
const error = ref('')
const blockedPayload = ref<BlockedIpsResponse>({ total: 0, limit: 0, offset: 0, blocked_ips: [] })

const blockedFilters = reactive({
  active_only: true,
  sort_by: 'blocked_at',
  sort_direction: 'desc' as 'asc' | 'desc',
})

const loadBlockedIps = async (showLoader = false) => {
  if (showLoader) loading.value = true
  refreshing.value = true
  try {
    blockedPayload.value = await fetchBlockedIps({
      limit: 30,
      active_only: blockedFilters.active_only,
      sort_by: blockedFilters.sort_by,
      sort_direction: blockedFilters.sort_direction,
    })
    error.value = ''
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取封禁名单失败'
  } finally {
    if (showLoader) loading.value = false
    refreshing.value = false
  }
}

const handleUnblock = async (id: number) => {
  try {
    await unblockIp(id)
    await loadBlockedIps()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '解除封禁失败'
  }
}

onMounted(async () => {
  await loadBlockedIps(true)
  filtersReady.value = true
})

watch(
  () => ({ ...blockedFilters }),
  () => {
    if (!filtersReady.value) return
    loadBlockedIps()
  },
  { deep: true },
)
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        @click="loadBlockedIps()"
        class="inline-flex items-center gap-2 rounded-full border border-cyber-border bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong disabled:opacity-60"
        :disabled="refreshing"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
        刷新名单
      </button>
    </template>

    <div class="space-y-6">
      <section class="rounded-[34px] border border-white/85 bg-[linear-gradient(140deg,rgba(255,250,244,0.92),rgba(244,239,231,0.96))] p-7 shadow-[0_26px_80px_rgba(90,60,30,0.10)]">
        <p class="text-sm tracking-[0.22em] text-cyber-accent-strong">封禁名单</p>
        <h2 class="mt-3 font-display text-4xl font-semibold text-stone-900">来源地址封控面板</h2>
        <p class="mt-4 max-w-2xl text-sm leading-7 text-stone-700">
          封禁页单独展示当前被限制访问的地址与原因，适合排查误封、手动解封和观察封禁过期节奏。
        </p>
      </section>

      <div
        v-if="error"
        class="rounded-[24px] border border-cyber-error/25 bg-cyber-error/8 px-5 py-4 text-sm text-cyber-error shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
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

      <div v-if="loading" class="text-sm text-cyber-muted">正在加载封禁名单...</div>

      <div v-else class="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
        <article
          v-for="ip in blockedPayload.blocked_ips"
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
        <p v-if="!blockedPayload.blocked_ips.length" class="text-sm text-cyber-muted">当前没有处于封禁状态的地址。</p>
      </div>
    </div>
  </AppLayout>
</template>
