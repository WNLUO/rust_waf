<script setup lang="ts">
import { onMounted, reactive, ref, watch } from 'vue'
import {
  fetchBlockedIps,
  pullSafeLineBlockedIps,
  syncSafeLineBlockedIps,
  unblockIp,
} from '@/shared/api/client'
import type { BlockedIpsResponse } from '@/shared/types'
import AppLayout from '@/app/layout/AppLayout.vue'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import { Ban, RefreshCw } from 'lucide-vue-next'

const { formatTimestamp, timeRemaining } = useFormatters()
const loading = ref(true)
const refreshing = ref(false)
const pulling = ref(false)
const pushing = ref(false)
const mutatingId = ref<number | null>(null)
const filtersReady = ref(false)
const error = ref('')
const successMessage = ref('')
const blockedPayload = ref<BlockedIpsResponse>({
  total: 0,
  limit: 0,
  offset: 0,
  blocked_ips: [],
})

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: '封禁名单',
  successTitle: '封禁名单',
  errorDuration: 5600,
  successDuration: 3200,
})

const blockedFilters = reactive({
  provider: 'all',
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
      provider:
        blockedFilters.provider === 'all' ? undefined : blockedFilters.provider,
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

const runSafeLinePull = async () => {
  pulling.value = true
  error.value = ''
  successMessage.value = ''

  try {
    const response = await pullSafeLineBlockedIps()
    successMessage.value = response.message
    await loadBlockedIps()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '拉取雷池封禁失败'
  } finally {
    pulling.value = false
  }
}

const runSafeLinePush = async () => {
  pushing.value = true
  error.value = ''
  successMessage.value = ''

  try {
    const response = await syncSafeLineBlockedIps()
    successMessage.value = response.message
    await loadBlockedIps()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '推送本地封禁失败'
  } finally {
    pushing.value = false
  }
}

const handleUnblock = async (id: number) => {
  mutatingId.value = id
  try {
    await unblockIp(id)
    await loadBlockedIps()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '解除封禁失败'
  } finally {
    mutatingId.value = null
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
        class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
        :disabled="pulling"
        @click="runSafeLinePull"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': pulling }" />
        {{ pulling ? '拉取中...' : '拉取雷池封禁' }}
      </button>
      <button
        class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
        :disabled="pushing"
        @click="runSafeLinePush"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': pushing }" />
        {{ pushing ? '推送中...' : '推送本地封禁' }}
      </button>
      <button
        class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
        :disabled="refreshing"
        @click="loadBlockedIps()"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
        刷新名单
      </button>
    </template>

    <div class="space-y-6">
      <div
        class="flex flex-wrap gap-3 rounded-[28px] border border-white/70 bg-white/60 p-4"
      >
        <label
          class="inline-flex items-center gap-2 rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <input
            v-model="blockedFilters.active_only"
            type="checkbox"
            class="accent-blue-600"
          />
          仅显示有效封禁
        </label>
        <select
          v-model="blockedFilters.provider"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="all">全部来源</option>
          <option value="safeline">雷池</option>
        </select>
        <select
          v-model="blockedFilters.sort_by"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="blocked_at">按封禁时间</option>
          <option value="expires_at">按到期时间</option>
          <option value="ip">按 IP</option>
        </select>
        <select
          v-model="blockedFilters.sort_direction"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="desc">降序</option>
          <option value="asc">升序</option>
        </select>
      </div>

      <div v-if="loading" class="text-sm text-slate-500">
        正在加载封禁名单...
      </div>

      <div v-else class="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        <article
          v-for="ip in blockedPayload.blocked_ips"
          :key="ip.id"
          class="rounded-xl border border-white/80 bg-white/78 p-4 shadow-[0_14px_40px_rgba(90,60,30,0.07)]"
        >
          <div class="flex items-start justify-between gap-4">
            <div
              class="flex h-12 w-12 items-center justify-center rounded-2xl bg-red-500/10 text-red-600"
            >
              <Ban :size="22" />
            </div>
            <button
              v-if="!ip.provider || ip.provider === 'safeline'"
              :disabled="mutatingId === ip.id"
              class="rounded-full border border-emerald-500/20 px-3 py-2 text-xs text-emerald-600 transition hover:bg-emerald-500/10"
              @click="handleUnblock(ip.id)"
            >
              {{
                mutatingId === ip.id
                  ? '处理中...'
                  : ip.provider === 'safeline'
                    ? '雷池解封'
                    : '解除封禁'
              }}
            </button>
            <span
              v-else
              class="rounded-full border border-slate-200 px-3 py-2 text-xs text-slate-500"
            >
              外部回流
            </span>
          </div>

          <h3 class="mt-3 font-mono text-2xl font-semibold text-stone-900">
            {{ ip.ip }}
          </h3>
          <p v-if="ip.provider" class="mt-2 text-xs text-blue-700">
            来源：{{ ip.provider }}
            <span v-if="ip.provider_remote_id">
              / 远端 ID：{{ ip.provider_remote_id }}</span
            >
          </p>
          <p class="mt-3 text-sm text-slate-500">
            封禁时间：{{ formatTimestamp(ip.blocked_at) }}
          </p>
          <p class="mt-2 text-sm text-slate-500">
            到期时间：{{ formatTimestamp(ip.expires_at) }}
          </p>
          <p class="mt-1 text-xs text-slate-500">
            剩余：{{ timeRemaining(ip.expires_at) }}
          </p>

          <div class="mt-3 rounded-xl bg-slate-50 p-4">
            <p class="text-xs tracking-wide text-slate-500">封禁原因</p>
            <p class="mt-2 text-sm leading-6 text-stone-800">{{ ip.reason }}</p>
          </div>
        </article>
        <p
          v-if="!blockedPayload.blocked_ips.length"
          class="text-sm text-slate-500"
        >
          当前没有处于封禁状态的地址。
        </p>
      </div>
    </div>
  </AppLayout>
</template>
