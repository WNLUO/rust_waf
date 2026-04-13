<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { fetchBlockedIps, unblockIp } from '@/shared/api/events'
import {
  pullSafeLineBlockedIps,
  syncSafeLineBlockedIps,
} from '@/shared/api/safeline'
import type { BlockedIpsResponse } from '@/shared/types'
import AppLayout from '@/app/layout/AppLayout.vue'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import {
  useAdminRealtimeState,
  useAdminRealtimeTopic,
} from '@/shared/realtime/adminRealtime'
import { RefreshCw } from 'lucide-vue-next'

const PAGE_SIZE = 30

const { formatTimestamp, timeRemaining } = useFormatters()
const loading = ref(true)
const refreshing = ref(false)
const pulling = ref(false)
const pushing = ref(false)
const mutatingId = ref<number | null>(null)
const filtersReady = ref(false)
const currentPage = ref(1)
const error = ref('')
const successMessage = ref('')
const pendingRealtimeCount = ref(0)
const realtimeState = useAdminRealtimeState()
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
  source_scope: 'all' as 'all' | 'local' | 'remote',
  provider: 'all',
  ip: '',
  keyword: '',
  active_only: true,
  blocked_from: '',
  blocked_to: '',
  sort_by: 'blocked_at',
  sort_direction: 'desc' as 'asc' | 'desc',
})

const toUnixTimestamp = (value: string) => {
  if (!value) return undefined
  const parsed = new Date(value).getTime()
  if (Number.isNaN(parsed)) return undefined
  return Math.floor(parsed / 1000)
}

const totalPages = computed(() =>
  Math.max(1, Math.ceil((blockedPayload.value.total || 0) / PAGE_SIZE)),
)
const pageStart = computed(() =>
  blockedPayload.value.total ? blockedPayload.value.offset + 1 : 0,
)
const pageEnd = computed(
  () => blockedPayload.value.offset + blockedPayload.value.blocked_ips.length,
)
const canInlineRefresh = computed(
  () =>
    currentPage.value === 1 &&
    blockedFilters.sort_by === 'blocked_at' &&
    blockedFilters.sort_direction === 'desc',
)

const matchesRealtimeFilters = (
  item: BlockedIpsResponse['blocked_ips'][number],
) => {
  if (
    blockedFilters.source_scope === 'local' &&
    item.provider
  ) {
    return false
  }
  if (
    blockedFilters.source_scope === 'remote' &&
    !item.provider
  ) {
    return false
  }
  if (
    blockedFilters.provider !== 'all' &&
    (item.provider || '').toLowerCase() !== blockedFilters.provider.toLowerCase()
  ) {
    return false
  }
  if (blockedFilters.ip.trim() && item.ip !== blockedFilters.ip.trim()) {
    return false
  }
  if (blockedFilters.keyword.trim()) {
    const keyword = blockedFilters.keyword.trim().toLowerCase()
    const haystack = `${item.ip} ${item.reason} ${item.provider || 'local'}`.toLowerCase()
    if (!haystack.includes(keyword)) {
      return false
    }
  }
  if (blockedFilters.active_only && item.expires_at <= Math.floor(Date.now() / 1000)) {
    return false
  }
  const blockedFrom = toUnixTimestamp(blockedFilters.blocked_from)
  if (blockedFrom !== undefined && item.blocked_at < blockedFrom) {
    return false
  }
  const blockedTo = toUnixTimestamp(blockedFilters.blocked_to)
  if (blockedTo !== undefined && item.blocked_at > blockedTo) {
    return false
  }
  return true
}

const mergeRealtimeBlockedIps = (
  incoming: BlockedIpsResponse['blocked_ips'],
) => {
  const matched = incoming.filter(matchesRealtimeFilters)
  if (!matched.length) return

  const existingIds = new Set(blockedPayload.value.blocked_ips.map((item) => item.id))
  const newUniqueCount = matched.filter((item) => !existingIds.has(item.id)).length
  const merged = [...matched, ...blockedPayload.value.blocked_ips]
  const deduped = merged.filter(
    (item, index, items) => items.findIndex((candidate) => candidate.id === item.id) === index,
  )

  blockedPayload.value = {
    ...blockedPayload.value,
    total: blockedPayload.value.total + newUniqueCount,
    blocked_ips: deduped.slice(0, PAGE_SIZE),
  }
}

const loadBlockedIps = async (showLoader = false) => {
  if (showLoader) loading.value = true
  refreshing.value = true
  try {
    blockedPayload.value = await fetchBlockedIps({
      limit: PAGE_SIZE,
      offset: (currentPage.value - 1) * PAGE_SIZE,
      source_scope: blockedFilters.source_scope,
      provider:
        blockedFilters.provider === 'all' ? undefined : blockedFilters.provider,
      ip: blockedFilters.ip.trim() || undefined,
      keyword: blockedFilters.keyword.trim() || undefined,
      active_only: blockedFilters.active_only,
      blocked_from: toUnixTimestamp(blockedFilters.blocked_from),
      blocked_to: toUnixTimestamp(blockedFilters.blocked_to),
      sort_by: blockedFilters.sort_by,
      sort_direction: blockedFilters.sort_direction,
    })
    error.value = ''

    if (currentPage.value > totalPages.value) {
      currentPage.value = totalPages.value
    }
    pendingRealtimeCount.value = 0
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
    currentPage.value = 1
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
  error.value = ''
  successMessage.value = ''
  try {
    const response = await unblockIp(id)
    successMessage.value = response.message
    await loadBlockedIps()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '解除封禁失败'
  } finally {
    mutatingId.value = null
  }
}

const goToPage = (page: number) => {
  currentPage.value = Math.min(Math.max(page, 1), totalPages.value)
}

useAdminRealtimeTopic<BlockedIpsResponse>('recent_blocked_ips', (payload) => {
  if (!payload.blocked_ips.length) return
  if (canInlineRefresh.value) {
    mergeRealtimeBlockedIps(payload.blocked_ips)
    pendingRealtimeCount.value = 0
    return
  }

  const matchedCount = payload.blocked_ips.filter(matchesRealtimeFilters).length
  if (matchedCount > 0) {
    pendingRealtimeCount.value = matchedCount
  }
})

onMounted(async () => {
  await loadBlockedIps(true)
  filtersReady.value = true
})

watch(
  () => ({ ...blockedFilters }),
  () => {
    if (!filtersReady.value) return
    currentPage.value = 1
    pendingRealtimeCount.value = 0
    loadBlockedIps()
  },
  { deep: true },
)

watch(currentPage, () => {
  if (!filtersReady.value) return
  pendingRealtimeCount.value = 0
  loadBlockedIps()
})
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <div class="flex flex-wrap items-center gap-2">
        <span class="text-xs text-slate-500">
          {{
            realtimeState.connected
              ? '实时通道已连接'
              : realtimeState.connecting
                ? '实时通道连接中'
                : '实时通道未连接'
          }}
        </span>
        <button
          v-if="pendingRealtimeCount > 0"
          class="inline-flex items-center gap-2 rounded-md border border-emerald-300 bg-emerald-50 px-3 py-1.5 text-xs text-emerald-700 hover:bg-emerald-100"
          @click="loadBlockedIps()"
        >
          有 {{ pendingRealtimeCount }} 条新封禁
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-60"
          :disabled="pulling"
          @click="runSafeLinePull"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': pulling }" />
          {{ pulling ? '拉取中' : '拉取雷池' }}
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-60"
          :disabled="pushing"
          @click="runSafeLinePush"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': pushing }" />
          {{ pushing ? '推送中' : '推送本地' }}
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-60"
          :disabled="refreshing"
          @click="loadBlockedIps()"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
          刷新
        </button>
      </div>
    </template>

    <div class="space-y-3">
      <div class="grid gap-2 md:grid-cols-3 xl:grid-cols-6">
        <select
          v-model="blockedFilters.source_scope"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
        >
          <option value="all">全部范围</option>
          <option value="local">仅本地</option>
          <option value="remote">仅远端</option>
        </select>
        <select
          v-model="blockedFilters.provider"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
        >
          <option value="all">全部来源</option>
          <option value="safeline">雷池</option>
        </select>
        <input
          v-model="blockedFilters.ip"
          type="text"
          placeholder="IP"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
        />
        <input
          v-model="blockedFilters.keyword"
          type="text"
          placeholder="关键词"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
        />
        <select
          v-model="blockedFilters.sort_by"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
        >
          <option value="blocked_at">按封禁时间</option>
          <option value="expires_at">按到期时间</option>
          <option value="ip">按 IP</option>
        </select>
        <select
          v-model="blockedFilters.sort_direction"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
        >
          <option value="desc">降序</option>
          <option value="asc">升序</option>
        </select>
      </div>

      <div class="grid gap-2 md:grid-cols-4 xl:grid-cols-6">
        <label
          class="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700"
        >
          <input
            v-model="blockedFilters.active_only"
            type="checkbox"
            class="accent-blue-600"
          />
          仅有效
        </label>
        <input
          v-model="blockedFilters.blocked_from"
          type="datetime-local"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
        />
        <input
          v-model="blockedFilters.blocked_to"
          type="datetime-local"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
        />
      </div>

      <div v-if="loading" class="text-sm text-slate-500">加载中...</div>

      <div
        v-else
        class="overflow-hidden rounded-md border border-slate-200 bg-white"
      >
        <div class="overflow-x-auto">
          <table class="w-full min-w-[980px] border-collapse text-left text-sm">
            <thead class="bg-slate-50 text-slate-600">
              <tr>
                <th class="px-3 py-2 font-medium">IP</th>
                <th class="px-3 py-2 font-medium">来源</th>
                <th class="px-3 py-2 font-medium">原因</th>
                <th class="px-3 py-2 font-medium">封禁时间</th>
                <th class="px-3 py-2 font-medium">到期</th>
                <th class="px-3 py-2 font-medium">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="ip in blockedPayload.blocked_ips"
                :key="ip.id"
                class="border-t border-slate-200 align-top text-slate-800"
              >
                <td class="px-3 py-2 font-mono text-xs text-slate-900">
                  {{ ip.ip }}
                </td>
                <td class="px-3 py-2">
                  <div class="space-y-1 text-xs">
                    <div class="text-slate-900">{{ ip.provider || 'local' }}</div>
                    <div v-if="ip.provider_remote_id" class="text-slate-500">
                      ID: {{ ip.provider_remote_id }}
                    </div>
                  </div>
                </td>
                <td class="px-3 py-2 text-sm text-slate-900">
                  <div class="max-w-[420px] break-all">{{ ip.reason }}</div>
                </td>
                <td class="px-3 py-2 text-xs text-slate-600">
                  {{ formatTimestamp(ip.blocked_at) }}
                </td>
                <td class="px-3 py-2 text-xs text-slate-600">
                  <div>{{ formatTimestamp(ip.expires_at) }}</div>
                  <div>{{ timeRemaining(ip.expires_at) }}</div>
                </td>
                <td class="px-3 py-2">
                  <button
                    v-if="!ip.provider || ip.provider === 'safeline'"
                    class="rounded-md border border-slate-300 bg-white px-2 py-1 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-60"
                    :disabled="mutatingId === ip.id"
                    @click="handleUnblock(ip.id)"
                  >
                    {{
                      mutatingId === ip.id
                        ? '处理中'
                        : ip.provider === 'safeline'
                          ? '雷池解封'
                          : '解除封禁'
                    }}
                  </button>
                  <span v-else class="text-xs text-slate-500">不可操作</span>
                </td>
              </tr>
              <tr v-if="!blockedPayload.blocked_ips.length">
                <td colspan="6" class="px-3 py-6 text-center text-sm text-slate-500">
                  无数据
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div
          class="flex flex-wrap items-center justify-between gap-2 border-t border-slate-200 px-3 py-2 text-xs text-slate-600"
        >
          <div>
            {{ pageStart }}-{{ pageEnd }} / {{ blockedPayload.total }}
          </div>
          <div class="flex items-center gap-2">
            <button
              class="rounded-md border border-slate-300 bg-white px-2 py-1 hover:bg-slate-50 disabled:opacity-50"
              :disabled="currentPage <= 1"
              @click="goToPage(currentPage - 1)"
            >
              上一页
            </button>
            <span>{{ currentPage }} / {{ totalPages }}</span>
            <button
              class="rounded-md border border-slate-300 bg-white px-2 py-1 hover:bg-slate-50 disabled:opacity-50"
              :disabled="currentPage >= totalPages"
              @click="goToPage(currentPage + 1)"
            >
              下一页
            </button>
          </div>
        </div>
      </div>
    </div>
  </AppLayout>
</template>
