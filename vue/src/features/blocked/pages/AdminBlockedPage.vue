<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import {
  cleanupExpiredBlockedIps,
  createBlockedIp,
  fetchBlockedIps,
  unblockIp,
  unblockIpsBatch,
} from '@/shared/api/events'
import {
  fetchSafeLineSyncState,
  pullSafeLineBlockedIps,
  syncSafeLineBlockedIps,
} from '@/shared/api/safeline'
import type { BlockedIpsResponse, SafeLineSyncOverviewResponse } from '@/shared/types'
import AppLayout from '@/app/layout/AppLayout.vue'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import {
  useAdminRealtimeState,
  useAdminRealtimeTopic,
} from '@/shared/realtime/adminRealtime'
import { RefreshCw, X } from 'lucide-vue-next'

const PAGE_SIZE = 30

const { formatTimestamp, timeRemaining } = useFormatters()
const loading = ref(true)
const refreshing = ref(false)
const pulling = ref(false)
const pushing = ref(false)
const mutatingId = ref<number | null>(null)
const creatingBlockedIp = ref(false)
const batchUnblocking = ref(false)
const cleaningExpired = ref(false)
const showBlockDialog = ref(false)
const filtersReady = ref(false)
const currentPage = ref(1)
const error = ref('')
const successMessage = ref('')
const pendingRealtimeCount = ref(0)
const selectedIds = ref<number[]>([])
const loadingSyncState = ref(false)
const realtimeState = useAdminRealtimeState()
const blockedPayload = ref<BlockedIpsResponse>({
  total: 0,
  limit: 0,
  offset: 0,
  blocked_ips: [],
})
const safeLineSyncState = ref<SafeLineSyncOverviewResponse>({
  events: null,
  blocked_ips_push: null,
  blocked_ips_pull: null,
  blocked_ips_delete: null,
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
const blockForm = reactive({
  ip: '',
  reason_preset: 'manual' as 'manual' | 'scanner' | 'flood' | 'payload' | 'custom',
  reason_custom: '',
  duration_preset: '1h' as '15m' | '1h' | '6h' | '24h' | '7d' | 'custom',
  duration_custom_minutes: 60,
})

const durationPresetSeconds: Record<'15m' | '1h' | '6h' | '24h' | '7d', number> = {
  '15m': 15 * 60,
  '1h': 60 * 60,
  '6h': 6 * 60 * 60,
  '24h': 24 * 60 * 60,
  '7d': 7 * 24 * 60 * 60,
}

const reasonPresetLabel: Record<'manual' | 'scanner' | 'flood' | 'payload', string> = {
  manual: '人工处置',
  scanner: '可疑扫描行为',
  flood: '高频请求/连接洪泛',
  payload: '恶意请求载荷',
}

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
const allSelectableIds = computed(() =>
  blockedPayload.value.blocked_ips.filter(canUnblock).map((item) => item.id),
)
const isAllSelected = computed(
  () =>
    allSelectableIds.value.length > 0 &&
    allSelectableIds.value.every((id) => selectedIds.value.includes(id)),
)

function canUnblock(item: BlockedIpsResponse['blocked_ips'][number]) {
  return !item.provider || item.provider === 'safeline'
}

const isSelected = (id: number) => selectedIds.value.includes(id)
const toggleSelected = (id: number, checked: boolean) => {
  if (checked) {
    if (!selectedIds.value.includes(id)) {
      selectedIds.value.push(id)
    }
    return
  }
  selectedIds.value = selectedIds.value.filter((item) => item !== id)
}
const toggleSelectAll = (checked: boolean) => {
  selectedIds.value = checked ? [...allSelectableIds.value] : []
}
const onSelectAllChange = (event: Event) => {
  const checked = (event.target as HTMLInputElement | null)?.checked || false
  toggleSelectAll(checked)
}
const onSelectOneChange = (id: number, event: Event) => {
  const checked = (event.target as HTMLInputElement | null)?.checked || false
  toggleSelected(id, checked)
}

const relatedEventsQuery = (item: BlockedIpsResponse['blocked_ips'][number]) => {
  const WINDOW_SECS = 1800
  return {
    source_ip: item.ip,
    blocked_only: '1',
    created_from: String(Math.max(0, item.blocked_at - WINDOW_SECS)),
    created_to: String(item.blocked_at + WINDOW_SECS),
    sort_by: 'created_at',
    sort_direction: 'desc',
  }
}

const syncStateItems = computed(() => [
  {
    key: 'push',
    label: '封禁推送',
    state: safeLineSyncState.value.blocked_ips_push,
  },
  {
    key: 'pull',
    label: '封禁回流',
    state: safeLineSyncState.value.blocked_ips_pull,
  },
  {
    key: 'delete',
    label: '远端解封',
    state: safeLineSyncState.value.blocked_ips_delete,
  },
])

const blockDurationSeconds = computed(() => {
  if (blockForm.duration_preset === 'custom') {
    const minutes = Math.max(1, Math.floor(Number(blockForm.duration_custom_minutes) || 0))
    return minutes * 60
  }
  return durationPresetSeconds[blockForm.duration_preset]
})

const blockReason = computed(() => {
  if (blockForm.reason_preset === 'custom') {
    return blockForm.reason_custom.trim()
  }
  return reasonPresetLabel[blockForm.reason_preset]
})

const blockExpiresAtPreview = computed(() =>
  Math.floor(Date.now() / 1000) + blockDurationSeconds.value,
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
    selectedIds.value = []
    pendingRealtimeCount.value = 0
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取封禁名单失败'
  } finally {
    if (showLoader) loading.value = false
    refreshing.value = false
  }
}

const loadSafeLineSyncState = async () => {
  loadingSyncState.value = true
  try {
    safeLineSyncState.value = await fetchSafeLineSyncState()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取雷池同步状态失败'
  } finally {
    loadingSyncState.value = false
  }
}

const openBlockDialog = () => {
  showBlockDialog.value = true
}

const closeBlockDialog = () => {
  if (creatingBlockedIp.value) return
  showBlockDialog.value = false
}

const handleCreateBlockedIp = async () => {
  const ip = blockForm.ip.trim()
  const reason = blockReason.value
  if (!ip) {
    error.value = '请填写要封禁的 IP'
    return
  }
  if (!reason) {
    error.value = '请填写封禁原因'
    return
  }

  creatingBlockedIp.value = true
  error.value = ''
  successMessage.value = ''
  try {
    const response = await createBlockedIp({
      ip,
      reason,
      duration_secs: blockDurationSeconds.value,
    })
    successMessage.value = response.message
    blockForm.ip = ''
    blockForm.reason_custom = ''
    currentPage.value = 1
    await loadBlockedIps()
    closeBlockDialog()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '新增封禁失败'
  } finally {
    creatingBlockedIp.value = false
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
    await loadSafeLineSyncState()
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
    await loadSafeLineSyncState()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '推送本地封禁失败'
  } finally {
    pushing.value = false
  }
}

const handleBatchUnblock = async () => {
  if (!selectedIds.value.length) return

  batchUnblocking.value = true
  error.value = ''
  successMessage.value = ''
  try {
    const response = await unblockIpsBatch({ ids: selectedIds.value })
    successMessage.value = response.message
    await loadBlockedIps()
    await loadSafeLineSyncState()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '批量解封失败'
  } finally {
    batchUnblocking.value = false
  }
}

const handleCleanupExpired = async () => {
  cleaningExpired.value = true
  error.value = ''
  successMessage.value = ''
  try {
    const response = await cleanupExpiredBlockedIps({
      source_scope: blockedFilters.source_scope,
      provider: blockedFilters.provider === 'all' ? undefined : blockedFilters.provider,
      blocked_from: toUnixTimestamp(blockedFilters.blocked_from),
      blocked_to: toUnixTimestamp(blockedFilters.blocked_to),
    })
    successMessage.value = response.message
    await loadBlockedIps()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '清理过期封禁失败'
  } finally {
    cleaningExpired.value = false
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
    await loadSafeLineSyncState()
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

useAdminRealtimeTopic<BlockedIpsResponse['blocked_ips'][number]>(
  'blocked_ip_upsert',
  (payload) => {
    if (!matchesRealtimeFilters(payload)) return
    if (canInlineRefresh.value) {
      mergeRealtimeBlockedIps([payload])
      pendingRealtimeCount.value = 0
      return
    }
    pendingRealtimeCount.value += 1
  },
)

useAdminRealtimeTopic<{ id: number }>('blocked_ip_deleted', ({ id }) => {
  const existed = blockedPayload.value.blocked_ips.some((item) => item.id === id)
  if (!existed) return
  blockedPayload.value = {
    ...blockedPayload.value,
    total: Math.max(0, blockedPayload.value.total - 1),
    blocked_ips: blockedPayload.value.blocked_ips.filter((item) => item.id !== id),
  }
})

onMounted(async () => {
  await Promise.all([loadBlockedIps(true), loadSafeLineSyncState()])
  filtersReady.value = true
})

watch(
  () => ({ ...blockedFilters }),
  () => {
    if (!filtersReady.value) return
    currentPage.value = 1
    selectedIds.value = []
    pendingRealtimeCount.value = 0
    loadBlockedIps()
  },
  { deep: true },
)

watch(currentPage, () => {
  if (!filtersReady.value) return
  selectedIds.value = []
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
        <button
          class="inline-flex items-center gap-2 rounded-md border border-blue-300 bg-blue-50 px-3 py-1.5 text-xs text-blue-700 hover:bg-blue-100 disabled:opacity-60"
          @click="openBlockDialog"
        >
          手动封禁
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-md border border-amber-300 bg-amber-50 px-3 py-1.5 text-xs text-amber-700 hover:bg-amber-100 disabled:opacity-60"
          :disabled="cleaningExpired"
          @click="handleCleanupExpired"
        >
          {{ cleaningExpired ? '清理中' : '清理过期' }}
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-md border border-rose-300 bg-rose-50 px-3 py-1.5 text-xs text-rose-700 hover:bg-rose-100 disabled:opacity-60"
          :disabled="batchUnblocking || !selectedIds.length"
          @click="handleBatchUnblock"
        >
          {{
            batchUnblocking
              ? '批量处理中'
              : selectedIds.length
                ? `批量解封(${selectedIds.length})`
                : '批量解封'
          }}
        </button>
      </div>
    </template>

    <div class="space-y-3">
      <div class="grid gap-2 md:grid-cols-3">
        <div
          v-for="item in syncStateItems"
          :key="item.key"
          class="rounded-md border border-slate-200 bg-white px-3 py-2"
        >
          <div class="text-xs text-slate-500">{{ item.label }}</div>
          <div class="mt-1 text-sm text-slate-800">
            {{
              item.state?.last_success_at
                ? `上次成功：${formatTimestamp(item.state.last_success_at)}`
                : loadingSyncState
                  ? '读取中...'
                  : '暂无成功记录'
            }}
          </div>
          <div class="mt-1 text-xs text-slate-600">
            导入/跳过：{{ item.state?.last_imported_count ?? 0 }} /
            {{ item.state?.last_skipped_count ?? 0 }}
          </div>
        </div>
      </div>

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
                <th class="px-3 py-2 font-medium">
                  <input
                    type="checkbox"
                    class="accent-blue-600"
                    :checked="isAllSelected"
                    @change="onSelectAllChange"
                  />
                </th>
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
                <td class="px-3 py-2">
                  <input
                    type="checkbox"
                    class="accent-blue-600"
                    :disabled="!canUnblock(ip)"
                    :checked="isSelected(ip.id)"
                    @change="onSelectOneChange(ip.id, $event)"
                  />
                </td>
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
                  <div class="flex flex-wrap items-center gap-2">
                    <button
                      v-if="canUnblock(ip)"
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
                    <RouterLink
                      class="rounded-md border border-slate-300 bg-white px-2 py-1 text-xs text-slate-700 hover:bg-slate-50"
                      :to="{ name: 'admin-events', query: relatedEventsQuery(ip) }"
                    >
                      相关事件
                    </RouterLink>
                  </div>
                </td>
              </tr>
              <tr v-if="!blockedPayload.blocked_ips.length">
                <td colspan="7" class="px-3 py-6 text-center text-sm text-slate-500">
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

    <div
      v-if="showBlockDialog"
      class="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/30 px-4"
    >
      <div class="absolute inset-0" @click="closeBlockDialog"></div>
      <div class="relative z-[101] w-full max-w-xl rounded-md border border-slate-300 bg-white">
        <div class="flex items-center justify-between border-b border-slate-200 px-4 py-3">
          <div>
            <div class="text-sm font-medium text-slate-900">手动封禁 IP</div>
            <div class="text-xs text-slate-500">只需填 IP，其他优先用预设即可</div>
          </div>
          <button
            class="inline-flex h-8 w-8 items-center justify-center rounded-md border border-slate-300 bg-white text-slate-600 hover:bg-slate-50"
            :disabled="creatingBlockedIp"
            @click="closeBlockDialog"
          >
            <X :size="16" />
          </button>
        </div>
        <div class="space-y-3 px-4 py-3">
          <div class="space-y-1">
            <label class="text-xs text-slate-600">IP 地址</label>
            <input
              v-model="blockForm.ip"
              type="text"
              placeholder="例如 1.2.3.4 或 2001:db8::1"
              class="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
            />
          </div>

          <div class="grid gap-3 md:grid-cols-2">
            <div class="space-y-1">
              <label class="text-xs text-slate-600">封禁时长</label>
              <select
                v-model="blockForm.duration_preset"
                class="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
              >
                <option value="15m">15 分钟</option>
                <option value="1h">1 小时（推荐）</option>
                <option value="6h">6 小时</option>
                <option value="24h">24 小时</option>
                <option value="7d">7 天</option>
                <option value="custom">自定义</option>
              </select>
            </div>
            <div v-if="blockForm.duration_preset === 'custom'" class="space-y-1">
              <label class="text-xs text-slate-600">自定义时长（分钟）</label>
              <input
                v-model.number="blockForm.duration_custom_minutes"
                type="number"
                min="1"
                step="1"
                class="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
              />
            </div>
          </div>

          <div class="space-y-1">
            <label class="text-xs text-slate-600">封禁原因</label>
            <select
              v-model="blockForm.reason_preset"
              class="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
            >
              <option value="manual">人工处置（推荐）</option>
              <option value="scanner">可疑扫描行为</option>
              <option value="flood">高频请求/连接洪泛</option>
              <option value="payload">恶意请求载荷</option>
              <option value="custom">自定义</option>
            </select>
          </div>
          <div v-if="blockForm.reason_preset === 'custom'" class="space-y-1">
            <label class="text-xs text-slate-600">自定义原因</label>
            <input
              v-model="blockForm.reason_custom"
              type="text"
              placeholder="请输入备注，例如：运维人工封禁"
              class="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
            />
          </div>

          <div class="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
            预计解封时间：{{ formatTimestamp(blockExpiresAtPreview) }}
          </div>
        </div>
        <div class="flex items-center justify-end gap-2 border-t border-slate-200 px-4 py-3">
          <button
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-60"
            :disabled="creatingBlockedIp"
            @click="closeBlockDialog"
          >
            取消
          </button>
          <button
            class="rounded-md border border-blue-300 bg-blue-50 px-3 py-2 text-sm text-blue-700 hover:bg-blue-100 disabled:opacity-60"
            :disabled="creatingBlockedIp"
            @click="handleCreateBlockedIp"
          >
            {{ creatingBlockedIp ? '封禁中...' : '确认封禁' }}
          </button>
        </div>
      </div>
    </div>
  </AppLayout>
</template>
