<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { fetchSecurityEvents } from '@/shared/api/events'
import { syncSafeLineEvents } from '@/shared/api/safeline'
import type { SecurityEventItem, SecurityEventsResponse } from '@/shared/types'
import AppLayout from '@/app/layout/AppLayout.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import {
  useAdminRealtimeState,
  useAdminRealtimeTopic,
} from '@/shared/realtime/adminRealtime'
import { Eye, RefreshCw, X } from 'lucide-vue-next'

const PAGE_SIZE = 30
const route = useRoute()

const { formatTimestamp, actionLabel, layerLabel } = useFormatters()
const loading = ref(true)
const refreshing = ref(false)
const syncing = ref(false)
const error = ref('')
const successMessage = ref('')
const filtersReady = ref(false)
const currentPage = ref(1)
const previewTitle = ref('')
const previewContent = ref('')
const pendingRealtimeCount = ref(0)
const realtimeState = useAdminRealtimeState()
const eventsPayload = ref<SecurityEventsResponse>({
  total: 0,
  limit: 0,
  offset: 0,
  events: [],
})

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: '事件记录',
  successTitle: '事件记录',
  errorDuration: 5600,
  successDuration: 3200,
})

const eventsFilters = reactive({
  layer: 'all',
  provider: 'all',
  provider_site_id: 'all',
  action: 'all',
  blocked_only: false,
  handled: 'all' as 'all' | 'handled' | 'unhandled',
  source_ip: '',
  created_from: '',
  created_to: '',
  sort_by: 'created_at',
  sort_direction: 'desc' as 'asc' | 'desc',
})
const showAdvancedFiltersDialog = ref(false)
const advancedFiltersDraft = reactive({
  provider: 'all',
  provider_site_id: 'all',
  blocked_only: false,
  created_from: '',
  created_to: '',
  sort_by: 'created_at',
  sort_direction: 'desc' as 'asc' | 'desc',
})

const openAdvancedFilters = () => {
  advancedFiltersDraft.provider = eventsFilters.provider
  advancedFiltersDraft.provider_site_id = eventsFilters.provider_site_id
  advancedFiltersDraft.blocked_only = eventsFilters.blocked_only
  advancedFiltersDraft.created_from = eventsFilters.created_from
  advancedFiltersDraft.created_to = eventsFilters.created_to
  advancedFiltersDraft.sort_by = eventsFilters.sort_by
  advancedFiltersDraft.sort_direction = eventsFilters.sort_direction
  showAdvancedFiltersDialog.value = true
}

const closeAdvancedFilters = () => {
  showAdvancedFiltersDialog.value = false
}

const resetAdvancedFilters = () => {
  advancedFiltersDraft.provider = 'all'
  advancedFiltersDraft.provider_site_id = 'all'
  advancedFiltersDraft.blocked_only = false
  advancedFiltersDraft.created_from = ''
  advancedFiltersDraft.created_to = ''
  advancedFiltersDraft.sort_by = 'created_at'
  advancedFiltersDraft.sort_direction = 'desc'
}

const applyAdvancedFilters = () => {
  eventsFilters.provider = advancedFiltersDraft.provider
  eventsFilters.provider_site_id = advancedFiltersDraft.provider_site_id
  eventsFilters.blocked_only = advancedFiltersDraft.blocked_only
  eventsFilters.created_from = advancedFiltersDraft.created_from
  eventsFilters.created_to = advancedFiltersDraft.created_to
  eventsFilters.sort_by = advancedFiltersDraft.sort_by
  eventsFilters.sort_direction = advancedFiltersDraft.sort_direction
  closeAdvancedFilters()
}

const toUnixTimestamp = (value: string) => {
  if (!value) return undefined
  const parsed = new Date(value).getTime()
  if (Number.isNaN(parsed)) return undefined
  return Math.floor(parsed / 1000)
}

const toDatetimeLocalString = (unix: number) => {
  const date = new Date(unix * 1000)
  const pad = (value: number) => String(value).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}

const totalPages = computed(() =>
  Math.max(1, Math.ceil((eventsPayload.value.total || 0) / PAGE_SIZE)),
)
const pageStart = computed(() =>
  eventsPayload.value.total ? eventsPayload.value.offset + 1 : 0,
)
const pageEnd = computed(
  () => eventsPayload.value.offset + eventsPayload.value.events.length,
)
const canInlineRefresh = computed(
  () =>
    currentPage.value === 1 &&
    eventsFilters.sort_by === 'created_at' &&
    eventsFilters.sort_direction === 'desc',
)

const matchesRealtimeFilters = (event: SecurityEventItem) => {
  if (
    eventsFilters.layer !== 'all' &&
    event.layer.toLowerCase() !== eventsFilters.layer.toLowerCase()
  ) {
    return false
  }
  if (
    eventsFilters.provider !== 'all' &&
    (event.provider || '').toLowerCase() !== eventsFilters.provider.toLowerCase()
  ) {
    return false
  }
  if (
    eventsFilters.provider_site_id !== 'all' &&
    event.provider_site_id !== eventsFilters.provider_site_id
  ) {
    return false
  }
  if (
    eventsFilters.action !== 'all' &&
    event.action.toLowerCase() !== eventsFilters.action.toLowerCase()
  ) {
    return false
  }
  if (eventsFilters.blocked_only && event.action.toLowerCase() !== 'block') {
    return false
  }
  if (
    eventsFilters.handled === 'handled' &&
    !event.handled
  ) {
    return false
  }
  if (
    eventsFilters.handled === 'unhandled' &&
    event.handled
  ) {
    return false
  }
  if (
    eventsFilters.source_ip.trim() &&
    event.source_ip !== eventsFilters.source_ip.trim()
  ) {
    return false
  }
  const createdFrom = toUnixTimestamp(eventsFilters.created_from)
  if (createdFrom !== undefined && event.created_at < createdFrom) {
    return false
  }
  const createdTo = toUnixTimestamp(eventsFilters.created_to)
  if (createdTo !== undefined && event.created_at > createdTo) {
    return false
  }
  return true
}

const mergeRealtimeEvents = (incoming: SecurityEventItem[]) => {
  const matched = incoming.filter(matchesRealtimeFilters)
  if (!matched.length) return

  const existingIds = new Set(eventsPayload.value.events.map((event) => event.id))
  const newUniqueCount = matched.filter((event) => !existingIds.has(event.id)).length
  const merged = [...matched, ...eventsPayload.value.events]
  const deduped = merged.filter(
    (event, index, items) => items.findIndex((item) => item.id === event.id) === index,
  )

  eventsPayload.value = {
    ...eventsPayload.value,
    total: eventsPayload.value.total + newUniqueCount,
    events: deduped.slice(0, PAGE_SIZE),
  }
}

const loadEvents = async (showLoader = false) => {
  if (showLoader) loading.value = true
  refreshing.value = true
  try {
    eventsPayload.value = await fetchSecurityEvents({
      limit: PAGE_SIZE,
      offset: (currentPage.value - 1) * PAGE_SIZE,
      sort_by: eventsFilters.sort_by,
      sort_direction: eventsFilters.sort_direction,
      blocked_only: eventsFilters.blocked_only,
      layer: eventsFilters.layer === 'all' ? undefined : eventsFilters.layer,
      provider:
        eventsFilters.provider === 'all' ? undefined : eventsFilters.provider,
      provider_site_id:
        eventsFilters.provider_site_id === 'all'
          ? undefined
          : eventsFilters.provider_site_id,
      action: eventsFilters.action === 'all' ? undefined : eventsFilters.action,
      handled_only:
        eventsFilters.handled === 'all'
          ? undefined
          : eventsFilters.handled === 'handled',
      source_ip: eventsFilters.source_ip.trim() || undefined,
      created_from: toUnixTimestamp(eventsFilters.created_from),
      created_to: toUnixTimestamp(eventsFilters.created_to),
    })
    error.value = ''

    if (currentPage.value > totalPages.value) {
      currentPage.value = totalPages.value
    }
    pendingRealtimeCount.value = 0
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取事件失败'
  } finally {
    if (showLoader) loading.value = false
    refreshing.value = false
  }
}

const runSafeLineSync = async () => {
  syncing.value = true
  error.value = ''
  successMessage.value = ''

  try {
    const response = await syncSafeLineEvents()
    successMessage.value = response.message
    currentPage.value = 1
    await loadEvents()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '同步雷池事件失败'
  } finally {
    syncing.value = false
  }
}

const openPreview = (title: string, content: string | null | undefined) => {
  if (!content) return
  previewTitle.value = title
  previewContent.value = content
}

const closePreview = () => {
  previewTitle.value = ''
  previewContent.value = ''
}

const safeLineActionMap: Record<string, string> = {
  '0': '检测',
  '1': '拦截',
}

const safeLineAttackTypeMap: Record<string, string> = {
  '7': '漏洞利用',
  '8': '代码注入',
  '10': '文件上传',
}
const REASON_PREVIEW_LIMIT = 72
const PATH_PREVIEW_LIMIT = 48

const getSafeLineAttackTypeCode = (event: SecurityEventItem) => {
  if (event.layer.toLowerCase() !== 'safeline') return null
  const matched = event.reason.match(/^safeline:([^:]+):/)
  return matched?.[1] ?? null
}

const eventActionLabel = (action: string) => {
  const normalized = action.trim().toLowerCase()
  if (normalized in safeLineActionMap) {
    return safeLineActionMap[normalized]
  }
  if (['block', 'allow', 'alert', 'log'].includes(normalized)) {
    return actionLabel(normalized)
  }
  return `未知动作(${action})`
}

const eventActionBadgeType = (action: string) => {
  const normalized = action.trim().toLowerCase()
  if (normalized === '1' || normalized === 'block') return 'error'
  if (normalized === 'allow') return 'success'
  if (normalized === '0' || normalized === 'alert' || normalized === 'log') {
    return 'warning'
  }
  return 'warning'
}

const shouldShowActionBadge = (action: string) =>
  action.trim().toLowerCase() !== 'respond'

const eventAttackTypeLabel = (event: SecurityEventItem) => {
  const code = getSafeLineAttackTypeCode(event)
  if (!code) return ''
  return safeLineAttackTypeMap[code] || `未知类型(${code})`
}

const eventReasonLabel = (event: SecurityEventItem) => {
  if (event.layer.toLowerCase() !== 'safeline') return event.reason

  const attackTypeCode = getSafeLineAttackTypeCode(event)
  const attackTypeLabel = attackTypeCode
    ? safeLineAttackTypeMap[attackTypeCode]
    : ''
  const normalized = event.reason.replace(/^safeline:[^:]+:/, '').trim()

  if (attackTypeCode && normalized === `检测到 ${attackTypeCode} 攻击`) {
    return attackTypeLabel || normalized
  }

  return normalized || event.reason
}

const truncateText = (value: string, limit: number) =>
  value.length > limit ? `${value.slice(0, limit)}…` : value

const eventReasonPreview = (event: SecurityEventItem) =>
  truncateText(eventReasonLabel(event), REASON_PREVIEW_LIMIT)

const isReasonTruncated = (event: SecurityEventItem) =>
  eventReasonLabel(event).length > REASON_PREVIEW_LIMIT

const eventPathText = (event: SecurityEventItem) =>
  `${event.http_method || '-'}${event.uri ? ` ${event.uri}` : ''}`

const eventPathPreview = (event: SecurityEventItem) =>
  truncateText(eventPathText(event), PATH_PREVIEW_LIMIT)

const isPathTruncated = (event: SecurityEventItem) =>
  eventPathText(event).length > PATH_PREVIEW_LIMIT

const parseEventDetails = (event: SecurityEventItem) => {
  if (!event.details_json) return null
  try {
    return JSON.parse(event.details_json) as {
      client_identity?: Record<string, unknown>
    }
  } catch {
    return null
  }
}

const hasClientIdentityDebug = (event: SecurityEventItem) =>
  Boolean(parseEventDetails(event)?.client_identity)

const openClientIdentityDebug = (event: SecurityEventItem) => {
  const details = parseEventDetails(event)
  const payload = details?.client_identity ?? details
  if (!payload) return
  openPreview('客户端身份调试', JSON.stringify(payload, null, 2))
}

const siteOptions = computed(() => {
  const seen = new Map<string, string>()
  for (const event of eventsPayload.value.events) {
    if (!event.provider_site_id) continue
    seen.set(
      event.provider_site_id,
      event.provider_site_name ||
        event.provider_site_domain ||
        event.provider_site_id,
    )
  }
  return Array.from(seen.entries()).map(([id, label]) => ({ id, label }))
})

const goToPage = (page: number) => {
  currentPage.value = Math.min(Math.max(page, 1), totalPages.value)
}

const applyFiltersFromRouteQuery = () => {
  const query = route.query
  const getValue = (key: string) => {
    const value = query[key]
    if (Array.isArray(value)) return value[0]
    return value
  }

  const sourceIp = getValue('source_ip')
  if (typeof sourceIp === 'string' && sourceIp.trim()) {
    eventsFilters.source_ip = sourceIp.trim()
  }

  const blockedOnly = getValue('blocked_only')
  if (typeof blockedOnly === 'string') {
    const normalized = blockedOnly.trim().toLowerCase()
    eventsFilters.blocked_only = ['1', 'true', 'yes', 'on'].includes(normalized)
  }

  const createdFrom = getValue('created_from')
  if (typeof createdFrom === 'string') {
    const unix = Number(createdFrom)
    if (Number.isFinite(unix) && unix > 0) {
      eventsFilters.created_from = toDatetimeLocalString(unix)
    }
  }

  const createdTo = getValue('created_to')
  if (typeof createdTo === 'string') {
    const unix = Number(createdTo)
    if (Number.isFinite(unix) && unix > 0) {
      eventsFilters.created_to = toDatetimeLocalString(unix)
    }
  }

  const sortBy = getValue('sort_by')
  if (sortBy === 'created_at' || sortBy === 'source_ip' || sortBy === 'dest_port') {
    eventsFilters.sort_by = sortBy
  }

  const sortDirection = getValue('sort_direction')
  if (sortDirection === 'asc' || sortDirection === 'desc') {
    eventsFilters.sort_direction = sortDirection
  }
}

useAdminRealtimeTopic<SecurityEventsResponse>('recent_events', (payload) => {
  if (!payload.events.length) return
  if (canInlineRefresh.value) {
    mergeRealtimeEvents(payload.events)
    pendingRealtimeCount.value = 0
    return
  }

  const matchedCount = payload.events.filter(matchesRealtimeFilters).length
  if (matchedCount > 0) {
    pendingRealtimeCount.value = matchedCount
  }
})

useAdminRealtimeTopic<SecurityEventItem>('security_event_delta', (payload) => {
  if (!matchesRealtimeFilters(payload)) return
  if (canInlineRefresh.value) {
    mergeRealtimeEvents([payload])
    pendingRealtimeCount.value = 0
    return
  }
  pendingRealtimeCount.value += 1
})

onMounted(async () => {
  applyFiltersFromRouteQuery()
  await loadEvents(true)
  filtersReady.value = true
})

watch(
  () => ({ ...eventsFilters }),
  () => {
    if (!filtersReady.value) return
    currentPage.value = 1
    pendingRealtimeCount.value = 0
    loadEvents()
  },
  { deep: true },
)

watch(currentPage, () => {
  if (!filtersReady.value) return
  pendingRealtimeCount.value = 0
  loadEvents()
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
          @click="loadEvents()"
        >
          有 {{ pendingRealtimeCount }} 条新事件
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-60"
          :disabled="syncing"
          @click="runSafeLineSync"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': syncing }" />
          {{ syncing ? '同步中' : '同步雷池' }}
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-60"
          :disabled="refreshing"
          @click="loadEvents()"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
          刷新
        </button>
      </div>
    </template>

    <div class="space-y-3">
      <div class="flex flex-wrap items-center gap-2 xl:flex-nowrap">
        <select
          v-model="eventsFilters.layer"
          class="w-full min-w-[140px] rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 xl:w-auto"
        >
          <option value="all">全部层级</option>
          <option value="l4">四层</option>
          <option value="l7">HTTP</option>
          <option value="safeline">雷池</option>
        </select>
        <select
          v-model="eventsFilters.action"
          class="w-full min-w-[140px] rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 xl:w-auto"
        >
          <option value="all">全部动作</option>
          <option value="block">拦截</option>
          <option value="allow">放行</option>
          <option value="alert">告警</option>
          <option value="log">记录</option>
        </select>
        <select
          v-model="eventsFilters.handled"
          class="w-full min-w-[140px] rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 xl:w-auto"
        >
          <option value="all">全部状态</option>
          <option value="unhandled">未处理</option>
          <option value="handled">已处理</option>
        </select>
        <input
          v-model="eventsFilters.source_ip"
          type="text"
          placeholder="源 IP"
          class="w-full min-w-[180px] rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 xl:w-[220px]"
        />
        <button
          class="inline-flex items-center justify-center rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700 hover:bg-slate-50"
          @click="openAdvancedFilters"
        >
          高级筛选
        </button>
      </div>

      <div v-if="loading" class="text-sm text-slate-500">加载中...</div>

      <div
        v-else
        class="overflow-hidden rounded-md border border-slate-200 bg-white"
      >
        <div class="overflow-x-auto">
          <table class="min-w-max w-full border-collapse text-sm whitespace-nowrap">
            <thead class="bg-slate-50 text-slate-600">
              <tr>
                <th class="px-3 py-2 text-center font-medium">时间</th>
                <th class="px-3 py-2 text-center font-medium">层级/动作</th>
                <th class="px-3 py-2 text-center font-medium">来源</th>
                <th class="px-3 py-2 text-center font-medium">目标/请求</th>
                <th class="px-3 py-2 text-center font-medium">原因</th>
                <th class="px-3 py-2 text-center font-medium">路径</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="event in eventsPayload.events"
                :key="event.id"
                class="border-t border-slate-200 align-middle text-slate-800"
              >
                <td class="px-3 py-2">
                  <div class="space-y-1 text-center">
                    <div class="font-mono text-xs text-slate-900">
                      {{ formatTimestamp(event.created_at) }}
                    </div>
                  </div>
                </td>
                <td class="px-3 py-2">
                  <div class="flex flex-nowrap justify-center gap-1">
                    <StatusBadge
                      :text="layerLabel(event.layer)"
                      :type="event.layer.toLowerCase() === 'l7' ? 'info' : 'warning'"
                      compact
                    />
                    <StatusBadge
                      v-if="shouldShowActionBadge(event.action)"
                      :text="eventActionLabel(event.action)"
                      :type="eventActionBadgeType(event.action)"
                      compact
                    />
                    <StatusBadge
                      v-if="eventAttackTypeLabel(event)"
                      :text="eventAttackTypeLabel(event)"
                      type="muted"
                      compact
                    />
                  </div>
                </td>
                <td class="px-3 py-2">
                  <div class="font-mono text-center text-xs text-slate-900">
                    {{ event.source_ip }}
                  </div>
                </td>
                <td class="px-3 py-2">
                  <div class="flex items-center justify-center gap-2 text-xs whitespace-nowrap">
                    <div class="font-mono text-slate-600">
                      {{ event.protocol }}
                      <span v-if="event.http_version"> / {{ event.http_version }}</span>
                    </div>
                  </div>
                </td>
                <td class="px-3 py-2">
                  <div class="flex items-center justify-center gap-2">
                    <div class="min-w-0">
                      <div
                        class="event-reason-text text-sm text-slate-900"
                        :title="eventReasonLabel(event)"
                      >
                        {{ eventReasonPreview(event) }}
                      </div>
                    </div>
                    <button
                      v-if="isReasonTruncated(event)"
                      class="inline-flex h-7 items-center justify-center whitespace-nowrap rounded-md border border-slate-300 bg-white px-2 text-xs text-slate-600 hover:bg-slate-50"
                      title="查看完整原因"
                      @click="openPreview('完整原因', eventReasonLabel(event))"
                    >
                      更多
                    </button>
                    <button
                      v-if="event.details_json"
                      class="inline-flex h-7 w-7 items-center justify-center rounded-md border border-slate-300 bg-white text-slate-600 hover:bg-slate-50"
                      title="查看详情"
                      @click="openPreview('事件详情', event.details_json)"
                    >
                      <Eye :size="14" />
                    </button>
                    <button
                      v-if="hasClientIdentityDebug(event)"
                      class="inline-flex h-7 items-center justify-center whitespace-nowrap rounded-md border border-blue-200 bg-blue-50 px-2 text-xs text-blue-700 hover:bg-blue-100"
                      title="查看客户端身份调试"
                      @click="openClientIdentityDebug(event)"
                    >
                      身份调试
                    </button>
                  </div>
                </td>
                <td class="px-3 py-2">
                  <div class="flex items-center justify-center gap-2">
                    <div
                      class="event-path-text font-mono text-xs text-slate-700"
                      :title="eventPathText(event)"
                    >
                      {{ eventPathPreview(event) }}
                    </div>
                    <button
                      v-if="isPathTruncated(event)"
                      class="inline-flex h-7 items-center justify-center whitespace-nowrap rounded-md border border-slate-300 bg-white px-2 text-xs text-slate-600 hover:bg-slate-50"
                      title="查看完整路径"
                      @click="openPreview('完整路径', eventPathText(event))"
                    >
                      更多
                    </button>
                  </div>
                </td>
              </tr>
              <tr v-if="!eventsPayload.events.length">
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
            {{ pageStart }}-{{ pageEnd }} / {{ eventsPayload.total }}
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
      v-if="showAdvancedFiltersDialog"
      class="fixed inset-0 z-[95] flex items-center justify-center bg-slate-950/30 px-4"
    >
      <div
        class="absolute inset-0"
        @click="closeAdvancedFilters"
      ></div>
      <div
        class="relative z-[96] w-full max-w-2xl rounded-md border border-slate-300 bg-white"
      >
        <div class="flex items-center justify-between border-b border-slate-200 px-4 py-3">
          <div class="text-sm font-medium text-slate-900">高级筛选</div>
          <button
            class="inline-flex h-8 w-8 items-center justify-center rounded-md border border-slate-300 bg-white text-slate-600 hover:bg-slate-50"
            @click="closeAdvancedFilters"
          >
            <X :size="16" />
          </button>
        </div>
        <div class="grid gap-3 p-4 md:grid-cols-2">
          <select
            v-model="advancedFiltersDraft.provider"
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
          >
            <option value="all">全部来源</option>
            <option value="browser_fingerprint">浏览器指纹</option>
            <option value="safeline">雷池</option>
          </select>
          <select
            v-model="advancedFiltersDraft.provider_site_id"
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
          >
            <option value="all">全部雷池站点</option>
            <option v-for="site in siteOptions" :key="site.id" :value="site.id">
              {{ site.label }}
            </option>
          </select>
          <label
            class="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700"
          >
            <input
              v-model="advancedFiltersDraft.blocked_only"
              type="checkbox"
              class="accent-blue-600"
            />
            仅拦截
          </label>
          <select
            v-model="advancedFiltersDraft.sort_by"
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
          >
            <option value="created_at">按时间</option>
            <option value="source_ip">按来源 IP</option>
            <option value="dest_port">按目标端口</option>
          </select>
          <input
            v-model="advancedFiltersDraft.created_from"
            type="datetime-local"
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
          />
          <input
            v-model="advancedFiltersDraft.created_to"
            type="datetime-local"
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
          />
          <select
            v-model="advancedFiltersDraft.sort_direction"
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 md:col-span-2"
          >
            <option value="desc">降序</option>
            <option value="asc">升序</option>
          </select>
        </div>
        <div
          class="flex items-center justify-end gap-2 border-t border-slate-200 px-4 py-3"
        >
          <button
            class="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
            @click="resetAdvancedFilters"
          >
            重置
          </button>
          <button
            class="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
            @click="closeAdvancedFilters"
          >
            取消
          </button>
          <button
            class="rounded-md border border-blue-600 bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-700"
            @click="applyAdvancedFilters"
          >
            应用筛选
          </button>
        </div>
      </div>
    </div>

    <div
      v-if="previewContent"
      class="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/30 px-4"
    >
      <div
        class="absolute inset-0"
        @click="closePreview"
      ></div>
      <div
        class="relative z-[101] w-full max-w-5xl rounded-md border border-slate-300 bg-white"
      >
        <div class="flex items-center justify-between border-b border-slate-200 px-4 py-3">
          <div class="text-sm font-medium text-slate-900">{{ previewTitle }}</div>
          <button
            class="inline-flex h-8 w-8 items-center justify-center rounded-md border border-slate-300 bg-white text-slate-600 hover:bg-slate-50"
            @click="closePreview"
          >
            <X :size="16" />
          </button>
        </div>
        <pre
          class="max-h-[70vh] overflow-auto whitespace-pre-wrap break-all px-4 py-3 text-xs text-slate-800"
        >{{ previewContent }}</pre>
      </div>
    </div>
  </AppLayout>
</template>

<style scoped>
.event-reason-text {
  max-width: 18rem;
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
}

.event-path-text {
  max-width: 22rem;
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
}
</style>
