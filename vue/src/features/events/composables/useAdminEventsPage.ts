import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { fetchSecurityEvents } from '@/shared/api/events'
import { syncSafeLineEvents } from '@/shared/api/safeline'
import type { SecurityEventItem, SecurityEventsResponse } from '@/shared/types'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import {
  useAdminRealtimeState,
  useAdminRealtimeTopic,
} from '@/shared/realtime/adminRealtime'
import { useAdminEventDisplay } from '@/features/events/composables/useAdminEventDisplay'

export function useAdminEventsPage() {
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
  const syncingFiltersFromRoute = ref(false)
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
    identity_state: 'all',
    primary_signal: '',
    blocked_only: false,
    handled: 'all' as 'all' | 'handled' | 'unhandled',
    source_ip: '',
    labels: '',
    created_from: '',
    created_to: '',
    sort_by: 'created_at',
    sort_direction: 'desc' as 'asc' | 'desc',
  })
  const showAdvancedFiltersDialog = ref(false)
  const advancedFiltersDraft = reactive({
    provider: 'all',
    provider_site_id: 'all',
    identity_state: 'all',
    primary_signal: '',
    labels: '',
    blocked_only: false,
    created_from: '',
    created_to: '',
    sort_by: 'created_at',
    sort_direction: 'desc' as 'asc' | 'desc',
  })

  const openAdvancedFilters = () => {
    advancedFiltersDraft.provider = eventsFilters.provider
    advancedFiltersDraft.provider_site_id = eventsFilters.provider_site_id
    advancedFiltersDraft.identity_state = eventsFilters.identity_state
    advancedFiltersDraft.primary_signal = eventsFilters.primary_signal
    advancedFiltersDraft.labels = eventsFilters.labels
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
    advancedFiltersDraft.identity_state = 'all'
    advancedFiltersDraft.primary_signal = ''
    advancedFiltersDraft.labels = ''
    advancedFiltersDraft.blocked_only = false
    advancedFiltersDraft.created_from = ''
    advancedFiltersDraft.created_to = ''
    advancedFiltersDraft.sort_by = 'created_at'
    advancedFiltersDraft.sort_direction = 'desc'
  }

  const applyAdvancedFilters = () => {
    eventsFilters.provider = advancedFiltersDraft.provider
    eventsFilters.provider_site_id = advancedFiltersDraft.provider_site_id
    eventsFilters.identity_state = advancedFiltersDraft.identity_state
    eventsFilters.primary_signal = advancedFiltersDraft.primary_signal
    eventsFilters.labels = advancedFiltersDraft.labels
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
      (event.provider || '').toLowerCase() !==
        eventsFilters.provider.toLowerCase()
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
    if (
      eventsFilters.identity_state !== 'all' &&
      (event.decision_summary?.identity_state || 'unknown') !==
        eventsFilters.identity_state
    ) {
      return false
    }
    if (
      eventsFilters.primary_signal.trim() &&
      (event.decision_summary?.primary_signal || '') !==
        eventsFilters.primary_signal.trim()
    ) {
      return false
    }
    if (eventsFilters.blocked_only && event.action.toLowerCase() !== 'block') {
      return false
    }
    if (eventsFilters.handled === 'handled' && !event.handled) {
      return false
    }
    if (eventsFilters.handled === 'unhandled' && event.handled) {
      return false
    }
    if (
      eventsFilters.source_ip.trim() &&
      event.source_ip !== eventsFilters.source_ip.trim()
    ) {
      return false
    }
    if (eventsFilters.labels.trim()) {
      const labels = event.decision_summary?.labels || []
      const expected = eventsFilters.labels
        .split(',')
        .map((value) => value.trim())
        .filter(Boolean)
      if (!expected.every((label) => labels.includes(label))) {
        return false
      }
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

    const existingIds = new Set(
      eventsPayload.value.events.map((event) => event.id),
    )
    const newUniqueCount = matched.filter(
      (event) => !existingIds.has(event.id),
    ).length
    const merged = [...matched, ...eventsPayload.value.events]
    const deduped = merged.filter(
      (event, index, items) =>
        items.findIndex((item) => item.id === event.id) === index,
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
        action:
          eventsFilters.action === 'all' ? undefined : eventsFilters.action,
        identity_state:
          eventsFilters.identity_state === 'all'
            ? undefined
            : eventsFilters.identity_state,
        primary_signal: eventsFilters.primary_signal.trim() || undefined,
        labels: eventsFilters.labels.trim() || undefined,
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

  const {
    safeLineActionMap,
    safeLineAttackTypeMap,
    REASON_PREVIEW_LIMIT,
    PATH_PREVIEW_LIMIT,
    getSafeLineAttackTypeCode,
    eventActionLabel,
    eventActionBadgeType,
    shouldShowActionBadge,
    eventAttackTypeLabel,
    eventReasonLabel,
    truncateText,
    eventReasonPreview,
    isReasonTruncated,
    eventPathText,
    eventPathPreview,
    isPathTruncated,
    identityStateLabelMap,
    primarySignalLabelMap,
    eventIdentityStateLabel,
    eventPrimarySignalLabel,
    eventLabelsPreview,
    parseStorageSummaryDetails,
    isStorageSummaryEvent,
    storageSummaryScopeLabel,
    storageSummaryCountLabel,
    storageSummaryWindowLabel,
    storageSummaryRouteLabel,
    openStorageSummaryPreview,
    parseEventDetails,
    hasClientIdentityDebug,
    hasUpstreamHttp2Debug,
    openClientIdentityDebug,
    openUpstreamHttp2Debug,
  } = useAdminEventDisplay({ actionLabel, formatTimestamp, openPreview })

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

  const resetRouteDrivenFilters = () => {
    eventsFilters.source_ip = ''
    eventsFilters.action = 'all'
    eventsFilters.identity_state = 'all'
    eventsFilters.primary_signal = ''
    eventsFilters.labels = ''
    eventsFilters.blocked_only = false
    eventsFilters.created_from = ''
    eventsFilters.created_to = ''
    eventsFilters.sort_by = 'created_at'
    eventsFilters.sort_direction = 'desc'
  }

  const applyFiltersFromRouteQuery = () => {
    resetRouteDrivenFilters()
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

    const action = getValue('action')
    if (
      action === 'block' ||
      action === 'allow' ||
      action === 'alert' ||
      action === 'log' ||
      action === 'summary'
    ) {
      eventsFilters.action = action
    }

    const identityState = getValue('identity_state')
    if (typeof identityState === 'string' && identityState.trim()) {
      eventsFilters.identity_state = identityState.trim()
    }

    const primarySignal = getValue('primary_signal')
    if (typeof primarySignal === 'string' && primarySignal.trim()) {
      eventsFilters.primary_signal = primarySignal.trim()
    }

    const labels = getValue('labels')
    if (typeof labels === 'string' && labels.trim()) {
      eventsFilters.labels = labels.trim()
    }

    const blockedOnly = getValue('blocked_only')
    if (typeof blockedOnly === 'string') {
      const normalized = blockedOnly.trim().toLowerCase()
      eventsFilters.blocked_only = ['1', 'true', 'yes', 'on'].includes(
        normalized,
      )
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
    if (
      sortBy === 'created_at' ||
      sortBy === 'source_ip' ||
      sortBy === 'dest_port'
    ) {
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

  useAdminRealtimeTopic<SecurityEventItem>(
    'security_event_delta',
    (payload) => {
      if (!matchesRealtimeFilters(payload)) return
      if (canInlineRefresh.value) {
        mergeRealtimeEvents([payload])
        pendingRealtimeCount.value = 0
        return
      }
      pendingRealtimeCount.value += 1
    },
  )

  onMounted(async () => {
    applyFiltersFromRouteQuery()
    await loadEvents(true)
    filtersReady.value = true
  })

  watch(
    () => route.query,
    () => {
      syncingFiltersFromRoute.value = true
      applyFiltersFromRouteQuery()
      syncingFiltersFromRoute.value = false
      if (!filtersReady.value) return
      currentPage.value = 1
      pendingRealtimeCount.value = 0
      loadEvents()
    },
  )

  watch(
    () => ({ ...eventsFilters }),
    () => {
      if (!filtersReady.value) return
      if (syncingFiltersFromRoute.value) return
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

  return {
    PAGE_SIZE,
    route,
    formatTimestamp,
    actionLabel,
    layerLabel,
    loading,
    refreshing,
    syncing,
    error,
    successMessage,
    filtersReady,
    currentPage,
    previewTitle,
    previewContent,
    pendingRealtimeCount,
    syncingFiltersFromRoute,
    realtimeState,
    eventsPayload,
    eventsFilters,
    showAdvancedFiltersDialog,
    advancedFiltersDraft,
    openAdvancedFilters,
    closeAdvancedFilters,
    resetAdvancedFilters,
    applyAdvancedFilters,
    toUnixTimestamp,
    toDatetimeLocalString,
    totalPages,
    pageStart,
    pageEnd,
    canInlineRefresh,
    matchesRealtimeFilters,
    mergeRealtimeEvents,
    loadEvents,
    runSafeLineSync,
    openPreview,
    closePreview,
    safeLineActionMap,
    safeLineAttackTypeMap,
    REASON_PREVIEW_LIMIT,
    PATH_PREVIEW_LIMIT,
    getSafeLineAttackTypeCode,
    eventActionLabel,
    eventActionBadgeType,
    shouldShowActionBadge,
    eventAttackTypeLabel,
    eventReasonLabel,
    truncateText,
    eventReasonPreview,
    isReasonTruncated,
    eventPathText,
    eventPathPreview,
    isPathTruncated,
    identityStateLabelMap,
    primarySignalLabelMap,
    eventIdentityStateLabel,
    eventPrimarySignalLabel,
    eventLabelsPreview,
    parseStorageSummaryDetails,
    isStorageSummaryEvent,
    storageSummaryScopeLabel,
    storageSummaryCountLabel,
    storageSummaryWindowLabel,
    storageSummaryRouteLabel,
    openStorageSummaryPreview,
    parseEventDetails,
    hasClientIdentityDebug,
    hasUpstreamHttp2Debug,
    openClientIdentityDebug,
    openUpstreamHttp2Debug,
    siteOptions,
    goToPage,
    resetRouteDrivenFilters,
    applyFiltersFromRouteQuery,
  }
}
