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
import type {
  BlockedIpsResponse,
  SafeLineSyncOverviewResponse,
} from '@/shared/types'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import {
  useAdminRealtimeState,
  useAdminRealtimeTopic,
} from '@/shared/realtime/adminRealtime'

export function useAdminBlockedPage() {
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
    reason_preset: 'manual' as
      | 'manual'
      | 'scanner'
      | 'flood'
      | 'payload'
      | 'custom',
    reason_custom: '',
    duration_preset: '1h' as '15m' | '1h' | '6h' | '24h' | '7d' | 'custom',
    duration_custom_minutes: 60,
  })

  const durationPresetSeconds: Record<
    '15m' | '1h' | '6h' | '24h' | '7d',
    number
  > = {
    '15m': 15 * 60,
    '1h': 60 * 60,
    '6h': 6 * 60 * 60,
    '24h': 24 * 60 * 60,
    '7d': 7 * 24 * 60 * 60,
  }

  const reasonPresetLabel: Record<
    'manual' | 'scanner' | 'flood' | 'payload',
    string
  > = {
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

  const relatedEventsQuery = (
    item: BlockedIpsResponse['blocked_ips'][number],
  ) => {
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
      const minutes = Math.max(
        1,
        Math.floor(Number(blockForm.duration_custom_minutes) || 0),
      )
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

  const blockExpiresAtPreview = computed(
    () => Math.floor(Date.now() / 1000) + blockDurationSeconds.value,
  )

  const matchesRealtimeFilters = (
    item: BlockedIpsResponse['blocked_ips'][number],
  ) => {
    if (blockedFilters.source_scope === 'local' && item.provider) {
      return false
    }
    if (blockedFilters.source_scope === 'remote' && !item.provider) {
      return false
    }
    if (
      blockedFilters.provider !== 'all' &&
      (item.provider || '').toLowerCase() !==
        blockedFilters.provider.toLowerCase()
    ) {
      return false
    }
    if (blockedFilters.ip.trim() && item.ip !== blockedFilters.ip.trim()) {
      return false
    }
    if (blockedFilters.keyword.trim()) {
      const keyword = blockedFilters.keyword.trim().toLowerCase()
      const haystack =
        `${item.ip} ${item.reason} ${item.provider || 'local'}`.toLowerCase()
      if (!haystack.includes(keyword)) {
        return false
      }
    }
    if (
      blockedFilters.active_only &&
      item.expires_at <= Math.floor(Date.now() / 1000)
    ) {
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

    const existingIds = new Set(
      blockedPayload.value.blocked_ips.map((item) => item.id),
    )
    const newUniqueCount = matched.filter(
      (item) => !existingIds.has(item.id),
    ).length
    const merged = [...matched, ...blockedPayload.value.blocked_ips]
    const deduped = merged.filter(
      (item, index, items) =>
        items.findIndex((candidate) => candidate.id === item.id) === index,
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
          blockedFilters.provider === 'all'
            ? undefined
            : blockedFilters.provider,
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
        provider:
          blockedFilters.provider === 'all'
            ? undefined
            : blockedFilters.provider,
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

    const matchedCount = payload.blocked_ips.filter(
      matchesRealtimeFilters,
    ).length
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
    const existed = blockedPayload.value.blocked_ips.some(
      (item) => item.id === id,
    )
    if (!existed) return
    blockedPayload.value = {
      ...blockedPayload.value,
      total: Math.max(0, blockedPayload.value.total - 1),
      blocked_ips: blockedPayload.value.blocked_ips.filter(
        (item) => item.id !== id,
      ),
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

  return {
    PAGE_SIZE,
    formatTimestamp,
    timeRemaining,
    loading,
    refreshing,
    pulling,
    pushing,
    mutatingId,
    creatingBlockedIp,
    batchUnblocking,
    cleaningExpired,
    showBlockDialog,
    filtersReady,
    currentPage,
    error,
    successMessage,
    pendingRealtimeCount,
    selectedIds,
    loadingSyncState,
    realtimeState,
    blockedPayload,
    safeLineSyncState,
    blockedFilters,
    blockForm,
    durationPresetSeconds,
    reasonPresetLabel,
    toUnixTimestamp,
    totalPages,
    pageStart,
    pageEnd,
    canInlineRefresh,
    allSelectableIds,
    isAllSelected,
    canUnblock,
    isSelected,
    toggleSelected,
    toggleSelectAll,
    onSelectAllChange,
    onSelectOneChange,
    relatedEventsQuery,
    syncStateItems,
    blockDurationSeconds,
    blockReason,
    blockExpiresAtPreview,
    matchesRealtimeFilters,
    mergeRealtimeBlockedIps,
    loadBlockedIps,
    loadSafeLineSyncState,
    openBlockDialog,
    closeBlockDialog,
    handleCreateBlockedIp,
    runSafeLinePull,
    runSafeLinePush,
    handleBatchUnblock,
    handleCleanupExpired,
    handleUnblock,
    goToPage,
  }
}
