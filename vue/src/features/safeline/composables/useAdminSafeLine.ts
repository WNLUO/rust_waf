import { computed, onMounted, reactive, ref } from 'vue'
import {
  fetchSafeLineMappings,
  fetchSafeLineSites,
  fetchSafeLineSyncState,
  pullSafeLineBlockedIps,
  syncSafeLineBlockedIps,
  syncSafeLineEvents,
  testSafeLineConnection,
  updateSafeLineMappings,
} from '@/shared/api/safeline'
import { fetchSettings } from '@/shared/api/settings'
import {
  mergeMappingDrafts,
  sortMappingDrafts,
  type SafeLineMappingDraft,
} from '@/features/safeline/utils/adminSafeLine'
import type {
  SafeLineMappingItem,
  SafeLineSiteItem,
  SafeLineSyncOverviewResponse,
  SafeLineSyncStateResponse,
  SafeLineTestResponse,
  SettingsPayload,
} from '@/shared/types'

export function useAdminSafeLine() {
  const loading = ref(true)
  const error = ref('')
  const successMessage = ref('')
  const settings = ref<SettingsPayload | null>(null)
  const mappings = ref<SafeLineMappingItem[]>([])
  const sites = ref<SafeLineSiteItem[]>([])
  const syncState = ref<SafeLineSyncOverviewResponse | null>(null)
  const testResult = ref<SafeLineTestResponse | null>(null)
  const mappingDrafts = ref<SafeLineMappingDraft[]>([])

  const actions = reactive({
    refreshing: false,
    testing: false,
    loadingSites: false,
    syncingEvents: false,
    pushingBlocked: false,
    pullingBlocked: false,
    savingMappings: false,
  })

  const syncCards = computed(() => [
    {
      key: 'events',
      title: '事件同步',
      description: '把雷池攻击日志落到本地事件库，供事件页统一检索。',
      data: syncState.value?.events ?? null,
    },
    {
      key: 'blocked_ips_pull',
      title: '封禁回流',
      description: '把雷池远端封禁拉回本地名单，便于统一查看与解封。',
      data: syncState.value?.blocked_ips_pull ?? null,
    },
    {
      key: 'blocked_ips_push',
      title: '本地推送',
      description: '把本地封禁推到雷池，联动边界拦截策略。',
      data: syncState.value?.blocked_ips_push ?? null,
    },
    {
      key: 'blocked_ips_delete',
      title: '远端解封',
      description: '记录从本地触发雷池解封时的最近执行结果。',
      data: syncState.value?.blocked_ips_delete ?? null,
    },
  ])

  const hasSavedConfig = computed(() =>
    Boolean(settings.value?.safeline.base_url.trim()),
  )

  const authMode = computed(() => {
    if (settings.value?.safeline.api_token.trim()) return 'API Token'
    if (
      settings.value?.safeline.username.trim() &&
      settings.value?.safeline.password.trim()
    ) {
      return '账号密码'
    }
    return '未配置鉴权'
  })

  const sortedDrafts = computed(() => sortMappingDrafts(mappingDrafts.value))

  function clearFeedback() {
    error.value = ''
    successMessage.value = ''
  }

  function syncStatusType(item: SafeLineSyncStateResponse | null) {
    if (!item) return 'muted'
    if (item.last_success_at) return 'success'
    return 'warning'
  }

  function syncStatusText(item: SafeLineSyncStateResponse | null) {
    if (!item) return '未执行'
    if (item.last_success_at) return '最近成功'
    return '已记录'
  }

  function refreshDrafts() {
    mappingDrafts.value = mergeMappingDrafts(sites.value, mappings.value)
  }

  function selectPrimary(siteId: string) {
    for (const item of mappingDrafts.value) {
      item.is_primary = item.safeline_site_id === siteId
    }
  }

  function clearPrimary() {
    for (const item of mappingDrafts.value) {
      item.is_primary = false
    }
  }

  async function loadPageData() {
    loading.value = true
    clearFeedback()

    try {
      const [settingsResponse, mappingsResponse, syncResponse] =
        await Promise.all([
          fetchSettings(),
          fetchSafeLineMappings(),
          fetchSafeLineSyncState(),
        ])

      settings.value = settingsResponse
      mappings.value = mappingsResponse.mappings
      syncState.value = syncResponse
      refreshDrafts()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取雷池联动信息失败'
    } finally {
      loading.value = false
    }
  }

  async function refreshSyncState() {
    actions.refreshing = true
    clearFeedback()

    try {
      syncState.value = await fetchSafeLineSyncState()
      successMessage.value = '联动状态已刷新。'
    } catch (e) {
      error.value = e instanceof Error ? e.message : '刷新联动状态失败'
    } finally {
      actions.refreshing = false
    }
  }

  async function runConnectionTest() {
    if (!settings.value) return

    actions.testing = true
    clearFeedback()

    try {
      testResult.value = await testSafeLineConnection(settings.value.safeline)
      successMessage.value = '连通性测试已完成。'
    } catch (e) {
      error.value = e instanceof Error ? e.message : '雷池连通性测试失败'
      testResult.value = null
    } finally {
      actions.testing = false
    }
  }

  async function loadRemoteSites() {
    if (!settings.value) return

    actions.loadingSites = true
    clearFeedback()

    try {
      const response = await fetchSafeLineSites(settings.value.safeline)
      sites.value = response.sites
      refreshDrafts()
      successMessage.value = `已读取 ${response.total} 个雷池站点。`
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取雷池站点失败'
    } finally {
      actions.loadingSites = false
    }
  }

  async function saveMappings() {
    actions.savingMappings = true
    clearFeedback()

    try {
      await updateSafeLineMappings({
        mappings: mappingDrafts.value.map((item) => ({
          safeline_site_id: item.safeline_site_id,
          safeline_site_name: item.safeline_site_name,
          safeline_site_domain: item.safeline_site_domain,
          local_alias: item.local_alias.trim(),
          enabled: item.enabled,
          is_primary: item.is_primary,
          notes: item.notes.trim(),
        })),
      })

      const mappingsResponse = await fetchSafeLineMappings()
      mappings.value = mappingsResponse.mappings
      refreshDrafts()
      successMessage.value = '站点映射已保存。'
    } catch (e) {
      error.value = e instanceof Error ? e.message : '保存站点映射失败'
    } finally {
      actions.savingMappings = false
    }
  }

  async function runEventSync() {
    actions.syncingEvents = true
    clearFeedback()

    try {
      const response = await syncSafeLineEvents()
      successMessage.value = response.message
      syncState.value = await fetchSafeLineSyncState()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '同步雷池事件失败'
    } finally {
      actions.syncingEvents = false
    }
  }

  async function runBlockedPush() {
    actions.pushingBlocked = true
    clearFeedback()

    try {
      const response = await syncSafeLineBlockedIps()
      successMessage.value = response.message
      syncState.value = await fetchSafeLineSyncState()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '推送本地封禁失败'
    } finally {
      actions.pushingBlocked = false
    }
  }

  async function runBlockedPull() {
    actions.pullingBlocked = true
    clearFeedback()

    try {
      const response = await pullSafeLineBlockedIps()
      successMessage.value = response.message
      syncState.value = await fetchSafeLineSyncState()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '拉取雷池封禁失败'
    } finally {
      actions.pullingBlocked = false
    }
  }

  onMounted(loadPageData)

  return {
    actions,
    authMode,
    clearPrimary,
    error,
    hasSavedConfig,
    loadRemoteSites,
    loading,
    mappingDrafts,
    refreshSyncState,
    runBlockedPull,
    runBlockedPush,
    runConnectionTest,
    runEventSync,
    saveMappings,
    selectPrimary,
    settings,
    sortedDrafts,
    successMessage,
    syncCards,
    syncState,
    syncStatusText,
    syncStatusType,
    testResult,
  }
}
