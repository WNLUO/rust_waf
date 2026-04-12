import { computed, reactive, ref, type Ref } from 'vue'
import { fetchL7Config } from '@/shared/api/l7'
import { fetchLocalCertificates } from '@/shared/api/certificates'
import {
  fetchCachedSafeLineSites,
  fetchSafeLineMappings,
  fetchSafeLineSites,
  fetchSiteSyncLinks,
  testSafeLineConnection,
} from '@/shared/api/safeline'
import {
  fetchGlobalEntryConfig,
  fetchLocalSites,
} from '@/shared/api/sites'
import { fetchSettings } from '@/shared/api/settings'
import { mergeSiteRows, type SiteRowDraft } from '@/features/sites/utils/adminSites'
import type {
  GlobalEntryConfigPayload,
  LocalCertificateItem,
  LocalSiteItem,
  SafeLineMappingItem,
  SafeLineSiteItem,
  SafeLineTestResponse,
  SettingsPayload,
  SiteSyncLinkItem,
} from '@/shared/types'

type RemoteSource = 'none' | 'cached' | 'live'

interface UseAdminSitesDataOptions {
  clearFeedback: () => void
  error: Ref<string>
  resetLocalSiteForm: () => void
  successMessage: Ref<string>
}

export function useAdminSitesData({
  clearFeedback,
  error,
  resetLocalSiteForm,
  successMessage,
}: UseAdminSitesDataOptions) {
  const loading = ref(true)
  const settings = ref<SettingsPayload | null>(null)
  const globalL7Config = ref<Awaited<ReturnType<typeof fetchL7Config>> | null>(null)
  const mappings = ref<SafeLineMappingItem[]>([])
  const sites = ref<SafeLineSiteItem[]>([])
  const localSites = ref<LocalSiteItem[]>([])
  const localCertificates = ref<LocalCertificateItem[]>([])
  const siteLinks = ref<SiteSyncLinkItem[]>([])
  const testResult = ref<SafeLineTestResponse | null>(null)
  const siteRows = ref<SiteRowDraft[]>([])
  const sitesLoadedAt = ref<number | null>(null)
  const globalEntryForm = reactive<GlobalEntryConfigPayload>({
    http_port: '',
    https_port: '',
  })

  const actions = reactive({
    refreshing: false,
    testing: false,
    loadingSites: false,
    loadingCertificates: false,
    savingLocalSite: false,
    deletingLocalSite: false,
    savingGlobalEntry: false,
  })

  const hasSavedConfig = computed(() =>
    Boolean(settings.value?.safeline.base_url.trim()),
  )

  function assignGlobalEntryForm(payload: GlobalEntryConfigPayload) {
    Object.assign(globalEntryForm, payload)
  }

  async function refreshCollections(remoteSource: RemoteSource) {
    const [
      mappingsResponse,
      localSitesResponse,
      siteLinksResponse,
      remoteSitesResponse,
    ] = await Promise.all([
      fetchSafeLineMappings(),
      fetchLocalSites(),
      fetchSiteSyncLinks(),
      remoteSource === 'live' && settings.value && hasSavedConfig.value
        ? fetchSafeLineSites(settings.value.safeline)
        : remoteSource === 'cached'
          ? fetchCachedSafeLineSites()
          : Promise.resolve(null),
    ])

    mappings.value = mappingsResponse.mappings
    localSites.value = localSitesResponse.sites
    siteLinks.value = siteLinksResponse.links

    if (remoteSitesResponse) {
      sites.value = remoteSitesResponse.sites
      sitesLoadedAt.value = remoteSitesResponse.cached_at
    }

    siteRows.value = mergeSiteRows(
      sites.value,
      mappings.value,
      localSites.value,
      siteLinks.value,
    )
  }

  async function loadLocalCertificates() {
    actions.loadingCertificates = true
    try {
      const response = await fetchLocalCertificates()
      localCertificates.value = response.certificates
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取本地证书失败'
    } finally {
      actions.loadingCertificates = false
    }
  }

  async function syncBaseData() {
    const [settingsResponse, l7ConfigResponse, globalEntryResponse] =
      await Promise.all([
        fetchSettings(),
        fetchL7Config(),
        fetchGlobalEntryConfig(),
      ])
    settings.value = settingsResponse
    globalL7Config.value = l7ConfigResponse
    assignGlobalEntryForm(globalEntryResponse)
  }

  async function loadPageData() {
    loading.value = true
    clearFeedback()
    try {
      await syncBaseData()
      resetLocalSiteForm()
      await loadLocalCertificates()
      await refreshCollections('cached')
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取站点管理信息失败'
    } finally {
      loading.value = false
    }
  }

  async function refreshPageData() {
    actions.refreshing = true
    clearFeedback()
    try {
      await syncBaseData()
      await refreshCollections(sitesLoadedAt.value !== null ? 'cached' : 'none')
      successMessage.value = '页面数据已刷新。'
    } catch (e) {
      error.value = e instanceof Error ? e.message : '刷新页面数据失败'
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
      sitesLoadedAt.value = response.cached_at ?? Math.floor(Date.now() / 1000)
      siteRows.value = mergeSiteRows(
        sites.value,
        mappings.value,
        localSites.value,
        siteLinks.value,
      )
      successMessage.value = `已读取 ${response.total} 个雷池站点。`
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取雷池站点失败'
    } finally {
      actions.loadingSites = false
    }
  }

  return {
    actions,
    assignGlobalEntryForm,
    globalEntryForm,
    globalL7Config,
    hasSavedConfig,
    loadLocalCertificates,
    loadPageData,
    loadRemoteSites,
    loading,
    localCertificates,
    localSites,
    mappings,
    refreshCollections,
    refreshPageData,
    runConnectionTest,
    settings,
    siteLinks,
    siteRows,
    sites,
    sitesLoadedAt,
    testResult,
  }
}
