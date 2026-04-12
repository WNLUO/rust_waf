import { computed, onMounted, reactive, ref } from 'vue'
import {
  createLocalSite,
  deleteLocalSite,
  fetchCachedSafeLineSites,
  fetchL7Config,
  fetchLocalCertificates,
  fetchLocalSites,
  fetchSafeLineMappings,
  fetchSafeLineSites,
  fetchSiteSyncLinks,
  fetchSettings,
  pullSafeLineSite,
  pushSafeLineSite,
  testSafeLineConnection,
  updateLocalSite,
} from '../lib/api'
import {
  mergeSiteRows,
  type SiteRowDraft,
} from '../lib/adminSites'
import { useAdminSitesEditor } from './useAdminSitesEditor'
import { useAdminSitesSync } from './useAdminSitesSync'
import type {
  LocalCertificateItem,
  LocalSiteDraft,
  LocalSiteItem,
  SafeLineSitePullOptions,
  SafeLineMappingItem,
  SafeLineSiteItem,
  SafeLineTestResponse,
  SettingsPayload,
  SiteSyncLinkItem,
} from '../lib/types'

export type LocalSitesStateFilter = 'all' | 'enabled' | 'disabled'

export interface RemoteSyncCandidate {
  id: string
  name: string
  domain: string
  serverNames: string[]
  upstreams: string[]
  ports: string[]
  sslPorts: string[]
  sslEnabled: boolean
  localMatchLabel: string | null
  recommendation: 'recommended' | 'update' | 'hostname_conflict' | 'name_conflict'
  recommendationText: string
  selectable: boolean
  defaultSelected: boolean
  linkedLocalSiteId: number | null
}

function createDefaultPullOptions(): SafeLineSitePullOptions {
  return {
    name: true,
    primary_hostname: true,
    hostnames: true,
    listen_ports: true,
    upstreams: true,
    enabled: true,
  }
}

function cloneSafelineIntercept(
  value: LocalSiteDraft['safeline_intercept'],
): LocalSiteDraft['safeline_intercept'] {
  if (!value) return null
  return {
    ...value,
    response_template: {
      ...value.response_template,
      headers: value.response_template.headers.map((header) => ({ ...header })),
    },
  }
}

export function useAdminSites(
  formatTimestamp: (timestamp?: number | null) => string,
) {
  const loading = ref(true)
  const error = ref('')
  const successMessage = ref('')
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

  const actions = reactive({
    refreshing: false,
    testing: false,
    loadingSites: false,
    loadingCertificates: false,
    savingLocalSite: false,
    deletingLocalSite: false,
  })

  const filters = reactive({
    keyword: '',
    state: 'all' as LocalSitesStateFilter,
  })
  const isRemoteSyncDialogOpen = ref(false)
  const selectedRemoteSiteIds = ref<string[]>([])
  const remoteSitePullOptions = ref<Record<string, SafeLineSitePullOptions>>({})
  const syncingRemoteSelection = ref(false)

  function clearFeedback() {
    error.value = ''
    successMessage.value = ''
  }
  const {
    closeLocalSiteModal,
    currentLocalSite,
    defaultSafelineInterceptConfig,
    editLocalSite,
    editingLocalSiteId,
    editorTitle,
    hostnamesText,
    isLocalSiteModalOpen,
    listenPortsText,
    localSiteForm,
    openCreateLocalSiteModal,
    populateLocalSiteForm,
    resetLocalSiteForm,
    siteDraftFromItem,
    upstreamsText,
  } = useAdminSitesEditor(settings, localSites, globalL7Config)

  const hasSavedConfig = computed(() =>
    Boolean(settings.value?.safeline.base_url.trim()),
  )
  const totalMapped = computed(
    () => siteRows.value.filter((item) => item.saved).length,
  )
  const totalUnmapped = computed(
    () =>
      siteRows.value.filter((item) => item.remote_present && !item.saved)
        .length,
  )
  const totalOrphaned = computed(
    () => siteRows.value.filter((item) => item.orphaned).length,
  )
  const totalLocalOnly = computed(
    () =>
      siteRows.value.filter((item) => item.row_kind === 'local_only').length,
  )
  const totalMissingRemote = computed(
    () =>
      siteRows.value.filter((item) => item.row_kind === 'missing_remote')
        .length,
  )
  const totalLocalSites = computed(() => localSites.value.length)
  const totalLinkedSites = computed(
    () => siteLinks.value.filter((item) => item.provider === 'safeline').length,
  )
  const totalSyncErrors = computed(
    () => siteLinks.value.filter((item) => Boolean(item.last_error)).length,
  )
  const primaryDraft = computed(
    () =>
      siteRows.value.find((item) => item.safeline_site_id && item.is_primary) ??
      null,
  )

  const localRows = computed(() =>
    siteRows.value
      .filter((item) => item.local_present)
      .sort((left, right) => {
        if (left.is_primary !== right.is_primary)
          return left.is_primary ? -1 : 1
        if (left.local_enabled !== right.local_enabled)
          return left.local_enabled ? -1 : 1
        return (left.local_site_name || left.local_primary_hostname).localeCompare(
          right.local_site_name || right.local_primary_hostname,
          'zh-CN',
        )
      }),
  )

  const filteredRows = computed(() => {
    const keyword = filters.keyword.trim().toLowerCase()

    return [...localRows.value]
      .filter((item) => {
        if (filters.state === 'enabled' && !item.local_enabled) return false
        if (filters.state === 'disabled' && item.local_enabled) return false
        if (!keyword) return true

        return [
          item.local_site_name,
          item.local_primary_hostname,
          item.local_hostnames.join(' '),
          item.local_listen_ports.join(' '),
          item.local_upstreams.join(' '),
          item.local_notes,
          item.local_alias,
          item.safeline_site_name,
          item.safeline_site_domain,
          item.safeline_site_id,
          item.link_last_error ?? '',
        ]
          .join(' ')
          .toLowerCase()
          .includes(keyword)
      })
  })

  const totalEnabledLocalSites = computed(
    () => localRows.value.filter((item) => item.local_enabled).length,
  )
  const totalSitesWithRemoteLink = computed(
    () => localRows.value.filter((item) => item.link_id !== null).length,
  )

  const remoteSyncCandidates = computed<RemoteSyncCandidate[]>(() => {
    const localByHostname = new Map<string, LocalSiteItem>()
    const localByName = new Map<string, LocalSiteItem>()
    for (const site of localSites.value) {
      const names = [
        site.primary_hostname,
        ...site.hostnames,
      ]
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean)
      for (const hostname of names) {
        if (!localByHostname.has(hostname)) {
          localByHostname.set(hostname, site)
        }
      }
      const normalizedName = site.name.trim().toLowerCase()
      if (normalizedName && !localByName.has(normalizedName)) {
        localByName.set(normalizedName, site)
      }
    }

    return [...sites.value]
      .map((site) => {
        const linkedRow =
          siteRows.value.find(
            (item) => item.safeline_site_id === site.id && item.local_present,
          ) ?? null
        const hostnameMatch = [
          site.domain,
          ...site.server_names,
        ]
          .map((item) => item.trim().toLowerCase())
          .find((hostname) => localByHostname.has(hostname))
        const matchedByHostname = hostnameMatch
          ? (localByHostname.get(hostnameMatch) ?? null)
          : null
        const matchedByName =
          localByName.get(site.name.trim().toLowerCase()) ?? null

        if (linkedRow) {
          return {
            id: site.id,
            name: site.name || site.domain || `站点 ${site.id}`,
            domain: site.domain,
            serverNames: site.server_names,
            upstreams: site.upstreams,
            ports: site.ports,
            sslPorts: site.ssl_ports,
            sslEnabled: site.ssl_enabled,
            localMatchLabel:
              linkedRow.local_site_name || linkedRow.local_primary_hostname,
            recommendation: 'update' as const,
            recommendationText: '已有关联本地站点，可按需更新本地配置。',
            selectable: true,
            defaultSelected: false,
            linkedLocalSiteId: linkedRow.local_site_id,
          }
        }

        if (matchedByHostname) {
          return {
            id: site.id,
            name: site.name || site.domain || `站点 ${site.id}`,
            domain: site.domain,
            serverNames: site.server_names,
            upstreams: site.upstreams,
            ports: site.ports,
            sslPorts: site.ssl_ports,
            sslEnabled: site.ssl_enabled,
            localMatchLabel:
              matchedByHostname.name || matchedByHostname.primary_hostname,
            recommendation: 'hostname_conflict' as const,
            recommendationText:
              '本地域名已存在相似站点，建议人工确认后再导入。',
            selectable: true,
            defaultSelected: false,
            linkedLocalSiteId: null,
          }
        }

        if (matchedByName) {
          return {
            id: site.id,
            name: site.name || site.domain || `站点 ${site.id}`,
            domain: site.domain,
            serverNames: site.server_names,
            upstreams: site.upstreams,
            ports: site.ports,
            sslPorts: site.ssl_ports,
            sslEnabled: site.ssl_enabled,
            localMatchLabel:
              matchedByName.name || matchedByName.primary_hostname,
            recommendation: 'name_conflict' as const,
            recommendationText:
              '本地已有同名站点，默认不勾选，避免重复导入。',
            selectable: true,
            defaultSelected: false,
            linkedLocalSiteId: null,
          }
        }

        return {
          id: site.id,
          name: site.name || site.domain || `站点 ${site.id}`,
          domain: site.domain,
          serverNames: site.server_names,
          upstreams: site.upstreams,
          ports: site.ports,
          sslPorts: site.ssl_ports,
          sslEnabled: site.ssl_enabled,
          localMatchLabel: null,
          recommendation: 'recommended' as const,
          recommendationText: '本地未发现重复站点，建议直接导入。',
          selectable: true,
          defaultSelected: true,
          linkedLocalSiteId: null,
        }
      })
      .sort((left, right) => {
        const priority = {
          recommended: 0,
          update: 1,
          hostname_conflict: 2,
          name_conflict: 3,
        }
        if (priority[left.recommendation] !== priority[right.recommendation]) {
          return priority[left.recommendation] - priority[right.recommendation]
        }
        return left.name.localeCompare(right.name, 'zh-CN')
      })
  })

  const recommendedRemoteSiteIds = computed(() =>
    remoteSyncCandidates.value
      .filter((item) => item.defaultSelected && item.selectable)
      .map((item) => item.id),
  )

  async function refreshCollections(remoteSource: 'none' | 'cached' | 'live') {
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

  async function loadPageData() {
    loading.value = true
    clearFeedback()
    try {
      const [settingsResponse, l7ConfigResponse] = await Promise.all([
        fetchSettings(),
        fetchL7Config(),
      ])
      settings.value = settingsResponse
      globalL7Config.value = l7ConfigResponse
      resetLocalSiteForm()
      await loadLocalCertificates()
      await refreshCollections('cached')
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取站点管理信息失败'
    } finally {
      loading.value = false
    }
  }

  async function saveLocalSite() {
    actions.savingLocalSite = true
    clearFeedback()
    try {
      const payload: LocalSiteDraft = {
        name: localSiteForm.name.trim(),
        primary_hostname: localSiteForm.primary_hostname.trim(),
        hostnames: localSiteForm.hostnames
          .map((item) => item.trim())
          .filter(Boolean),
        listen_ports: localSiteForm.listen_ports
          .map((item) => item.trim())
          .filter(Boolean),
        upstreams: localSiteForm.upstreams
          .map((item) => item.trim())
          .filter(Boolean),
        safeline_intercept: cloneSafelineIntercept(localSiteForm.safeline_intercept),
        enabled: localSiteForm.enabled,
        tls_enabled: localSiteForm.tls_enabled,
        local_certificate_id: localSiteForm.local_certificate_id,
        source: 'manual',
        sync_mode: localSiteForm.sync_mode.trim() || 'manual',
        notes: localSiteForm.notes.trim(),
        last_synced_at: currentLocalSite.value?.last_synced_at ?? null,
      }

      if (editingLocalSiteId.value === null) {
        const created = await createLocalSite(payload)
        successMessage.value = `本地站点 ${created.name} 已创建。重启服务后生效。`
        editingLocalSiteId.value = created.id
      } else {
        const response = await updateLocalSite(
          editingLocalSiteId.value,
          payload,
        )
        successMessage.value = response.message
      }

      await refreshCollections(sitesLoadedAt.value !== null ? 'cached' : 'none')

      if (editingLocalSiteId.value !== null) {
        const updatedSite =
          localSites.value.find(
            (item) => item.id === editingLocalSiteId.value,
          ) ?? null
        if (updatedSite) {
          populateLocalSiteForm(siteDraftFromItem(updatedSite), updatedSite.id)
        }
      }

      closeLocalSiteModal()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '保存本地站点失败'
    } finally {
      actions.savingLocalSite = false
    }
  }

  async function removeCurrentLocalSite() {
    if (editingLocalSiteId.value === null) return
    actions.deletingLocalSite = true
    clearFeedback()
    try {
      const response = await deleteLocalSite(editingLocalSiteId.value)
      successMessage.value = response.message
      resetLocalSiteForm()
      await refreshCollections(sitesLoadedAt.value !== null ? 'cached' : 'none')
      closeLocalSiteModal()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '删除本地站点失败'
    } finally {
      actions.deletingLocalSite = false
    }
  }

  async function refreshPageData() {
    actions.refreshing = true
    clearFeedback()
    try {
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

  async function openRemoteSyncDialog() {
    await loadRemoteSites()
    if (error.value) return
    selectedRemoteSiteIds.value = recommendedRemoteSiteIds.value
    remoteSitePullOptions.value = Object.fromEntries(
      remoteSyncCandidates.value.map((candidate) => [
        candidate.id,
        createDefaultPullOptions(),
      ]),
    )
    isRemoteSyncDialogOpen.value = true
  }

  function closeRemoteSyncDialog() {
    isRemoteSyncDialogOpen.value = false
  }

  function toggleRemoteSiteSelection(remoteSiteId: string) {
    if (selectedRemoteSiteIds.value.includes(remoteSiteId)) {
      selectedRemoteSiteIds.value = selectedRemoteSiteIds.value.filter(
        (item) => item !== remoteSiteId,
      )
      return
    }
    selectedRemoteSiteIds.value = [...selectedRemoteSiteIds.value, remoteSiteId]
  }

  function selectRecommendedRemoteSites() {
    selectedRemoteSiteIds.value = recommendedRemoteSiteIds.value
  }

  function clearRemoteSiteSelection() {
    selectedRemoteSiteIds.value = []
  }

  function toggleRemoteSitePullOption(
    remoteSiteId: string,
    field: keyof SafeLineSitePullOptions,
  ) {
    const candidate = remoteSyncCandidates.value.find((item) => item.id === remoteSiteId)
    if (!candidate) return
    if (field === 'primary_hostname' && candidate.linkedLocalSiteId === null) return

    const current = remoteSitePullOptions.value[remoteSiteId] ?? createDefaultPullOptions()
    remoteSitePullOptions.value = {
      ...remoteSitePullOptions.value,
      [remoteSiteId]: {
        ...current,
        [field]: !current[field],
      },
    }
  }

  async function syncSelectedRemoteSites() {
    if (!selectedRemoteSiteIds.value.length) {
      error.value = '请先选择要同步的雷池站点。'
      return
    }

    syncingRemoteSelection.value = true
    clearFeedback()
    let successCount = 0
    const failed: string[] = []

    try {
      for (const remoteSiteId of selectedRemoteSiteIds.value) {
        try {
          await pullSafeLineSite(
            remoteSiteId,
            remoteSitePullOptions.value[remoteSiteId] ?? createDefaultPullOptions(),
          )
          successCount += 1
        } catch (e) {
          failed.push(
            e instanceof Error ? `${remoteSiteId}: ${e.message}` : remoteSiteId,
          )
        }
      }

      await refreshCollections('live')
      if (failed.length) {
        error.value = `已同步 ${successCount} 个站点，${failed.length} 个失败：${failed.join('；')}`
      } else {
        successMessage.value = `已从雷池同步 ${successCount} 个站点到本地。`
      }
      if (successCount > 0) {
        closeRemoteSyncDialog()
      }
    } finally {
      syncingRemoteSelection.value = false
    }
  }
  const {
    localActionLabel,
    remoteActionLabel,
    rowActionPending,
    rowBusy,
    rowSyncText,
    syncLocalSite,
    syncRemoteSite,
  } = useAdminSitesSync(
    formatTimestamp,
    sitesLoadedAt,
    clearFeedback,
    refreshCollections,
    pullSafeLineSite,
    pushSafeLineSite,
    (value) => {
      successMessage.value = value
    },
    (value) => {
      error.value = value
    },
  )

  onMounted(loadPageData)

  return {
    actions,
    currentLocalSite,
    defaultSafelineInterceptConfig,
    editorTitle,
    editingLocalSiteId,
    error,
    filteredRows,
    filters,
    hasSavedConfig,
    hostnamesText,
    isRemoteSyncDialogOpen,
    isLocalSiteModalOpen,
    listenPortsText,
    loadRemoteSites,
    localActionLabel,
    localCertificates,
    localSiteForm,
    localSites,
    openCreateLocalSiteModal,
    openRemoteSyncDialog,
    primaryDraft,
    recommendedRemoteSiteIds,
    remoteSyncCandidates,
    refreshPageData,
    remoteActionLabel,
    removeCurrentLocalSite,
    resetLocalSiteForm,
    rowActionPending,
    rowBusy,
    rowSyncText,
    runConnectionTest,
    saveLocalSite,
    selectRecommendedRemoteSites,
    clearRemoteSiteSelection,
    closeRemoteSyncDialog,
    sites,
    sitesLoadedAt,
    selectedRemoteSiteIds,
    remoteSitePullOptions,
    successMessage,
    syncLocalSite,
    syncSelectedRemoteSites,
    syncRemoteSite,
    syncingRemoteSelection,
    testResult,
    toggleRemoteSiteSelection,
    toggleRemoteSitePullOption,
    totalLinkedSites,
    totalLocalOnly,
    totalLocalSites,
    totalEnabledLocalSites,
    totalMapped,
    totalMissingRemote,
    totalOrphaned,
    totalSyncErrors,
    totalSitesWithRemoteLink,
    totalUnmapped,
    closeLocalSiteModal,
    editLocalSite,
    loading,
    upstreamsText,
  }
}
