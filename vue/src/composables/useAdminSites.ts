import { computed, onMounted, reactive, ref } from 'vue'
import {
  createLocalSite,
  deleteLocalSite,
  fetchCachedSafeLineSites,
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
  type ScopeFilter,
  type SiteRowDraft,
  type StateFilter,
} from '../lib/adminSites'
import type {
  LocalCertificateItem,
  LocalSiteDraft,
  LocalSiteItem,
  SafeLineMappingItem,
  SafeLineSiteItem,
  SafeLineTestResponse,
  SettingsPayload,
  SiteSyncLinkItem,
} from '../lib/types'

function splitEditorList(value: string) {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean)
}

export function useAdminSites(
  formatTimestamp: (timestamp?: number | null) => string,
) {
  const loading = ref(true)
  const error = ref('')
  const successMessage = ref('')
  const settings = ref<SettingsPayload | null>(null)
  const mappings = ref<SafeLineMappingItem[]>([])
  const sites = ref<SafeLineSiteItem[]>([])
  const localSites = ref<LocalSiteItem[]>([])
  const localCertificates = ref<LocalCertificateItem[]>([])
  const siteLinks = ref<SiteSyncLinkItem[]>([])
  const testResult = ref<SafeLineTestResponse | null>(null)
  const siteRows = ref<SiteRowDraft[]>([])
  const sitesLoadedAt = ref<number | null>(null)
  const editingLocalSiteId = ref<number | null>(null)
  const isLocalSiteModalOpen = ref(false)

  const actions = reactive({
    refreshing: false,
    testing: false,
    loadingSites: false,
    loadingCertificates: false,
    savingLocalSite: false,
    deletingLocalSite: false,
  })

  const rowActions = reactive<Record<string, 'pull' | 'push' | undefined>>({})

  const filters = reactive({
    keyword: '',
    scope: 'all' as ScopeFilter,
    state: 'all' as StateFilter,
  })

  const localSiteForm = reactive<LocalSiteDraft>({
    name: '',
    primary_hostname: '',
    hostnames: [],
    listen_ports: [],
    upstreams: [],
    enabled: true,
    tls_enabled: true,
    local_certificate_id: null,
    source: 'manual',
    sync_mode: 'manual',
    notes: '',
    last_synced_at: null,
  })

  function clearFeedback() {
    error.value = ''
    successMessage.value = ''
  }

  const hostnamesText = computed({
    get: () => localSiteForm.hostnames.join(', '),
    set: (value: string) => {
      localSiteForm.hostnames = splitEditorList(value)
    },
  })

  const listenPortsText = computed({
    get: () => localSiteForm.listen_ports.join(', '),
    set: (value: string) => {
      localSiteForm.listen_ports = splitEditorList(value)
    },
  })

  const upstreamsText = computed({
    get: () => localSiteForm.upstreams.join(', '),
    set: (value: string) => {
      localSiteForm.upstreams = splitEditorList(value)
    },
  })

  const currentLocalSite = computed(() =>
    editingLocalSiteId.value === null
      ? null
      : (localSites.value.find(
          (item) => item.id === editingLocalSiteId.value,
        ) ?? null),
  )

  const editorTitle = computed(() =>
    editingLocalSiteId.value === null
      ? '新建本地站点'
      : `编辑本地站点 #${editingLocalSiteId.value}`,
  )

  function defaultListenPorts() {
    const httpsListenAddr = settings.value?.https_listen_addr?.trim() ?? ''
    if (!httpsListenAddr) return []
    const port = httpsListenAddr.split(':').pop()?.trim()
    return port ? [port] : []
  }

  function resetLocalSiteForm() {
    editingLocalSiteId.value = null
    localSiteForm.name = ''
    localSiteForm.primary_hostname = ''
    localSiteForm.hostnames = []
    localSiteForm.listen_ports = defaultListenPorts()
    localSiteForm.upstreams = []
    localSiteForm.enabled = true
    localSiteForm.tls_enabled = true
    localSiteForm.local_certificate_id =
      settings.value?.default_certificate_id ?? null
    localSiteForm.source = 'manual'
    localSiteForm.sync_mode = 'manual'
    localSiteForm.notes = ''
    localSiteForm.last_synced_at = null
  }

  function openCreateLocalSiteModal() {
    resetLocalSiteForm()
    isLocalSiteModalOpen.value = true
  }

  function closeLocalSiteModal() {
    isLocalSiteModalOpen.value = false
  }

  function populateLocalSiteForm(
    site: LocalSiteDraft,
    localSiteId: number | null,
  ) {
    editingLocalSiteId.value = localSiteId
    localSiteForm.name = site.name
    localSiteForm.primary_hostname = site.primary_hostname
    localSiteForm.hostnames = [...site.hostnames]
    localSiteForm.listen_ports = [...site.listen_ports]
    localSiteForm.upstreams = [...site.upstreams]
    localSiteForm.enabled = site.enabled
    localSiteForm.tls_enabled = site.tls_enabled
    localSiteForm.local_certificate_id = site.local_certificate_id
    localSiteForm.source = site.source
    localSiteForm.sync_mode = site.sync_mode
    localSiteForm.notes = site.notes
    localSiteForm.last_synced_at = site.last_synced_at
  }

  function siteDraftFromItem(site: LocalSiteItem): LocalSiteDraft {
    return {
      name: site.name,
      primary_hostname: site.primary_hostname,
      hostnames: [...site.hostnames],
      listen_ports: [...site.listen_ports],
      upstreams: [...site.upstreams],
      enabled: site.enabled,
      tls_enabled: site.tls_enabled,
      local_certificate_id: site.local_certificate_id,
      source: site.source,
      sync_mode: site.sync_mode,
      notes: site.notes,
      last_synced_at: site.last_synced_at,
    }
  }

  function siteDraftFromRow(row: SiteRowDraft): LocalSiteDraft {
    const localSite =
      row.local_present && row.local_site_id
        ? (localSites.value.find((item) => item.id === row.local_site_id) ??
          null)
        : null
    const primaryHostname =
      row.local_primary_hostname ||
      row.safeline_site_domain ||
      row.server_names[0] ||
      ''
    const hostnames = row.local_hostnames.length
      ? [...row.local_hostnames]
      : row.server_names.length
        ? [...row.server_names]
        : primaryHostname
          ? [primaryHostname]
          : []
    const listenPorts = row.local_listen_ports.length
      ? [...row.local_listen_ports]
      : row.remote_ssl_ports.length
        ? [...row.remote_ssl_ports]
        : row.remote_ports.length
          ? [...row.remote_ports]
          : defaultListenPorts()
    const upstreams = row.local_upstreams.length
      ? [...row.local_upstreams]
      : row.remote_upstreams.length
        ? [...row.remote_upstreams]
        : []

    return {
      name:
        row.local_site_name ||
        row.local_alias ||
        row.safeline_site_name ||
        primaryHostname,
      primary_hostname: primaryHostname,
      hostnames,
      listen_ports: listenPorts,
      upstreams,
      enabled: row.local_present ? row.local_enabled : true,
      tls_enabled: localSite?.tls_enabled ?? row.remote_ssl_enabled ?? false,
      local_certificate_id:
        localSite?.local_certificate_id ??
        settings.value?.default_certificate_id ??
        null,
      source: 'manual',
      sync_mode: row.local_sync_mode || 'manual',
      notes: row.local_notes || row.notes || '',
      last_synced_at: row.link_last_synced_at,
    }
  }

  function editLocalSite(row: SiteRowDraft) {
    if (row.local_present && row.local_site_id) {
      const site = localSites.value.find(
        (item) => item.id === row.local_site_id,
      )
      if (site) {
        populateLocalSiteForm(siteDraftFromItem(site), site.id)
        isLocalSiteModalOpen.value = true
        return
      }
    }

    populateLocalSiteForm(siteDraftFromRow(row), null)
    isLocalSiteModalOpen.value = true
  }

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

  const filteredRows = computed(() => {
    const keyword = filters.keyword.trim().toLowerCase()

    return [...siteRows.value]
      .filter((item) => {
        if (filters.scope === 'mapped' && !item.saved) return false
        if (
          filters.scope === 'unmapped' &&
          (!item.remote_present || item.saved)
        )
          return false
        if (filters.scope === 'orphaned' && !item.orphaned) return false
        if (filters.scope === 'local_only' && item.row_kind !== 'local_only')
          return false
        if (
          filters.scope === 'missing_remote' &&
          item.row_kind !== 'missing_remote'
        )
          return false
        if (filters.state === 'enabled' && !item.enabled) return false
        if (filters.state === 'disabled' && item.enabled) return false
        if (filters.state === 'primary' && !item.is_primary) return false
        if (!keyword) return true

        return [
          item.local_alias,
          item.local_site_name,
          item.local_primary_hostname,
          item.safeline_site_name,
          item.safeline_site_domain,
          item.safeline_site_id,
          item.local_listen_ports.join(' '),
          item.local_upstreams.join(' '),
          item.server_names.join(' '),
          item.notes,
          item.local_notes,
          item.link_last_error ?? '',
        ]
          .join(' ')
          .toLowerCase()
          .includes(keyword)
      })
      .sort((left, right) => {
        if (left.is_primary !== right.is_primary)
          return left.is_primary ? -1 : 1
        if (left.saved !== right.saved) return left.saved ? -1 : 1
        if (left.remote_present !== right.remote_present)
          return left.remote_present ? -1 : 1
        return (
          left.local_alias ||
          left.local_site_name ||
          left.safeline_site_name
        ).localeCompare(
          right.local_alias ||
            right.local_site_name ||
            right.safeline_site_name,
          'zh-CN',
        )
      })
  })

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
      settings.value = await fetchSettings()
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

  async function syncRemoteSite(row: SiteRowDraft) {
    if (!row.safeline_site_id) return
    rowActions[row.row_key] = 'pull'
    clearFeedback()
    try {
      const response = await pullSafeLineSite(row.safeline_site_id)
      await refreshCollections('live')
      successMessage.value = response.message
    } catch (e) {
      error.value = e instanceof Error ? e.message : '单站点回流失败'
    } finally {
      delete rowActions[row.row_key]
    }
  }

  async function syncLocalSite(row: SiteRowDraft) {
    if (!row.local_site_id) return
    rowActions[row.row_key] = 'push'
    clearFeedback()
    try {
      const response = await pushSafeLineSite(row.local_site_id)
      await refreshCollections('live')
      successMessage.value = response.message
    } catch (e) {
      error.value = e instanceof Error ? e.message : '单站点推送失败'
    } finally {
      delete rowActions[row.row_key]
    }
  }

  function rowActionPending(row: SiteRowDraft, action: 'pull' | 'push') {
    return rowActions[row.row_key] === action
  }

  function rowBusy(row: SiteRowDraft) {
    return Boolean(rowActions[row.row_key])
  }

  function remoteActionLabel(row: SiteRowDraft) {
    return row.local_present ? '从雷池更新' : '导入到本地'
  }

  function localActionLabel(row: SiteRowDraft) {
    if (row.row_kind === 'missing_remote') return '重新创建到雷池'
    return row.remote_present && row.link_id ? '推送到雷池' : '创建到雷池'
  }

  function rowSyncText(row: SiteRowDraft) {
    if (row.link_last_error) return row.link_last_error
    if (row.link_last_synced_at)
      return `最近同步：${formatTimestamp(row.link_last_synced_at)}`
    if (row.remote_present && sitesLoadedAt.value) {
      return `远端读取：${formatTimestamp(sitesLoadedAt.value)}`
    }
    if (row.local_updated_at) {
      return `本地更新：${formatTimestamp(row.local_updated_at)}`
    }
    return '尚未执行单站点同步'
  }

  onMounted(loadPageData)

  return {
    actions,
    currentLocalSite,
    editorTitle,
    editingLocalSiteId,
    error,
    filteredRows,
    filters,
    hasSavedConfig,
    hostnamesText,
    isLocalSiteModalOpen,
    listenPortsText,
    loadRemoteSites,
    localActionLabel,
    localCertificates,
    localSiteForm,
    localSites,
    openCreateLocalSiteModal,
    primaryDraft,
    refreshPageData,
    remoteActionLabel,
    removeCurrentLocalSite,
    resetLocalSiteForm,
    rowActionPending,
    rowBusy,
    rowSyncText,
    runConnectionTest,
    saveLocalSite,
    sites,
    sitesLoadedAt,
    successMessage,
    syncLocalSite,
    syncRemoteSite,
    testResult,
    totalLinkedSites,
    totalLocalOnly,
    totalLocalSites,
    totalMapped,
    totalMissingRemote,
    totalOrphaned,
    totalSyncErrors,
    totalUnmapped,
    closeLocalSiteModal,
    editLocalSite,
    loading,
    upstreamsText,
  }
}
