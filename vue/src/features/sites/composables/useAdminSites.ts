import { computed, onMounted, reactive, ref } from 'vue'
import { pullSafeLineSite, pushSafeLineSite } from '@/shared/api/sites'
import { useAdminSitesEditor } from './useAdminSitesEditor'
import { useAdminSitesData } from './useAdminSitesData'
import { useAdminSitesLocalCrud } from './useAdminSitesLocalCrud'
import { useAdminSitesRemoteSync } from './useAdminSitesRemoteSync'
import { useAdminSitesSync } from './useAdminSitesSync'
import { useNotifications } from '@/shared/composables/useNotifications'

export type LocalSitesStateFilter = 'all' | 'enabled' | 'disabled'

export function useAdminSites(
  formatTimestamp: (timestamp?: number | null) => string,
) {
  const { notifyError, notifySuccess } = useNotifications()
  const error = ref('')
  const successMessage = ref('')
  const filters = reactive({
    keyword: '',
    state: 'all' as LocalSitesStateFilter,
  })

  function clearFeedback() {
    error.value = ''
    successMessage.value = ''
  }
  let resetEditorForm = () => {}
  const data = useAdminSitesData({
    clearFeedback,
    error,
    resetLocalSiteForm: () => resetEditorForm(),
    successMessage,
  })
  const editor = useAdminSitesEditor(
    data.settings,
    data.localSites,
    data.globalL7Config,
  )
  resetEditorForm = editor.resetLocalSiteForm
  const localCrud = useAdminSitesLocalCrud({
    clearFeedback,
    data,
    editor,
    error,
    successMessage,
  })

  const hasSavedConfig = data.hasSavedConfig
  const totalMapped = computed(
    () => data.siteRows.value.filter((item) => item.saved).length,
  )
  const totalUnmapped = computed(
    () =>
      data.siteRows.value.filter((item) => item.remote_present && !item.saved)
        .length,
  )
  const totalOrphaned = computed(
    () => data.siteRows.value.filter((item) => item.orphaned).length,
  )
  const totalLocalOnly = computed(
    () =>
      data.siteRows.value.filter((item) => item.row_kind === 'local_only').length,
  )
  const totalMissingRemote = computed(
    () =>
      data.siteRows.value.filter((item) => item.row_kind === 'missing_remote')
        .length,
  )
  const totalLocalSites = computed(() => data.localSites.value.length)
  const totalLinkedSites = computed(
    () => data.siteLinks.value.filter((item) => item.provider === 'safeline').length,
  )
  const totalSyncErrors = computed(
    () => data.siteLinks.value.filter((item) => Boolean(item.last_error)).length,
  )
  const primaryDraft = computed(
    () =>
      data.siteRows.value.find((item) => item.safeline_site_id && item.is_primary) ??
      null,
  )

  const localRows = computed(() =>
    data.siteRows.value
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

  const remoteSync = useAdminSitesRemoteSync({
    clearFeedback,
    error,
    loadRemoteSites: data.loadRemoteSites,
    notifyError,
    notifySuccess,
    pullSafeLineSite,
    refreshCollections: data.refreshCollections,
    setSuccessMessage: (value) => {
      successMessage.value = value
    },
    localSites: data.localSites,
    sites: data.sites,
    siteRows: data.siteRows,
  })

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
    data.sitesLoadedAt,
    clearFeedback,
    data.refreshCollections,
    pullSafeLineSite,
    pushSafeLineSite,
    (value) => {
      successMessage.value = value
    },
    (value) => {
      error.value = value
    },
  )

  onMounted(data.loadPageData)

  return {
    actions: data.actions,
    currentLocalSite: editor.currentLocalSite,
    defaultSafelineInterceptConfig: editor.defaultSafelineInterceptConfig,
    editorTitle: editor.editorTitle,
    editingLocalSiteId: editor.editingLocalSiteId,
    error,
    filteredRows,
    filters,
    hasSavedConfig,
    hostnamesText: editor.hostnamesText,
    isRemoteSyncDialogOpen: remoteSync.isRemoteSyncDialogOpen,
    isLocalSiteModalOpen: editor.isLocalSiteModalOpen,
    loadRemoteSites: data.loadRemoteSites,
    localActionLabel,
    localCertificates: data.localCertificates,
    localSiteForm: editor.localSiteForm,
    localSites: data.localSites,
    openCreateLocalSiteModal: editor.openCreateLocalSiteModal,
    openRemoteSyncDialog: remoteSync.openRemoteSyncDialog,
    primaryDraft,
    recommendedRemoteSiteIds: remoteSync.recommendedRemoteSiteIds,
    remoteSyncCandidates: remoteSync.remoteSyncCandidates,
    refreshPageData: data.refreshPageData,
    remoteActionLabel,
    removeCurrentLocalSite: localCrud.removeCurrentLocalSite,
    resetLocalSiteForm: editor.resetLocalSiteForm,
    rowActionPending,
    rowBusy,
    rowSyncText,
    runConnectionTest: data.runConnectionTest,
    saveLocalSite: localCrud.saveLocalSite,
    selectRecommendedRemoteSites: remoteSync.selectRecommendedRemoteSites,
    clearRemoteSiteSelection: remoteSync.clearRemoteSiteSelection,
    closeRemoteSyncDialog: remoteSync.closeRemoteSyncDialog,
    sites: data.sites,
    sitesLoadedAt: data.sitesLoadedAt,
    selectedRemoteSiteIds: remoteSync.selectedRemoteSiteIds,
    remoteSitePullOptions: remoteSync.remoteSitePullOptions,
    successMessage,
    syncLocalSite,
    syncSelectedRemoteSites: remoteSync.syncSelectedRemoteSites,
    syncRemoteSite,
    syncingRemoteSelection: remoteSync.syncingRemoteSelection,
    testResult: data.testResult,
    toggleRemoteSiteSelection: remoteSync.toggleRemoteSiteSelection,
    toggleRemoteSitePullOption: remoteSync.toggleRemoteSitePullOption,
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
    closeLocalSiteModal: editor.closeLocalSiteModal,
    editLocalSite: editor.editLocalSite,
    loading: data.loading,
    upstreamsText: editor.upstreamsText,
  }
}
