import { computed, reactive, ref } from 'vue'
import type { SiteRowDraft } from '../lib/adminSites'
import type {
  LocalSiteDraft,
  LocalSiteItem,
  SettingsPayload,
} from '../lib/types'

function splitEditorList(value: string) {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean)
}

export function useAdminSitesEditor(
  settings: { value: SettingsPayload | null },
  localSites: { value: LocalSiteItem[] },
) {
  const editingLocalSiteId = ref<number | null>(null)
  const isLocalSiteModalOpen = ref(false)

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

  function siteDraftFromRow(
    row: SiteRowDraft,
    defaultCertificateId: number | null,
  ): LocalSiteDraft {
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
        localSite?.local_certificate_id ?? defaultCertificateId ?? null,
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

    populateLocalSiteForm(
      siteDraftFromRow(row, settings.value?.default_certificate_id ?? null),
      null,
    )
    isLocalSiteModalOpen.value = true
  }

  return {
    closeLocalSiteModal,
    currentLocalSite,
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
  }
}
