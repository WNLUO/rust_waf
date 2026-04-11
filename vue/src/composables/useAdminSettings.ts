import { computed, onMounted, reactive, ref } from 'vue'
import {
  createLocalCertificate,
  deleteLocalCertificate,
  fetchLocalCertificates,
  fetchSafeLineMappings,
  fetchSafeLineSites,
  fetchSettings,
  generateLocalCertificate,
  testSafeLineConnection,
  updateSafeLineMappings,
  updateSettings,
} from '../lib/api'
import {
  createDefaultSystemSettings,
  createDefaultUploadCertificateForm,
  defaultCertificateName,
  defaultGeneratedDomain,
  extractPemBlocks,
  normalizeDomainList,
  type SystemSettingsForm,
} from '../lib/adminSettings'
import type {
  LocalCertificateDraft,
  LocalCertificateItem,
  SafeLineMappingItem,
  SafeLineSiteItem,
  SafeLineTestResponse,
  SettingsPayload,
} from '../lib/types'

export function useAdminSettings() {
  const loading = ref(true)
  const saving = ref(false)
  const testing = ref(false)
  const loadingSites = ref(false)
  const savingMappings = ref(false)
  const loadingCertificates = ref(false)
  const savingCertificate = ref(false)
  const generatingCertificate = ref(false)
  const savingDefaultCertificate = ref(false)
  const readingClipboard = ref(false)
  const deletingCertificateId = ref<number | null>(null)
  const showGenerateModal = ref(false)
  const showUploadModal = ref(false)
  const error = ref('')
  const successMessage = ref('')
  const testResult = ref<SafeLineTestResponse | null>(null)
  const sites = ref<SafeLineSiteItem[]>([])
  const mappings = ref<SafeLineMappingItem[]>([])
  const localCertificates = ref<LocalCertificateItem[]>([])
  const sitesLoadedAt = ref<number | null>(null)

  const systemSettings = reactive<SystemSettingsForm>(
    createDefaultSystemSettings(),
  )
  const generateCertificateForm = reactive({
    name: '',
    domainsText: '',
  })
  const uploadCertificateForm = reactive<LocalCertificateDraft>(
    createDefaultUploadCertificateForm(),
  )

  const uploadCertificateDomainsText = computed({
    get: () => uploadCertificateForm.domains.join(', '),
    set: (value: string) => {
      uploadCertificateForm.domains = normalizeDomainList(value)
    },
  })

  function clearFeedback() {
    error.value = ''
    successMessage.value = ''
  }

  function toPlainSafeLineSettings() {
    return {
      enabled: true,
      auto_sync_events: systemSettings.safeline.auto_sync_events,
      auto_sync_blocked_ips_push:
        systemSettings.safeline.auto_sync_blocked_ips_push,
      auto_sync_blocked_ips_pull:
        systemSettings.safeline.auto_sync_blocked_ips_pull,
      auto_sync_interval_secs: systemSettings.safeline.auto_sync_interval_secs,
      base_url: systemSettings.safeline.base_url,
      api_token: systemSettings.safeline.api_token,
      username: systemSettings.safeline.username,
      password: systemSettings.safeline.password,
      verify_tls: systemSettings.safeline.verify_tls,
      openapi_doc_path: systemSettings.safeline.openapi_doc_path,
      auth_probe_path: systemSettings.safeline.auth_probe_path,
      site_list_path: systemSettings.safeline.site_list_path,
      event_list_path: systemSettings.safeline.event_list_path,
      blocklist_sync_path: systemSettings.safeline.blocklist_sync_path,
      blocklist_delete_path: systemSettings.safeline.blocklist_delete_path,
      blocklist_ip_group_ids: [
        ...systemSettings.safeline.blocklist_ip_group_ids,
      ],
    }
  }

  function toPlainSettingsPayload(): SettingsPayload {
    return {
      gateway_name: systemSettings.gateway_name,
      auto_refresh_seconds: systemSettings.auto_refresh_seconds,
      https_listen_addr: systemSettings.https_listen_addr,
      default_certificate_id: systemSettings.default_certificate_id,
      upstream_endpoint: systemSettings.upstream_endpoint,
      api_endpoint: systemSettings.api_endpoint,
      notification_level: systemSettings.notification_level,
      retain_days: systemSettings.retain_days,
      notes: systemSettings.notes,
      safeline: toPlainSafeLineSettings(),
    }
  }

  async function loadCertificates() {
    loadingCertificates.value = true
    try {
      const response = await fetchLocalCertificates()
      localCertificates.value = response.certificates
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取本地证书失败'
    } finally {
      loadingCertificates.value = false
    }
  }

  async function loadSettings() {
    loading.value = true
    error.value = ''
    try {
      const payload = await fetchSettings()
      Object.assign(systemSettings, payload)
    } catch (e) {
      error.value = e instanceof Error ? e.message : '系统设置加载失败'
    } finally {
      loading.value = false
    }
  }

  async function loadMappings() {
    try {
      const response = await fetchSafeLineMappings()
      mappings.value = response.mappings
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取雷池站点映射失败'
    }
  }

  async function saveSettings() {
    saving.value = true
    clearFeedback()
    try {
      systemSettings.auto_refresh_seconds = Number.isFinite(
        systemSettings.auto_refresh_seconds,
      )
        ? Math.min(Math.max(systemSettings.auto_refresh_seconds, 3), 60)
        : 5
      systemSettings.retain_days = Number.isFinite(systemSettings.retain_days)
        ? Math.min(Math.max(systemSettings.retain_days, 1), 365)
        : 30
      systemSettings.safeline.auto_sync_interval_secs = Number.isFinite(
        systemSettings.safeline.auto_sync_interval_secs,
      )
        ? Math.min(
            Math.max(systemSettings.safeline.auto_sync_interval_secs, 15),
            86400,
          )
        : 300

      const response = await updateSettings(toPlainSettingsPayload())
      successMessage.value = response.message
    } catch (e) {
      error.value = e instanceof Error ? e.message : '系统设置保存失败'
    } finally {
      saving.value = false
    }
  }

  async function runSafeLineTest() {
    testing.value = true
    error.value = ''
    try {
      testResult.value = await testSafeLineConnection(toPlainSafeLineSettings())
    } catch (e) {
      error.value = e instanceof Error ? e.message : '雷池连通性测试失败'
      testResult.value = null
    } finally {
      testing.value = false
    }
  }

  async function loadSafeLineSites() {
    loadingSites.value = true
    error.value = ''
    try {
      const response = await fetchSafeLineSites(toPlainSafeLineSettings())
      sites.value = response.sites
      sitesLoadedAt.value = Math.floor(Date.now() / 1000)
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取雷池站点列表失败'
      sites.value = []
    } finally {
      loadingSites.value = false
    }
  }

  function siteMappingDraft(site: SafeLineSiteItem) {
    const existing = mappings.value.find(
      (item) => item.safeline_site_id === site.id,
    )
    return {
      safeline_site_id: site.id,
      safeline_site_name: site.name,
      safeline_site_domain: site.domain,
      local_alias: existing?.local_alias ?? site.name ?? site.domain ?? '',
      enabled: existing?.enabled ?? true,
      is_primary: existing?.is_primary ?? false,
      notes: existing?.notes ?? '',
      updated_at: existing?.updated_at ?? null,
    }
  }

  const mappingDrafts = computed(() => sites.value.map(siteMappingDraft))

  async function saveMappings() {
    savingMappings.value = true
    clearFeedback()
    try {
      const payload = {
        mappings: mappingDrafts.value.map((item) => ({
          safeline_site_id: item.safeline_site_id,
          safeline_site_name: item.safeline_site_name,
          safeline_site_domain: item.safeline_site_domain,
          local_alias: item.local_alias,
          enabled: item.enabled,
          is_primary: item.is_primary,
          notes: item.notes,
        })),
      }
      const response = await updateSafeLineMappings(payload)
      successMessage.value = response.message
      await loadMappings()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '保存雷池站点映射失败'
    } finally {
      savingMappings.value = false
    }
  }

  function resetGenerateModal() {
    generateCertificateForm.name = ''
    generateCertificateForm.domainsText = ''
  }

  function resetUploadModal() {
    Object.assign(uploadCertificateForm, createDefaultUploadCertificateForm())
  }

  function openGenerateModal() {
    clearFeedback()
    resetGenerateModal()
    showGenerateModal.value = true
  }

  function closeGenerateModal() {
    showGenerateModal.value = false
  }

  function closeUploadModal() {
    showUploadModal.value = false
  }

  async function tryFillCertificateFromClipboard() {
    if (!navigator.clipboard?.readText) return
    readingClipboard.value = true
    try {
      const text = await navigator.clipboard.readText()
      const detected = extractPemBlocks(text)
      if (
        detected.certificate_pem &&
        !uploadCertificateForm.certificate_pem?.trim()
      ) {
        uploadCertificateForm.certificate_pem = detected.certificate_pem
      }
      if (
        detected.private_key_pem &&
        !uploadCertificateForm.private_key_pem?.trim()
      ) {
        uploadCertificateForm.private_key_pem = detected.private_key_pem
      }
    } catch {
      // 浏览器权限或非安全上下文下读取失败时静默降级。
    } finally {
      readingClipboard.value = false
    }
  }

  async function openUploadModal() {
    clearFeedback()
    resetUploadModal()
    showUploadModal.value = true
    await tryFillCertificateFromClipboard()
  }

  async function persistDefaultCertificate(
    id: number | null,
    successText = '默认证书已保存。',
  ) {
    savingDefaultCertificate.value = true
    clearFeedback()
    try {
      const latest = await fetchSettings()
      const nextId =
        typeof id === 'number' && Number.isFinite(id) && id > 0 ? id : null
      latest.default_certificate_id = nextId
      const response = await updateSettings(latest)
      systemSettings.default_certificate_id = nextId
      successMessage.value = successText || response.message
    } catch (e) {
      error.value = e instanceof Error ? e.message : '默认证书保存失败'
      await loadSettings()
    } finally {
      savingDefaultCertificate.value = false
    }
  }

  async function handleDefaultCertificateChange(event: Event) {
    const target = event.target as HTMLSelectElement | null
    const rawValue = target?.value ?? ''
    const nextId =
      rawValue === '' || rawValue === 'null'
        ? null
        : Number.parseInt(rawValue, 10)
    await persistDefaultCertificate(
      Number.isFinite(nextId as number) ? (nextId as number) : null,
    )
  }

  async function uploadCertificate() {
    savingCertificate.value = true
    clearFeedback()
    try {
      const payload: LocalCertificateDraft = {
        ...uploadCertificateForm,
        name:
          uploadCertificateForm.name.trim() ||
          defaultCertificateName(uploadCertificateForm.domains[0]),
        domains: uploadCertificateForm.domains
          .map((item) => item.trim())
          .filter(Boolean),
        issuer: uploadCertificateForm.issuer.trim(),
        notes: uploadCertificateForm.notes.trim(),
        certificate_pem: uploadCertificateForm.certificate_pem?.trim() ?? '',
        private_key_pem: uploadCertificateForm.private_key_pem?.trim() ?? '',
      }

      await createLocalCertificate(payload)
      closeUploadModal()
      resetUploadModal()
      await loadCertificates()
      successMessage.value = '证书已上传。'
    } catch (e) {
      error.value = e instanceof Error ? e.message : '上传本地证书失败'
    } finally {
      savingCertificate.value = false
    }
  }

  async function generateCertificate() {
    generatingCertificate.value = true
    clearFeedback()
    try {
      const domains = normalizeDomainList(generateCertificateForm.domainsText)
      const normalizedDomains = domains.length
        ? domains
        : [defaultGeneratedDomain()]
      const created = await generateLocalCertificate({
        name: generateCertificateForm.name.trim() || null,
        domains: normalizedDomains,
        notes: '系统设置中生成的随机假证书',
      })
      await loadCertificates()
      await persistDefaultCertificate(
        created.id,
        `已生成随机证书「${created.name}」并设为默认证书。`,
      )
      closeGenerateModal()
      resetGenerateModal()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '生成随机证书失败'
    } finally {
      generatingCertificate.value = false
    }
  }

  async function removeCertificate(id: number) {
    deletingCertificateId.value = id
    clearFeedback()
    try {
      const response = await deleteLocalCertificate(id)
      if (systemSettings.default_certificate_id === id) {
        await persistDefaultCertificate(null, '已删除证书并清空默认证书。')
      }
      await loadCertificates()
      successMessage.value = response.message
    } catch (e) {
      error.value = e instanceof Error ? e.message : '删除本地证书失败'
    } finally {
      deletingCertificateId.value = null
    }
  }

  onMounted(async () => {
    await loadSettings()
    await loadCertificates()
    await loadMappings()
  })

  return {
    deletingCertificateId,
    error,
    generateCertificate,
    generateCertificateForm,
    handleDefaultCertificateChange,
    loadSafeLineSites,
    loading,
    loadingCertificates,
    loadingSites,
    localCertificates,
    mappingDrafts,
    openGenerateModal,
    openUploadModal,
    persistDefaultCertificate,
    readingClipboard,
    removeCertificate,
    runSafeLineTest,
    saveMappings,
    saveSettings,
    saving,
    savingCertificate,
    savingDefaultCertificate,
    savingMappings,
    showGenerateModal,
    showUploadModal,
    sites,
    sitesLoadedAt,
    successMessage,
    systemSettings,
    testResult,
    testing,
    tryFillCertificateFromClipboard,
    uploadCertificate,
    uploadCertificateDomainsText,
    uploadCertificateForm,
    closeGenerateModal,
    closeUploadModal,
    generatingCertificate,
  }
}
