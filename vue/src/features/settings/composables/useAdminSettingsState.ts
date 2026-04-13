import { computed, reactive, ref } from 'vue'
import {
  createDefaultSystemSettings,
  createDefaultUploadCertificateForm,
  normalizeDomainList,
  type SystemSettingsForm,
} from '@/features/settings/utils/adminSettings'
import type {
  GlobalEntryConfigPayload,
  LocalCertificateDraft,
  LocalCertificateItem,
  SafeLineMappingItem,
  SafeLineSiteItem,
  SettingsUpdatePayload,
  SafeLineTestResponse,
} from '@/shared/types'

export function useAdminSettingsState() {
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
  const globalEntryForm = reactive<GlobalEntryConfigPayload>({
    http_port: '66',
    https_port: '660',
  })

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

  function toPlainSafeLineTestPayload() {
    return {
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

  function toPlainSettingsPayload(): SettingsUpdatePayload {
    return {
      gateway_name: systemSettings.gateway_name,
      drop_unmatched_requests: systemSettings.drop_unmatched_requests,
      https_listen_addr: systemSettings.https_listen_addr,
      default_certificate_id: systemSettings.default_certificate_id,
      api_endpoint: systemSettings.api_endpoint,
      notes: systemSettings.notes,
      safeline: {
        auto_sync_events: systemSettings.safeline.auto_sync_events,
        auto_sync_blocked_ips_push:
          systemSettings.safeline.auto_sync_blocked_ips_push,
        auto_sync_blocked_ips_pull:
          systemSettings.safeline.auto_sync_blocked_ips_pull,
        auto_sync_interval_secs:
          systemSettings.safeline.auto_sync_interval_secs,
        base_url: systemSettings.safeline.base_url,
        api_token: systemSettings.safeline.api_token,
        username: systemSettings.safeline.username,
        password: systemSettings.safeline.password,
        verify_tls: systemSettings.safeline.verify_tls,
      },
    }
  }

  return {
    clearFeedback,
    deletingCertificateId,
    error,
    generateCertificateForm,
    generatingCertificate,
    globalEntryForm,
    loading,
    loadingCertificates,
    loadingSites,
    localCertificates,
    mappings,
    readingClipboard,
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
    toPlainSafeLineTestPayload,
    toPlainSettingsPayload,
    uploadCertificateDomainsText,
    uploadCertificateForm,
  }
}

export type AdminSettingsState = ReturnType<typeof useAdminSettingsState>
