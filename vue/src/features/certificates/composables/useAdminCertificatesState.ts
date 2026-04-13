import { computed, reactive, ref } from 'vue'
import { createDefaultUploadCertificateForm, normalizeDomainList } from '@/features/settings/utils/adminSettings'
import type {
  LocalCertificateDraft,
  LocalCertificateItem,
  SafeLineCertificateMatchPreviewResponse,
} from '@/shared/types'

export function useAdminCertificatesState() {
  const loading = ref(true)
  const saving = ref(false)
  const generatingCertificate = ref(false)
  const openingEditor = ref(false)
  const readingClipboard = ref(false)
  const pullingSafeLine = ref(false)
  const pushingIds = ref<number[]>([])
  const previewingIds = ref<number[]>([])
  const bindingIds = ref<number[]>([])
  const preflightingAll = ref(false)
  const error = ref('')
  const successMessage = ref('')
  const certificates = ref<LocalCertificateItem[]>([])
  const selectedIds = ref<number[]>([])
  const deletingIds = ref<number[]>([])
  const dialogOpen = ref(false)
  const dialogMode = ref<'create' | 'edit'>('create')
  const editingCertificateId = ref<number | null>(null)
  const showGenerateModal = ref(false)
  const certificateMatchPreviews = ref<
    Record<number, SafeLineCertificateMatchPreviewResponse | undefined>
  >({})
  const generateCertificateForm = reactive({
    name: '',
    domainsText: '',
  })

  const form = reactive<LocalCertificateDraft>(
    createDefaultUploadCertificateForm(),
  )

  const domainsText = computed({
    get: () => form.domains.join(', '),
    set: (value: string) => {
      form.domains = normalizeDomainList(value)
    },
  })

  const allSelected = computed(
    () =>
      certificates.value.length > 0 &&
      selectedIds.value.length === certificates.value.length,
  )

  const preflightSummary = computed(() => {
    const previews = certificates.value
      .map((certificate) => ({
        certificate,
        preview: certificateMatchPreviews.value[certificate.id],
      }))
      .filter((item) => item.preview)

    return {
      total: previews.length,
      ok: previews.filter((item) => item.preview?.status === 'ok').length,
      create: previews.filter((item) => item.preview?.status === 'create')
        .length,
      conflict: previews.filter((item) => item.preview?.status === 'conflict')
        .length,
    }
  })

  const autoPushableIds = computed(() =>
    certificates.value
      .filter(
        (certificate) =>
          certificateMatchPreviews.value[certificate.id]?.status === 'ok',
      )
      .map((certificate) => certificate.id),
  )

  function formatTimestamp(timestamp: number | null) {
    if (!timestamp) return '暂无'
    return new Date(timestamp * 1000).toLocaleString('zh-CN', {
      hour12: false,
    })
  }

  function clearFeedback() {
    error.value = ''
    successMessage.value = ''
  }

  function resetForm() {
    Object.assign(form, createDefaultUploadCertificateForm())
    editingCertificateId.value = null
  }

  function syncStatusTone(status: string) {
    switch (status) {
      case 'synced':
        return 'bg-emerald-50 text-emerald-700'
      case 'blocked':
      case 'conflict':
      case 'drifted':
        return 'bg-amber-50 text-amber-700'
      case 'error':
        return 'bg-red-50 text-red-700'
      default:
        return 'bg-slate-100 text-slate-600'
    }
  }

  function syncStatusText(status: string) {
    switch (status) {
      case 'synced':
        return '已同步'
      case 'blocked':
        return '受限'
      case 'conflict':
        return '冲突'
      case 'drifted':
        return '已漂移'
      case 'error':
        return '失败'
      default:
        return '未同步'
    }
  }

  return {
    allSelected,
    autoPushableIds,
    bindingIds,
    certificateMatchPreviews,
    certificates,
    clearFeedback,
    deletingIds,
    dialogMode,
    dialogOpen,
    domainsText,
    editingCertificateId,
    error,
    form,
    formatTimestamp,
    generateCertificateForm,
    generatingCertificate,
    loading,
    openingEditor,
    preflightSummary,
    preflightingAll,
    previewingIds,
    pullingSafeLine,
    pushingIds,
    readingClipboard,
    resetForm,
    saving,
    selectedIds,
    showGenerateModal,
    successMessage,
    syncStatusText,
    syncStatusTone,
  }
}

export type AdminCertificatesState = ReturnType<typeof useAdminCertificatesState>
