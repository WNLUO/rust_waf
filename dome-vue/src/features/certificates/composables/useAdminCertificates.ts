import { onMounted } from 'vue'
import {
  fetchLocalCertificates,
  generateLocalCertificate,
} from '@/shared/api/certificates'
import { fetchSettings, updateSettings } from '@/shared/api/settings'
import { useAdminCertificateEditor } from '@/features/certificates/composables/useAdminCertificateEditor'
import { useAdminCertificatesState } from '@/features/certificates/composables/useAdminCertificatesState'
import { useAdminCertificateSync } from '@/features/certificates/composables/useAdminCertificateSync'
import {
  defaultGeneratedDomain,
  normalizeDomainList,
} from '@/features/settings/utils/adminSettings'

export function useAdminCertificates() {
  const state = useAdminCertificatesState()

  function resetGenerateModal() {
    state.generateCertificateForm.name = ''
    state.generateCertificateForm.domainsText = ''
  }

  function openGenerateModal() {
    state.clearFeedback()
    resetGenerateModal()
    state.showGenerateModal.value = true
  }

  function closeGenerateModal() {
    state.showGenerateModal.value = false
  }

  async function loadCertificates() {
    state.loading.value = true
    state.clearFeedback()
    try {
      const response = await fetchLocalCertificates()
      state.certificates.value = response.certificates
      state.certificateMatchPreviews.value = Object.fromEntries(
        Object.entries(state.certificateMatchPreviews.value).filter(([id]) =>
          response.certificates.some(
            (certificate) => certificate.id === Number(id),
          ),
        ),
      )
      state.selectedIds.value = state.selectedIds.value.filter((id) =>
        state.certificates.value.some((certificate) => certificate.id === id),
      )
    } catch (e) {
      state.error.value = e instanceof Error ? e.message : '读取证书列表失败'
    } finally {
      state.loading.value = false
    }
  }

  async function persistDefaultCertificate(
    id: number | null,
    successText = '默认证书已保存。',
  ) {
    state.saving.value = true
    state.clearFeedback()
    try {
      const latest = await fetchSettings()
      latest.default_certificate_id =
        typeof id === 'number' && Number.isFinite(id) && id > 0 ? id : null
      const response = await updateSettings(latest)
      state.successMessage.value = successText || response.message
    } catch (e) {
      state.error.value = e instanceof Error ? e.message : '默认证书保存失败'
    } finally {
      state.saving.value = false
    }
  }

  async function generateCertificate() {
    state.generatingCertificate.value = true
    state.clearFeedback()
    try {
      const domains = normalizeDomainList(
        state.generateCertificateForm.domainsText,
      )
      const created = await generateLocalCertificate({
        name: state.generateCertificateForm.name.trim() || null,
        domains: domains.length ? domains : [defaultGeneratedDomain()],
        notes: '证书管理中生成的随机假证书',
      })
      await loadCertificates()
      await persistDefaultCertificate(
        created.id,
        `已生成随机证书「${created.name}」并设为默认证书。`,
      )
      closeGenerateModal()
      resetGenerateModal()
    } catch (e) {
      state.error.value = e instanceof Error ? e.message : '生成随机证书失败'
    } finally {
      state.generatingCertificate.value = false
    }
  }

  const editor = useAdminCertificateEditor({
    loadCertificates,
    state,
  })
  const sync = useAdminCertificateSync({
    loadCertificates,
    state,
  })

  onMounted(loadCertificates)

  return {
    allSelected: state.allSelected,
    autoPushableIds: state.autoPushableIds,
    bindRemoteCertificate: sync.bindRemoteCertificate,
    bindingIds: state.bindingIds,
    certificateMatchPreviews: state.certificateMatchPreviews,
    certificates: state.certificates,
    closeGenerateModal,
    closeDialog: editor.closeDialog,
    deletingIds: state.deletingIds,
    dialogMode: state.dialogMode,
    dialogOpen: state.dialogOpen,
    domainsText: state.domainsText,
    error: state.error,
    form: state.form,
    formatTimestamp: state.formatTimestamp,
    generateCertificate,
    generateCertificateForm: state.generateCertificateForm,
    generatingCertificate: state.generatingCertificate,
    loadCertificateMatchPreview: sync.loadCertificateMatchPreview,
    loadCertificates,
    loading: state.loading,
    openGenerateModal,
    openCreateDialog: editor.openCreateDialog,
    openEditDialog: editor.openEditDialog,
    openingEditor: state.openingEditor,
    preflightSummary: state.preflightSummary,
    preflightingAll: state.preflightingAll,
    previewingIds: state.previewingIds,
    pullingSafeLine: state.pullingSafeLine,
    pushAutoMatchedCertificates: sync.pushAutoMatchedCertificates,
    pushingIds: state.pushingIds,
    pushSelectedCertificates: sync.pushSelectedCertificates,
    pushSingleCertificate: sync.pushSingleCertificate,
    readingClipboard: state.readingClipboard,
    removeSelectedCertificates: sync.removeSelectedCertificates,
    removeSingleCertificate: sync.removeSingleCertificate,
    runCertificatePreflight: sync.runCertificatePreflight,
    saving: state.saving,
    selectedIds: state.selectedIds,
    showGenerateModal: state.showGenerateModal,
    submitDialog: editor.submitDialog,
    successMessage: state.successMessage,
    syncFromSafeLine: sync.syncFromSafeLine,
    syncStatusText: state.syncStatusText,
    syncStatusTone: state.syncStatusTone,
    toggleSelectAll: sync.toggleSelectAll,
    toggleSelection: sync.toggleSelection,
    tryFillCertificateFromClipboard: editor.tryFillCertificateFromClipboard,
    unbindRemoteCertificate: sync.unbindRemoteCertificate,
  }
}
