import { onMounted } from 'vue'
import { fetchLocalCertificates } from '@/shared/api/certificates'
import { useAdminCertificateEditor } from '@/features/certificates/composables/useAdminCertificateEditor'
import { useAdminCertificatesState } from '@/features/certificates/composables/useAdminCertificatesState'
import { useAdminCertificateSync } from '@/features/certificates/composables/useAdminCertificateSync'

export function useAdminCertificates() {
  const state = useAdminCertificatesState()

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
    closeDialog: editor.closeDialog,
    deletingIds: state.deletingIds,
    dialogMode: state.dialogMode,
    dialogOpen: state.dialogOpen,
    domainsText: state.domainsText,
    error: state.error,
    form: state.form,
    formatTimestamp: state.formatTimestamp,
    loadCertificateMatchPreview: sync.loadCertificateMatchPreview,
    loadCertificates,
    loading: state.loading,
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
