import {
  createLocalCertificate,
  fetchLocalCertificate,
  updateLocalCertificate,
} from '@/shared/api/certificates'
import {
  defaultCertificateName,
  extractPemBlocks,
} from '@/features/settings/utils/adminSettings'
import type { LocalCertificateDraft, LocalCertificateItem } from '@/shared/types'
import type { AdminCertificatesState } from '@/features/certificates/composables/useAdminCertificatesState'

interface UseAdminCertificateEditorOptions {
  loadCertificates: () => Promise<void>
  state: AdminCertificatesState
}

export function useAdminCertificateEditor({
  loadCertificates,
  state,
}: UseAdminCertificateEditorOptions) {
  const {
    clearFeedback,
    dialogMode,
    dialogOpen,
    editingCertificateId,
    error,
    form,
    openingEditor,
    readingClipboard,
    resetForm,
    saving,
    successMessage,
  } = state

  async function tryFillCertificateFromClipboard() {
    if (!navigator.clipboard?.readText) return
    readingClipboard.value = true
    try {
      const text = await navigator.clipboard.readText()
      const detected = extractPemBlocks(text)
      if (detected.certificate_pem && !form.certificate_pem?.trim()) {
        form.certificate_pem = detected.certificate_pem
      }
      if (detected.private_key_pem && !form.private_key_pem?.trim()) {
        form.private_key_pem = detected.private_key_pem
      }
    } catch {
      // ignore clipboard errors
    } finally {
      readingClipboard.value = false
    }
  }

  function openCreateDialog() {
    clearFeedback()
    dialogMode.value = 'create'
    resetForm()
    dialogOpen.value = true
  }

  async function openEditDialog(certificate: LocalCertificateItem) {
    clearFeedback()
    openingEditor.value = true
    dialogMode.value = 'edit'
    try {
      const detail = await fetchLocalCertificate(certificate.id)
      editingCertificateId.value = detail.id
      Object.assign(form, {
        name: detail.name,
        domains: [...detail.domains],
        issuer: detail.issuer,
        valid_from: detail.valid_from,
        valid_to: detail.valid_to,
        source_type: detail.source_type,
        provider_remote_id: detail.provider_remote_id,
        provider_remote_domains: [...detail.provider_remote_domains],
        last_remote_fingerprint: detail.last_remote_fingerprint,
        sync_status: detail.sync_status,
        sync_message: detail.sync_message,
        auto_sync_enabled: detail.auto_sync_enabled,
        trusted: detail.trusted,
        expired: detail.expired,
        notes: detail.notes,
        last_synced_at: detail.last_synced_at,
        certificate_pem: detail.certificate_pem ?? '',
        private_key_pem: detail.private_key_pem ?? '',
      } satisfies LocalCertificateDraft)
      dialogOpen.value = true
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取证书详情失败'
    } finally {
      openingEditor.value = false
    }
  }

  function closeDialog() {
    dialogOpen.value = false
  }

  async function submitDialog() {
    saving.value = true
    clearFeedback()
    try {
      const normalizedDomains = form.domains
        .map((item) => item.trim())
        .filter(Boolean)
      const payload: LocalCertificateDraft = {
        name: form.name.trim() || defaultCertificateName(normalizedDomains[0]),
        domains: normalizedDomains,
        issuer: form.issuer.trim(),
        valid_from: form.valid_from,
        valid_to: form.valid_to,
        source_type: form.source_type.trim() || 'manual',
        provider_remote_id: form.provider_remote_id?.trim() || null,
        provider_remote_domains: [...form.provider_remote_domains],
        last_remote_fingerprint: form.last_remote_fingerprint?.trim() || null,
        sync_status: form.sync_status.trim() || 'idle',
        sync_message: form.sync_message.trim(),
        auto_sync_enabled: form.auto_sync_enabled,
        trusted: form.trusted,
        expired: form.expired,
        notes: form.notes.trim(),
        last_synced_at: form.last_synced_at,
      }

      if (form.certificate_pem?.trim() || form.private_key_pem?.trim()) {
        payload.certificate_pem = form.certificate_pem?.trim() ?? ''
        payload.private_key_pem = form.private_key_pem?.trim() ?? ''
      }

      if (dialogMode.value === 'create') {
        await createLocalCertificate(payload)
        successMessage.value = '证书已上传。'
      } else if (editingCertificateId.value !== null) {
        const response = await updateLocalCertificate(
          editingCertificateId.value,
          payload,
        )
        successMessage.value = response.message
      }

      closeDialog()
      resetForm()
      await loadCertificates()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '保存证书失败'
    } finally {
      saving.value = false
    }
  }

  return {
    closeDialog,
    openCreateDialog,
    openEditDialog,
    submitDialog,
    tryFillCertificateFromClipboard,
  }
}
