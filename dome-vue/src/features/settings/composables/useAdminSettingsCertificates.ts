import {
  createLocalCertificate,
  deleteLocalCertificate,
  fetchLocalCertificates,
  generateLocalCertificate,
} from '@/shared/api/certificates'
import { fetchSettings, updateSettings } from '@/shared/api/settings'
import {
  createDefaultUploadCertificateForm,
  defaultCertificateName,
  defaultGeneratedDomain,
  extractPemBlocks,
  normalizeDomainList,
} from '@/features/settings/utils/adminSettings'
import type { LocalCertificateDraft } from '@/shared/types'
import type { AdminSettingsState } from '@/features/settings/composables/useAdminSettingsState'

interface UseAdminSettingsCertificatesOptions {
  loadSettings: () => Promise<void>
  state: AdminSettingsState
}

export function useAdminSettingsCertificates({
  loadSettings,
  state,
}: UseAdminSettingsCertificatesOptions) {
  const {
    clearFeedback,
    deletingCertificateId,
    error,
    generateCertificateForm,
    generatingCertificate,
    loadingCertificates,
    localCertificates,
    readingClipboard,
    savingCertificate,
    savingDefaultCertificate,
    showGenerateModal,
    showUploadModal,
    successMessage,
    systemSettings,
    uploadCertificateForm,
  } = state

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

  return {
    closeGenerateModal,
    closeUploadModal,
    generateCertificate,
    handleDefaultCertificateChange,
    loadCertificates,
    openGenerateModal,
    openUploadModal,
    persistDefaultCertificate,
    removeCertificate,
    tryFillCertificateFromClipboard,
    uploadCertificate,
  }
}
