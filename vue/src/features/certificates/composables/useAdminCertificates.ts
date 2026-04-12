import { computed, onMounted, reactive, ref } from 'vue'
import {
  bindLocalCertificateRemote,
  createLocalCertificate,
  deleteLocalCertificate,
  fetchLocalCertificate,
  fetchLocalCertificates,
  previewSafeLineCertificateMatch,
  pullSafeLineCertificates,
  pushSafeLineCertificate,
  unbindLocalCertificateRemote,
  updateLocalCertificate,
} from '@/shared/api/client'
import {
  createDefaultUploadCertificateForm,
  defaultCertificateName,
  extractPemBlocks,
  normalizeDomainList,
} from '@/features/settings/utils/adminSettings'
import type {
  LocalCertificateDraft,
  LocalCertificateItem,
  SafeLineCertificateMatchPreviewResponse,
} from '@/shared/types'

export function useAdminCertificates() {
  const loading = ref(true)
  const saving = ref(false)
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
  const certificateMatchPreviews = ref<
    Record<number, SafeLineCertificateMatchPreviewResponse | undefined>
  >({})

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

  async function confirmPushCertificates(ids: number[]) {
    const riskyItems: string[] = []

    for (const id of ids) {
      const certificate = certificates.value.find((item) => item.id === id)
      const preview = certificateMatchPreviews.value[id]
      const detail = await fetchLocalCertificate(id)
      const reasons: string[] = []

      if (preview?.status === 'create') {
        reasons.push('预检结果为“将新建”')
      }
      if (preview?.status === 'conflict') {
        reasons.push('预检结果为“需人工确认”')
      }
      if (!detail.private_key_pem?.trim()) {
        reasons.push('本地没有私钥')
      }

      if (reasons.length) {
        const label = certificate
          ? `#${certificate.id} ${certificate.name}`
          : `#${id}`
        riskyItems.push(`${label}：${reasons.join('，')}`)
      }
    }

    if (!riskyItems.length) {
      return true
    }

    return window.confirm(
      `以下证书存在高风险推送条件：\n${riskyItems.join(
        '\n',
      )}\n\n是否仍然继续同步到雷池？`,
    )
  }

  async function loadCertificates() {
    loading.value = true
    clearFeedback()
    try {
      const response = await fetchLocalCertificates()
      certificates.value = response.certificates
      certificateMatchPreviews.value = Object.fromEntries(
        Object.entries(certificateMatchPreviews.value).filter(([id]) =>
          response.certificates.some(
            (certificate) => certificate.id === Number(id),
          ),
        ),
      )
      selectedIds.value = selectedIds.value.filter((id) =>
        certificates.value.some((certificate) => certificate.id === id),
      )
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取证书列表失败'
    } finally {
      loading.value = false
    }
  }

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

  function toggleSelection(id: number) {
    if (selectedIds.value.includes(id)) {
      selectedIds.value = selectedIds.value.filter((item) => item !== id)
      return
    }
    selectedIds.value = [...selectedIds.value, id]
  }

  function toggleSelectAll() {
    if (allSelected.value) {
      selectedIds.value = []
      return
    }
    selectedIds.value = certificates.value.map((certificate) => certificate.id)
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

  async function syncFromSafeLine() {
    pullingSafeLine.value = true
    clearFeedback()
    try {
      const response = await pullSafeLineCertificates()
      successMessage.value = response.message
      await loadCertificates()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '从雷池同步证书失败'
    } finally {
      pullingSafeLine.value = false
    }
  }

  async function pushCertificates(ids: number[]) {
    if (!ids.length) return
    const confirmed = await confirmPushCertificates(ids)
    if (!confirmed) return
    pushingIds.value = [...new Set([...pushingIds.value, ...ids])]
    clearFeedback()
    let successCount = 0
    const failed: string[] = []

    try {
      for (const id of ids) {
        try {
          const response = await pushSafeLineCertificate(id)
          successCount += 1
          successMessage.value = response.message
        } catch (e) {
          failed.push(e instanceof Error ? `#${id} ${e.message}` : `#${id}`)
        }
      }

      await loadCertificates()
      if (failed.length) {
        error.value = `已同步 ${successCount} 张证书到雷池，${failed.length} 张失败：${failed.join('；')}`
      } else if (successCount > 1) {
        successMessage.value = `已同步 ${successCount} 张证书到雷池。`
      }
    } finally {
      pushingIds.value = pushingIds.value.filter((id) => !ids.includes(id))
    }
  }

  async function pushSingleCertificate(id: number) {
    await pushCertificates([id])
  }

  async function pushSelectedCertificates() {
    if (!selectedIds.value.length) return
    await pushCertificates([...selectedIds.value])
  }

  async function pushAutoMatchedCertificates() {
    if (!autoPushableIds.value.length) return
    await pushCertificates([...autoPushableIds.value])
  }

  async function loadCertificateMatchPreview(id: number) {
    previewingIds.value = [...new Set([...previewingIds.value, id])]
    clearFeedback()
    try {
      const preview = await previewSafeLineCertificateMatch(id)
      certificateMatchPreviews.value = {
        ...certificateMatchPreviews.value,
        [id]: preview,
      }
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取雷池证书匹配预览失败'
    } finally {
      previewingIds.value = previewingIds.value.filter((item) => item !== id)
    }
  }

  async function runCertificatePreflight() {
    if (!certificates.value.length) return
    preflightingAll.value = true
    clearFeedback()
    try {
      for (const certificate of certificates.value) {
        try {
          const preview = await previewSafeLineCertificateMatch(certificate.id)
          certificateMatchPreviews.value = {
            ...certificateMatchPreviews.value,
            [certificate.id]: preview,
          }
        } catch (e) {
          certificateMatchPreviews.value = {
            ...certificateMatchPreviews.value,
            [certificate.id]: {
              success: false,
              status: 'conflict',
              strategy: 'error',
              local_certificate_id: certificate.id,
              local_domains: certificate.domains,
              linked_remote_id: certificate.provider_remote_id,
              matched_remote_id: null,
              message: e instanceof Error ? e.message : '预检失败',
              candidates: [],
            },
          }
        }
      }
      successMessage.value = `已完成 ${certificates.value.length} 张证书的雷池预检。`
    } finally {
      preflightingAll.value = false
    }
  }

  async function bindRemoteCertificate(
    localCertificateId: number,
    remoteCertificateId: string,
    remoteDomains: string[],
  ) {
    bindingIds.value = [...new Set([...bindingIds.value, localCertificateId])]
    clearFeedback()
    try {
      const response = await bindLocalCertificateRemote(localCertificateId, {
        remote_certificate_id: remoteCertificateId,
        remote_domains: remoteDomains,
      })
      successMessage.value = response.message
      await loadCertificates()
      await loadCertificateMatchPreview(localCertificateId)
    } catch (e) {
      error.value = e instanceof Error ? e.message : '绑定雷池证书失败'
    } finally {
      bindingIds.value = bindingIds.value.filter((id) => id !== localCertificateId)
    }
  }

  async function unbindRemoteCertificate(localCertificateId: number) {
    bindingIds.value = [...new Set([...bindingIds.value, localCertificateId])]
    clearFeedback()
    try {
      const response = await unbindLocalCertificateRemote(localCertificateId)
      successMessage.value = response.message
      await loadCertificates()
      await loadCertificateMatchPreview(localCertificateId)
    } catch (e) {
      error.value = e instanceof Error ? e.message : '解除雷池证书绑定失败'
    } finally {
      bindingIds.value = bindingIds.value.filter((id) => id !== localCertificateId)
    }
  }

  async function removeCertificates(ids: number[]) {
    if (!ids.length) return
    deletingIds.value = [...new Set([...deletingIds.value, ...ids])]
    clearFeedback()
    let successCount = 0
    const failed: string[] = []

    try {
      for (const id of ids) {
        try {
          await deleteLocalCertificate(id)
          successCount += 1
        } catch (e) {
          failed.push(e instanceof Error ? `#${id} ${e.message}` : `#${id}`)
        }
      }

      await loadCertificates()
      selectedIds.value = selectedIds.value.filter((id) => !ids.includes(id))
      if (failed.length) {
        error.value = `已删除 ${successCount} 张证书，${failed.length} 张失败：${failed.join('；')}`
      } else {
        successMessage.value =
          ids.length === 1 ? '证书已删除。' : `已批量删除 ${successCount} 张证书。`
      }
    } finally {
      deletingIds.value = deletingIds.value.filter((id) => !ids.includes(id))
    }
  }

  async function removeSingleCertificate(id: number) {
    if (!window.confirm(`确认删除证书 #${id} 吗？`)) return
    await removeCertificates([id])
  }

  async function removeSelectedCertificates() {
    if (!selectedIds.value.length) return
    if (
      !window.confirm(`确认批量删除已选的 ${selectedIds.value.length} 张证书吗？`)
    ) {
      return
    }
    await removeCertificates([...selectedIds.value])
  }

  onMounted(loadCertificates)

  return {
    allSelected,
    autoPushableIds,
    bindRemoteCertificate,
    bindingIds,
    certificateMatchPreviews,
    certificates,
    closeDialog,
    deletingIds,
    dialogMode,
    dialogOpen,
    domainsText,
    error,
    form,
    formatTimestamp,
    loadCertificateMatchPreview,
    loadCertificates,
    loading,
    openCreateDialog,
    openEditDialog,
    openingEditor,
    preflightSummary,
    preflightingAll,
    previewingIds,
    pullingSafeLine,
    pushAutoMatchedCertificates,
    pushingIds,
    pushSelectedCertificates,
    pushSingleCertificate,
    readingClipboard,
    removeSelectedCertificates,
    removeSingleCertificate,
    runCertificatePreflight,
    saving,
    selectedIds,
    submitDialog,
    successMessage,
    syncFromSafeLine,
    syncStatusText,
    syncStatusTone,
    toggleSelectAll,
    toggleSelection,
    tryFillCertificateFromClipboard,
    unbindRemoteCertificate,
  }
}
