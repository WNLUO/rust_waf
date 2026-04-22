import {
  bindLocalCertificateRemote,
  deleteLocalCertificate,
  fetchLocalCertificate,
  previewSafeLineCertificateMatch,
  pullSafeLineCertificates,
  pushSafeLineCertificate,
  unbindLocalCertificateRemote,
} from '@/shared/api/certificates'
import type {
  LocalCertificateItem,
  SafeLineCertificateMatchPreviewResponse,
} from '@/shared/types'
import type { AdminCertificatesState } from '@/features/certificates/composables/useAdminCertificatesState'

interface UseAdminCertificateSyncOptions {
  loadCertificates: () => Promise<void>
  state: AdminCertificatesState
}

export function useAdminCertificateSync({
  loadCertificates,
  state,
}: UseAdminCertificateSyncOptions) {
  const {
    allSelected,
    autoPushableIds,
    bindingIds,
    certificateMatchPreviews,
    certificates,
    clearFeedback,
    deletingIds,
    error,
    preflightingAll,
    previewingIds,
    pullingSafeLine,
    pushingIds,
    selectedIds,
    successMessage,
  } = state

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

  function buildFailedPreflight(
    certificate: LocalCertificateItem,
    error: unknown,
  ): SafeLineCertificateMatchPreviewResponse {
    return {
      success: false,
      status: 'conflict',
      strategy: 'error',
      local_certificate_id: certificate.id,
      local_domains: certificate.domains,
      linked_remote_id: certificate.provider_remote_id,
      matched_remote_id: null,
      message: error instanceof Error ? error.message : '预检失败',
      candidates: [],
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
            [certificate.id]: buildFailedPreflight(certificate, e),
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

  return {
    bindRemoteCertificate,
    loadCertificateMatchPreview,
    pushAutoMatchedCertificates,
    pushSelectedCertificates,
    pushSingleCertificate,
    removeSelectedCertificates,
    removeSingleCertificate,
    runCertificatePreflight,
    syncFromSafeLine,
    toggleSelectAll,
    toggleSelection,
    unbindRemoteCertificate,
  }
}
