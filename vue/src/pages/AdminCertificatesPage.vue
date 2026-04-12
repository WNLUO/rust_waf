<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import AppLayout from '../components/layout/AppLayout.vue'
import AdminCertificateEditorDialog from '../components/sites/AdminCertificateEditorDialog.vue'
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
} from '../lib/api'
import {
  createDefaultUploadCertificateForm,
  defaultCertificateName,
  extractPemBlocks,
  normalizeDomainList,
} from '../lib/adminSettings'
import { useFlashMessages } from '../composables/useNotifications'
import type {
  LocalCertificateDraft,
  LocalCertificateItem,
  SafeLineCertificateMatchPreviewResponse,
} from '../lib/types'

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

const form = reactive<LocalCertificateDraft>(createDefaultUploadCertificateForm())

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: '证书管理',
  successTitle: '证书管理',
  errorDuration: 5600,
  successDuration: 3200,
})

const domainsText = computed({
  get: () => form.domains.join(', '),
  set: (value: string) => {
    form.domains = normalizeDomainList(value)
  },
})

const allSelected = computed(
  () => certificates.value.length > 0 && selectedIds.value.length === certificates.value.length,
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
    create: previews.filter((item) => item.preview?.status === 'create').length,
    conflict: previews.filter((item) => item.preview?.status === 'conflict').length,
  }
})

const autoPushableIds = computed(() =>
  certificates.value
    .filter(
      (certificate) => certificateMatchPreviews.value[certificate.id]?.status === 'ok',
    )
    .map((certificate) => certificate.id),
)

function formatTimestamp(timestamp: number | null) {
  if (!timestamp) return '暂无'
  return new Date(timestamp * 1000).toLocaleString('zh-CN', { hour12: false })
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
      const label = certificate ? `#${certificate.id} ${certificate.name}` : `#${id}`
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
        response.certificates.some((certificate) => certificate.id === Number(id)),
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
    const normalizedDomains = form.domains.map((item) => item.trim()).filter(Boolean)
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
      const response = await updateLocalCertificate(editingCertificateId.value, payload)
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
  if (!window.confirm(`确认批量删除已选的 ${selectedIds.value.length} 张证书吗？`)) return
  await removeCertificates([...selectedIds.value])
}

onMounted(loadCertificates)
</script>

<template>
  <AppLayout>
    <div class="space-y-4">
      <section class="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
        <div class="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p class="text-sm font-semibold text-stone-900">证书管理</p>
            <p class="mt-1 text-sm text-slate-500">
              站点和证书同步已拆分。这里可以单独同步雷池证书资产，并把本地证书推送到雷池。
            </p>
          </div>
          <div class="flex flex-wrap gap-2">
            <button
              :disabled="pullingSafeLine"
              class="inline-flex items-center justify-center rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
              @click="syncFromSafeLine"
            >
              {{ pullingSafeLine ? '同步中...' : '同步雷池证书' }}
            </button>
            <button
              :disabled="preflightingAll || certificates.length === 0"
              class="inline-flex items-center justify-center rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
              @click="runCertificatePreflight"
            >
              {{ preflightingAll ? '预检中...' : '批量自动预检' }}
            </button>
            <button
              class="inline-flex items-center justify-center rounded-lg bg-blue-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-blue-600/90"
              @click="openCreateDialog"
            >
              上传证书
            </button>
            <button
              :disabled="selectedIds.length === 0 || pushingIds.length > 0"
              class="inline-flex items-center justify-center rounded-lg border border-blue-200 bg-blue-50 px-3 py-2 text-sm text-blue-700 transition hover:border-blue-300 hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-60"
              @click="pushSelectedCertificates"
            >
              批量同步到雷池
            </button>
            <button
              :disabled="selectedIds.length === 0 || deletingIds.length > 0"
              class="inline-flex items-center justify-center rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 transition hover:border-red-300 hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-60"
              @click="removeSelectedCertificates"
            >
              批量删除
            </button>
            <button
              class="inline-flex items-center justify-center rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
              @click="loadCertificates"
            >
              刷新列表
            </button>
          </div>
        </div>
      </section>

      <div
        v-if="loading"
        class="rounded-xl border border-slate-200 bg-white px-4 py-6 text-center text-sm text-slate-500 shadow-sm"
      >
        正在读取证书列表...
      </div>
      <section
        v-if="preflightSummary.total > 0"
        class="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm"
      >
        <div class="flex flex-col gap-3">
          <div class="flex flex-wrap items-center gap-2">
            <span class="text-sm font-semibold text-stone-900">雷池证书预检</span>
            <span class="rounded-full bg-slate-100 px-2.5 py-1 text-xs text-slate-600">
              已分析 {{ preflightSummary.total }} 张
            </span>
            <span class="rounded-full bg-emerald-50 px-2.5 py-1 text-xs text-emerald-700">
              可自动更新 {{ preflightSummary.ok }}
            </span>
            <span class="rounded-full bg-blue-50 px-2.5 py-1 text-xs text-blue-700">
              将新建 {{ preflightSummary.create }}
            </span>
            <span class="rounded-full bg-amber-50 px-2.5 py-1 text-xs text-amber-700">
              需人工确认 {{ preflightSummary.conflict }}
            </span>
          </div>
          <p class="text-xs text-slate-500">
            预检不会改动雷池，只会根据当前本地证书、已绑定远端 ID 和雷池证书目录分析后续推送路径。
          </p>
          <div class="flex flex-wrap gap-2">
            <button
              :disabled="autoPushableIds.length === 0 || pushingIds.length > 0"
              class="inline-flex items-center justify-center rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-700 transition hover:border-emerald-300 hover:bg-emerald-100 disabled:cursor-not-allowed disabled:opacity-60"
              @click="pushAutoMatchedCertificates"
            >
              仅同步可自动命中的证书
            </button>
            <span class="text-xs leading-8 text-slate-500">
              基于当前预检结果，仅推送“可自动更新”的证书。
            </span>
          </div>
        </div>
      </section>

      <section
        v-if="!loading"
        class="rounded-2xl border border-slate-200 bg-white shadow-sm"
      >
        <div
          v-if="certificates.length === 0"
          class="px-4 py-8 text-center text-sm text-slate-500"
        >
          当前没有本地证书。
        </div>

        <div v-else class="overflow-x-auto">
          <table class="w-full min-w-[980px] text-left text-sm text-slate-700">
            <thead class="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th class="px-4 py-3 font-medium">
                  <input
                    :checked="allSelected"
                    type="checkbox"
                    class="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                    @change="toggleSelectAll"
                  />
                </th>
                <th class="px-4 py-3 font-medium">证书</th>
                <th class="px-4 py-3 font-medium">域名</th>
                <th class="px-4 py-3 font-medium">签发信息</th>
                <th class="px-4 py-3 font-medium">雷池同步</th>
                <th class="px-4 py-3 font-medium">有效期</th>
                <th class="px-4 py-3 font-medium">操作</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-200">
              <tr v-for="certificate in certificates" :key="certificate.id">
                <td class="px-4 py-3 align-top">
                  <input
                    :checked="selectedIds.includes(certificate.id)"
                    type="checkbox"
                    class="mt-1 h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                    @change="toggleSelection(certificate.id)"
                  />
                </td>
                <td class="px-4 py-3 align-top">
                  <div class="space-y-1">
                    <p class="font-medium text-stone-900">
                      #{{ certificate.id }} · {{ certificate.name }}
                    </p>
                    <div class="flex flex-wrap gap-2 text-xs">
                      <span
                        class="rounded-full px-2.5 py-1"
                        :class="
                          certificate.trusted
                            ? 'bg-emerald-50 text-emerald-700'
                            : 'bg-slate-100 text-slate-600'
                        "
                      >
                        {{ certificate.trusted ? '可信' : '未标记可信' }}
                      </span>
                      <span
                        class="rounded-full px-2.5 py-1"
                        :class="
                          certificate.expired
                            ? 'bg-red-50 text-red-700'
                            : 'bg-blue-50 text-blue-700'
                        "
                      >
                        {{ certificate.expired ? '已过期' : '有效中' }}
                      </span>
                    </div>
                  </div>
                </td>
                <td class="px-4 py-3 align-top text-xs text-slate-600">
                  {{
                    certificate.domains.length
                      ? certificate.domains.join(' / ')
                      : '未填写域名'
                  }}
                </td>
                <td class="px-4 py-3 align-top text-xs text-slate-600">
                  <div>签发者：{{ certificate.issuer || '未填写' }}</div>
                  <div class="mt-1">来源：{{ certificate.source_type || '未知' }}</div>
                </td>
                <td class="px-4 py-3 align-top text-xs text-slate-600">
                  <div class="flex flex-wrap gap-2">
                    <span
                      class="rounded-full px-2.5 py-1"
                      :class="syncStatusTone(certificate.sync_status)"
                    >
                      {{ syncStatusText(certificate.sync_status) }}
                    </span>
                    <span
                      class="rounded-full px-2.5 py-1"
                      :class="
                        certificate.auto_sync_enabled
                          ? 'bg-blue-50 text-blue-700'
                          : 'bg-slate-100 text-slate-600'
                      "
                    >
                      {{ certificate.auto_sync_enabled ? '自动同步开' : '自动同步关' }}
                    </span>
                  </div>
                  <div class="mt-2">
                    远端 ID：{{ certificate.provider_remote_id || '未关联' }}
                  </div>
                  <div class="mt-1">
                    远端域名：
                    {{
                      certificate.provider_remote_domains.length
                        ? certificate.provider_remote_domains.join(' / ')
                        : '未记录'
                    }}
                  </div>
                  <div class="mt-1 text-[11px] text-slate-500">
                    {{ certificate.sync_message || '尚未执行证书同步。' }}
                  </div>
                  <div
                    v-if="certificateMatchPreviews[certificate.id]"
                    class="mt-2 flex flex-wrap gap-2"
                  >
                    <span
                      class="rounded-full px-2.5 py-1 text-[11px]"
                      :class="
                        certificateMatchPreviews[certificate.id]?.status === 'ok'
                          ? 'bg-emerald-50 text-emerald-700'
                          : certificateMatchPreviews[certificate.id]?.status === 'create'
                            ? 'bg-blue-50 text-blue-700'
                            : 'bg-amber-50 text-amber-700'
                      "
                    >
                      {{
                        certificateMatchPreviews[certificate.id]?.status === 'ok'
                          ? '预检可自动命中'
                          : certificateMatchPreviews[certificate.id]?.status === 'create'
                            ? '预检将新建'
                            : '预检需人工确认'
                      }}
                    </span>
                  </div>
                </td>
                <td class="px-4 py-3 align-top text-xs text-slate-600">
                  <div>开始：{{ formatTimestamp(certificate.valid_from) }}</div>
                  <div class="mt-1">到期：{{ formatTimestamp(certificate.valid_to) }}</div>
                  <div class="mt-1">上次同步：{{ formatTimestamp(certificate.last_synced_at) }}</div>
                </td>
                <td class="px-4 py-3 align-top">
                  <div class="flex flex-wrap gap-2">
                    <button
                      :disabled="previewingIds.includes(certificate.id)"
                      class="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
                      @click="loadCertificateMatchPreview(certificate.id)"
                    >
                      {{ previewingIds.includes(certificate.id) ? '分析中...' : '匹配预览' }}
                    </button>
                    <button
                      :disabled="pushingIds.includes(certificate.id)"
                      class="rounded-lg border border-blue-200 bg-blue-50 px-3 py-1.5 text-xs text-blue-700 transition hover:border-blue-300 hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-60"
                      @click="pushSingleCertificate(certificate.id)"
                    >
                      {{ pushingIds.includes(certificate.id) ? '同步中...' : '同步雷池' }}
                    </button>
                    <button
                      :disabled="bindingIds.includes(certificate.id)"
                      class="rounded-lg border border-amber-200 bg-amber-50 px-3 py-1.5 text-xs text-amber-700 transition hover:border-amber-300 hover:bg-amber-100 disabled:cursor-not-allowed disabled:opacity-60"
                      @click="unbindRemoteCertificate(certificate.id)"
                    >
                      {{
                        bindingIds.includes(certificate.id)
                          ? '解绑中...'
                          : '解除绑定'
                      }}
                    </button>
                    <button
                      :disabled="openingEditor"
                      class="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                      @click="openEditDialog(certificate)"
                    >
                      {{ openingEditor ? '读取中...' : '编辑' }}
                    </button>
                    <button
                      :disabled="deletingIds.includes(certificate.id)"
                      class="rounded-lg border border-red-200 bg-red-50 px-3 py-1.5 text-xs text-red-700 transition hover:border-red-300 hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-60"
                      @click="removeSingleCertificate(certificate.id)"
                    >
                      {{ deletingIds.includes(certificate.id) ? '删除中...' : '删除' }}
                    </button>
                  </div>
                  <div
                    v-if="certificateMatchPreviews[certificate.id]"
                    class="mt-3 rounded-xl border border-slate-200 bg-slate-50 p-3 text-xs text-slate-700"
                  >
                    <div class="flex flex-wrap items-center gap-2">
                      <span
                        class="rounded-full px-2.5 py-1"
                        :class="
                          certificateMatchPreviews[certificate.id]?.status === 'ok'
                            ? 'bg-emerald-50 text-emerald-700'
                            : certificateMatchPreviews[certificate.id]?.status === 'create'
                              ? 'bg-blue-50 text-blue-700'
                              : 'bg-amber-50 text-amber-700'
                        "
                      >
                        {{
                          certificateMatchPreviews[certificate.id]?.status === 'ok'
                            ? '可自动命中'
                            : certificateMatchPreviews[certificate.id]?.status === 'create'
                              ? '将新建'
                              : '需要人工确认'
                        }}
                      </span>
                      <span class="text-slate-500">
                        策略：{{ certificateMatchPreviews[certificate.id]?.strategy }}
                      </span>
                    </div>
                    <p class="mt-2 leading-5">
                      {{ certificateMatchPreviews[certificate.id]?.message }}
                    </p>
                    <div
                      v-if="certificateMatchPreviews[certificate.id]?.candidates.length"
                      class="mt-3 space-y-2"
                    >
                      <div
                        v-for="candidate in certificateMatchPreviews[certificate.id]?.candidates"
                        :key="candidate.id"
                        class="rounded-lg border border-slate-200 bg-white p-2"
                      >
                        <div class="font-medium text-stone-900">
                          雷池证书 {{ candidate.id }}
                        </div>
                        <div class="mt-1 text-slate-600">
                          域名：{{ candidate.domains.join(' / ') || '未提供' }}
                        </div>
                        <div class="mt-1 text-slate-600">
                          签发者：{{ candidate.issuer || '未提供' }}
                        </div>
                        <div class="mt-1 text-slate-600">
                          到期：{{ formatTimestamp(candidate.valid_to) }}
                        </div>
                        <div class="mt-1 text-slate-500">
                          关联站点：{{ candidate.related_sites.join(' / ') || '无' }}
                        </div>
                        <div class="mt-2">
                          <button
                            :disabled="bindingIds.includes(certificate.id)"
                            class="rounded-lg border border-blue-200 bg-blue-50 px-3 py-1.5 text-xs text-blue-700 transition hover:border-blue-300 hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-60"
                            @click="
                              bindRemoteCertificate(
                                certificate.id,
                                candidate.id,
                                candidate.domains,
                              )
                            "
                          >
                            {{
                              bindingIds.includes(certificate.id)
                                ? '绑定中...'
                                : '绑定为目标证书'
                            }}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <AdminCertificateEditorDialog
      :form="form"
      :is-open="dialogOpen"
      :mode="dialogMode"
      :reading-clipboard="readingClipboard"
      :saving="saving"
      :domains-text="domainsText"
      @close="closeDialog"
      @submit="submitDialog"
      @fill-clipboard="tryFillCertificateFromClipboard"
      @update:form="Object.assign(form, $event)"
      @update:domains-text="domainsText = $event"
    />
  </AppLayout>
</template>
