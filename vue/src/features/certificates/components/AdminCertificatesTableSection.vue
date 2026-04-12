<script setup lang="ts">
import type {
  LocalCertificateItem,
  SafeLineCertificateMatchCandidate,
  SafeLineCertificateMatchPreviewResponse,
} from '@/shared/types'

defineProps<{
  allSelected: boolean
  bindingIds: number[]
  certificateMatchPreviews: Record<
    number,
    SafeLineCertificateMatchPreviewResponse | undefined
  >
  certificates: LocalCertificateItem[]
  deletingIds: number[]
  formatTimestamp: (timestamp: number | null) => string
  openingEditor: boolean
  previewingIds: number[]
  pushingIds: number[]
  selectedIds: number[]
  syncStatusText: (status: string) => string
  syncStatusTone: (status: string) => string
}>()

const emit = defineEmits<{
  bindRemote: [localCertificateId: number, remoteCertificateId: string, remoteDomains: string[]]
  edit: [certificate: LocalCertificateItem]
  preview: [certificateId: number]
  push: [certificateId: number]
  remove: [certificateId: number]
  toggleSelection: [certificateId: number]
  toggleSelectAll: []
  unbind: [certificateId: number]
}>()

function previewTone(preview: SafeLineCertificateMatchPreviewResponse | undefined) {
  if (preview?.status === 'ok') return 'bg-emerald-50 text-emerald-700'
  if (preview?.status === 'create') return 'bg-blue-50 text-blue-700'
  return 'bg-amber-50 text-amber-700'
}

function previewLabel(preview: SafeLineCertificateMatchPreviewResponse | undefined) {
  if (preview?.status === 'ok') return '预检可自动命中'
  if (preview?.status === 'create') return '预检将新建'
  return '预检需人工确认'
}

function previewCardLabel(preview: SafeLineCertificateMatchPreviewResponse | undefined) {
  if (preview?.status === 'ok') return '可自动命中'
  if (preview?.status === 'create') return '将新建'
  return '需要人工确认'
}

function candidateKey(candidate: SafeLineCertificateMatchCandidate) {
  return candidate.id
}
</script>

<template>
  <section class="rounded-2xl border border-slate-200 bg-white shadow-sm">
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
                @change="emit('toggleSelectAll')"
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
                @change="emit('toggleSelection', certificate.id)"
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
                  :class="previewTone(certificateMatchPreviews[certificate.id])"
                >
                  {{ previewLabel(certificateMatchPreviews[certificate.id]) }}
                </span>
              </div>
            </td>
            <td class="px-4 py-3 align-top text-xs text-slate-600">
              <div>开始：{{ formatTimestamp(certificate.valid_from) }}</div>
              <div class="mt-1">到期：{{ formatTimestamp(certificate.valid_to) }}</div>
              <div class="mt-1">
                上次同步：{{ formatTimestamp(certificate.last_synced_at) }}
              </div>
            </td>
            <td class="px-4 py-3 align-top">
              <div class="flex flex-wrap gap-2">
                <button
                  :disabled="previewingIds.includes(certificate.id)"
                  class="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
                  @click="emit('preview', certificate.id)"
                >
                  {{ previewingIds.includes(certificate.id) ? '分析中...' : '匹配预览' }}
                </button>
                <button
                  :disabled="pushingIds.includes(certificate.id)"
                  class="rounded-lg border border-blue-200 bg-blue-50 px-3 py-1.5 text-xs text-blue-700 transition hover:border-blue-300 hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-60"
                  @click="emit('push', certificate.id)"
                >
                  {{ pushingIds.includes(certificate.id) ? '同步中...' : '同步雷池' }}
                </button>
                <button
                  :disabled="bindingIds.includes(certificate.id)"
                  class="rounded-lg border border-amber-200 bg-amber-50 px-3 py-1.5 text-xs text-amber-700 transition hover:border-amber-300 hover:bg-amber-100 disabled:cursor-not-allowed disabled:opacity-60"
                  @click="emit('unbind', certificate.id)"
                >
                  {{ bindingIds.includes(certificate.id) ? '解绑中...' : '解除绑定' }}
                </button>
                <button
                  :disabled="openingEditor"
                  class="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                  @click="emit('edit', certificate)"
                >
                  {{ openingEditor ? '读取中...' : '编辑' }}
                </button>
                <button
                  :disabled="deletingIds.includes(certificate.id)"
                  class="rounded-lg border border-red-200 bg-red-50 px-3 py-1.5 text-xs text-red-700 transition hover:border-red-300 hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-60"
                  @click="emit('remove', certificate.id)"
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
                    :class="previewTone(certificateMatchPreviews[certificate.id])"
                  >
                    {{ previewCardLabel(certificateMatchPreviews[certificate.id]) }}
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
                    :key="candidateKey(candidate)"
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
                          emit(
                            'bindRemote',
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
</template>
