<script setup lang="ts">
import type {
  LocalCertificateItem,
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
            <th class="px-4 py-3 font-medium">雷池同步</th>
            <th class="px-4 py-3 font-medium">到期时间</th>
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
                  {{ certificate.name }}
                </p>
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
              <div class="flex flex-wrap gap-2">
                <span
                  class="rounded-full px-2.5 py-1"
                  :class="syncStatusTone(certificate.sync_status)"
                >
                  {{ syncStatusText(certificate.sync_status) }}
                </span>
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
              {{ formatTimestamp(certificate.valid_to) }}
            </td>
            <td class="px-4 py-3 align-top">
              <div class="flex flex-wrap gap-2">
                <button
                  :disabled="pushingIds.includes(certificate.id)"
                  class="rounded-lg border border-blue-200 bg-blue-50 px-3 py-1.5 text-xs text-blue-700 transition hover:border-blue-300 hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-60"
                  @click="emit('push', certificate.id)"
                >
                  {{ pushingIds.includes(certificate.id) ? '同步中...' : '同步雷池' }}
                </button>
                <button
                  v-if="certificate.provider_remote_id"
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
                <details class="relative">
                  <summary
                    class="list-none cursor-pointer rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                  >
                    更多
                  </summary>
                  <div
                    class="absolute right-0 z-10 mt-2 min-w-[120px] rounded-lg border border-slate-200 bg-white p-1 shadow-lg"
                  >
                    <button
                      :disabled="previewingIds.includes(certificate.id)"
                      class="block w-full rounded-md px-2 py-1.5 text-left text-xs text-stone-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
                      @click="emit('preview', certificate.id)"
                    >
                      {{ previewingIds.includes(certificate.id) ? '分析中...' : '匹配预览' }}
                    </button>
                    <button
                      v-if="certificate.provider_remote_id"
                      :disabled="bindingIds.includes(certificate.id)"
                      class="block w-full rounded-md px-2 py-1.5 text-left text-xs text-amber-700 transition hover:bg-amber-50 disabled:cursor-not-allowed disabled:opacity-60"
                      @click="emit('unbind', certificate.id)"
                    >
                      {{ bindingIds.includes(certificate.id) ? '解绑中...' : '解除绑定' }}
                    </button>
                    <button
                      :disabled="deletingIds.includes(certificate.id)"
                      class="block w-full rounded-md px-2 py-1.5 text-left text-xs text-red-700 transition hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-60"
                      @click="emit('remove', certificate.id)"
                    >
                      {{ deletingIds.includes(certificate.id) ? '删除中...' : '删除' }}
                    </button>
                  </div>
                </details>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
