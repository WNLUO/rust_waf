<script setup lang="ts">
import { RefreshCw, Save, ServerCog } from 'lucide-vue-next'
import type { LocalCertificateItem } from '@/shared/types'
import type { SystemSettingsForm } from '@/features/settings/utils/adminSettings'

defineProps<{
  deletingCertificateId: number | null
  generatingCertificate: boolean
  loadingCertificates: boolean
  localCertificates: LocalCertificateItem[]
  savingCertificate: boolean
  savingDefaultCertificate: boolean
  systemSettings: SystemSettingsForm
}>()

const emit = defineEmits<{
  generate: []
  upload: []
  setDefault: [id: number]
  remove: [id: number]
}>()
</script>

<template>
  <div
    class="rounded-xl border border-white/80 bg-white/80 p-5 shadow-[0_14px_30px_rgba(90,60,30,0.06)]"
  >
    <div class="flex items-center gap-3">
      <div
        class="flex h-10 w-10 items-center justify-center rounded-xl bg-slate-50 text-blue-700"
      >
        <ServerCog :size="20" />
      </div>
      <div>
        <p class="text-xs tracking-wide text-blue-700">证书中心</p>
        <h3 class="mt-0.5 text-lg font-semibold text-stone-900">
          本地证书上传与生成
        </h3>
      </div>
    </div>

    <div class="mt-3 space-y-4">
      <div class="flex flex-wrap items-center justify-end gap-2.5">
        <button
          :disabled="
            generatingCertificate ||
            savingCertificate ||
            savingDefaultCertificate
          "
          class="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/25 bg-emerald-50 px-3 py-1.5 text-xs font-medium text-emerald-700 transition hover:bg-emerald-100 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('generate')"
        >
          <RefreshCw :size="12" />
          生成随机证书
        </button>
        <button
          :disabled="savingCertificate || generatingCertificate"
          class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-white px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('upload')"
        >
          <Save :size="12" />
          上传证书
        </button>
      </div>

      <div class="rounded-lg border border-slate-200 bg-slate-50 p-4">
        <div class="flex items-center justify-between gap-3">
          <div>
            <p class="text-sm font-medium text-stone-900">当前证书</p>
            <p class="mt-1 text-xs leading-5 text-slate-500">
              {{
                loadingCertificates
                  ? '正在读取本地证书...'
                  : `共 ${localCertificates.length} 张，可用于站点证书和默认证书。`
              }}
            </p>
          </div>
        </div>

        <div v-if="localCertificates.length" class="mt-3 grid gap-3">
          <div
            v-for="certificate in localCertificates"
            :key="certificate.id"
            class="rounded-[16px] border border-slate-200 bg-white px-4 py-3"
          >
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p class="text-sm font-medium text-stone-900">
                  #{{ certificate.id }} · {{ certificate.name }}
                </p>
                <p class="mt-1 text-xs text-slate-500">
                  {{
                    certificate.domains.length
                      ? certificate.domains.join(' / ')
                      : '未填写域名'
                  }}
                </p>
              </div>
              <div class="flex flex-wrap gap-2">
                <span
                  v-if="
                    systemSettings.default_certificate_id === certificate.id
                  "
                  class="inline-flex items-center rounded-full bg-blue-50 px-2.5 py-1 text-xs font-medium text-blue-700"
                >
                  当前默认
                </span>
                <button
                  v-if="
                    systemSettings.default_certificate_id !== certificate.id
                  "
                  :disabled="savingDefaultCertificate"
                  class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
                  @click="emit('setDefault', certificate.id)"
                >
                  设为默认
                </button>
                <button
                  :disabled="deletingCertificateId === certificate.id"
                  class="inline-flex items-center gap-1 rounded-lg border border-red-500/20 px-2.5 py-1 text-xs font-medium text-red-600 transition hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-60"
                  @click="emit('remove', certificate.id)"
                >
                  {{
                    deletingCertificateId === certificate.id
                      ? '删除中...'
                      : '删除'
                  }}
                </button>
              </div>
            </div>
          </div>
        </div>

        <div
          v-else-if="!loadingCertificates"
          class="mt-3 rounded-[16px] border border-dashed border-slate-200 bg-white px-4 py-6 text-sm text-slate-500"
        >
          还没有上传本地证书。
        </div>
      </div>
    </div>
  </div>
</template>
