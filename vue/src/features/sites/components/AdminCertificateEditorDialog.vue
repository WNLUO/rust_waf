<script setup lang="ts">
import { computed } from 'vue'
import { Save, X } from 'lucide-vue-next'
import type { LocalCertificateDraft } from '@/shared/types'

const props = defineProps<{
  form: LocalCertificateDraft
  isOpen: boolean
  mode: 'create' | 'edit'
  readingClipboard: boolean
  saving: boolean
  domainsText: string
}>()

const emit = defineEmits<{
  close: []
  submit: []
  fillClipboard: []
  'update:form': [value: LocalCertificateDraft]
  'update:domainsText': [value: string]
}>()

function updateForm<K extends keyof LocalCertificateDraft>(
  key: K,
  value: LocalCertificateDraft[K],
) {
  emit('update:form', {
    ...props.form,
    [key]: value,
  })
}

const nameModel = computed({
  get: () => props.form.name,
  set: (value: string) => updateForm('name', value),
})

const notesModel = computed({
  get: () => props.form.notes,
  set: (value: string) => updateForm('notes', value),
})

const issuerModel = computed({
  get: () => props.form.issuer,
  set: (value: string) => updateForm('issuer', value),
})

const trustedModel = computed({
  get: () => props.form.trusted,
  set: (value: boolean) => updateForm('trusted', value),
})

const expiredModel = computed({
  get: () => props.form.expired,
  set: (value: boolean) => updateForm('expired', value),
})

const autoSyncModel = computed({
  get: () => props.form.auto_sync_enabled,
  set: (value: boolean) => updateForm('auto_sync_enabled', value),
})

const certificatePemModel = computed({
  get: () => props.form.certificate_pem,
  set: (value: string) => updateForm('certificate_pem', value),
})

const privateKeyPemModel = computed({
  get: () => props.form.private_key_pem,
  set: (value: string) => updateForm('private_key_pem', value),
})
</script>

<template>
  <div
    v-if="isOpen"
    class="fixed inset-0 z-[100] flex items-center justify-center px-4 py-8"
  >
    <div
      class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm"
      @click="emit('close')"
    ></div>
    <div
      class="relative w-full max-w-4xl rounded-xl border border-slate-200 bg-white p-5 shadow-[0_24px_80px_rgba(60,40,20,0.24)]"
    >
      <div class="flex items-start justify-between gap-4">
        <div>
          <p class="text-sm tracking-wide text-blue-700">证书管理</p>
          <h3 class="mt-2 text-2xl font-semibold text-stone-900">
            {{ mode === 'create' ? '上传本地证书' : '编辑证书' }}
          </h3>
          <p class="mt-2 text-sm leading-6 text-slate-500">
            {{
              mode === 'create'
                ? '支持直接上传 PEM 证书和私钥。名称可自动生成。'
                : '可编辑证书名称、域名和备注；如需替换证书材料，可重新填写 PEM 和私钥。留空则保留原内容。'
            }}
          </p>
        </div>
        <button
          class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-slate-200 bg-white transition hover:border-blue-500/40 hover:text-blue-700"
          @click="emit('close')"
        >
          <X :size="18" />
        </button>
      </div>

      <div class="mt-5 grid gap-4 md:grid-cols-2">
        <label class="space-y-1.5">
          <span class="text-xs text-slate-500">证书名称</span>
          <input
            v-model="nameModel"
            type="text"
            placeholder="可留空后自动命名"
            class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
          />
        </label>
        <label class="space-y-1.5">
          <span class="text-xs text-slate-500">域名列表</span>
          <input
            :value="domainsText"
            type="text"
            placeholder="多个域名用逗号分隔"
            class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
            @input="
              emit(
                'update:domainsText',
                ($event.target as HTMLInputElement).value,
              )
            "
          />
        </label>
        <label class="space-y-1.5">
          <span class="text-xs text-slate-500">签发者</span>
          <input
            v-model="issuerModel"
            type="text"
            placeholder="可选"
            class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
          />
        </label>
        <label class="space-y-1.5">
          <span class="text-xs text-slate-500">备注</span>
          <input
            v-model="notesModel"
            type="text"
            placeholder="可选"
            class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
          />
        </label>
        <label class="space-y-1.5">
          <span class="text-xs text-slate-500">状态</span>
          <div class="flex flex-wrap gap-4 rounded-[16px] border border-slate-200 bg-slate-50 px-3.5 py-3 text-sm">
            <label class="inline-flex items-center gap-2">
              <input v-model="trustedModel" type="checkbox" />
              标记为可信
            </label>
            <label class="inline-flex items-center gap-2">
              <input v-model="expiredModel" type="checkbox" />
              标记为已过期
            </label>
            <label class="inline-flex items-center gap-2">
              <input v-model="autoSyncModel" type="checkbox" />
              变更后自动同步到雷池
            </label>
          </div>
        </label>
        <div
          class="rounded-[16px] border border-slate-200 bg-slate-50 px-3.5 py-3 text-xs leading-5 text-slate-600"
        >
          <div>雷池远端 ID：{{ props.form.provider_remote_id || '未关联' }}</div>
          <div class="mt-1">同步状态：{{ props.form.sync_status || 'idle' }}</div>
          <div class="mt-1">
            {{ props.form.sync_message || '保存后可手动同步到雷池。' }}
          </div>
        </div>
        <div
          v-if="mode === 'edit'"
          class="rounded-[16px] border border-amber-200 bg-amber-50 px-3.5 py-3 text-xs leading-5 text-amber-900"
        >
          编辑模式下，如果不填写新的 PEM 与私钥，将继续保留现有证书内容。
        </div>
        <label class="space-y-1.5 md:col-span-2">
          <div class="flex items-center justify-between gap-3">
            <span class="text-xs text-slate-500">证书 PEM</span>
            <button
              type="button"
              class="text-xs font-medium text-blue-700 transition hover:text-blue-900"
              @click="emit('fillClipboard')"
            >
              {{ readingClipboard ? '识别中...' : '从剪切板识别' }}
            </button>
          </div>
          <textarea
            v-model="certificatePemModel"
            rows="8"
            class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 font-mono text-xs outline-none transition focus:border-blue-500"
          />
        </label>
        <label class="space-y-1.5 md:col-span-2">
          <span class="text-xs text-slate-500">私钥 PEM</span>
          <textarea
            v-model="privateKeyPemModel"
            rows="8"
            class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 font-mono text-xs outline-none transition focus:border-blue-500"
          />
        </label>
      </div>

      <div class="mt-5 flex flex-wrap items-center gap-3">
        <button
          :disabled="saving"
          class="inline-flex items-center gap-2 rounded-lg border border-blue-500/25 bg-white px-4 py-2 text-sm font-medium text-blue-700 transition hover:bg-blue-50 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('submit')"
        >
          <Save :size="14" />
          {{ saving ? '保存中...' : mode === 'create' ? '确认上传' : '保存修改' }}
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm text-stone-700 transition hover:border-slate-300"
          @click="emit('close')"
        >
          取消
        </button>
      </div>
    </div>
  </div>
</template>
