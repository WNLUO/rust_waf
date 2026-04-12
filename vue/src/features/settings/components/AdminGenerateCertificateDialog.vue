<script setup lang="ts">
import { computed } from 'vue'
import { RefreshCw, X } from 'lucide-vue-next'

const props = defineProps<{
  form: {
    name: string
    domainsText: string
  }
  generatingCertificate: boolean
  isOpen: boolean
  savingDefaultCertificate: boolean
}>()

const emit = defineEmits<{
  close: []
  submit: []
  'update:form': [value: { name: string; domainsText: string }]
}>()

const nameModel = computed({
  get: () => props.form.name,
  set: (value: string) => emit('update:form', { ...props.form, name: value }),
})

const domainsTextModel = computed({
  get: () => props.form.domainsText,
  set: (value: string) =>
    emit('update:form', { ...props.form, domainsText: value }),
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
      class="relative w-full max-w-xl rounded-xl border border-white/85 bg-[linear-gradient(160deg,rgba(255,250,244,0.98),rgba(244,239,231,0.98))] p-5 shadow-[0_24px_80px_rgba(60,40,20,0.24)]"
    >
      <div class="flex items-start justify-between gap-4">
        <div>
          <p class="text-sm tracking-wide text-emerald-700">证书生成</p>
          <h3 class="mt-2 text-2xl font-semibold text-stone-900">
            生成随机假证书
          </h3>
          <p class="mt-2 text-sm leading-6 text-slate-500">
            名称和域名都可留空。留空域名时系统会自动补一个 `.local`
            域名，并在生成后自动设为默认证书。
          </p>
        </div>
        <button
          class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-slate-200 bg-white/75 transition hover:border-emerald-500/40 hover:text-emerald-700"
          @click="emit('close')"
        >
          <X :size="18" />
        </button>
      </div>

      <div class="mt-5 grid gap-4">
        <label class="space-y-1.5">
          <span class="text-xs text-slate-500">证书名称</span>
          <input
            v-model="nameModel"
            type="text"
            placeholder="可留空，系统自动命名"
            class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-emerald-500"
          />
        </label>
        <label class="space-y-1.5">
          <span class="text-xs text-slate-500">域名列表</span>
          <input
            v-model="domainsTextModel"
            type="text"
            placeholder="多个域名用逗号分隔，可留空"
            class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-emerald-500"
          />
        </label>
      </div>

      <div class="mt-5 flex flex-wrap items-center gap-3">
        <button
          :disabled="generatingCertificate || savingDefaultCertificate"
          class="inline-flex items-center gap-2 rounded-lg border border-emerald-500/25 bg-emerald-50 px-4 py-2 text-sm font-medium text-emerald-700 transition hover:bg-emerald-100 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('submit')"
        >
          <RefreshCw
            :size="14"
            :class="{ 'animate-spin': generatingCertificate }"
          />
          {{ generatingCertificate ? '生成中...' : '生成并设为默认' }}
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white/75 px-4 py-2 text-sm text-stone-700 transition hover:border-slate-300"
          @click="emit('close')"
        >
          取消
        </button>
      </div>
    </div>
  </div>
</template>
