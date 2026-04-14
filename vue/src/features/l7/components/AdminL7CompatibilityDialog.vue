<script setup lang="ts">
import { Save, X } from 'lucide-vue-next'
import type { AutoTuningRuntimePayload } from '@/features/l7/types/l7'
import {
  type L7ConfigForm,
} from '@/features/l7/utils/adminL7'
import AdminL7ConfigSection from './AdminL7ConfigSection.vue'

defineProps<{
  form: L7ConfigForm
  isOpen: boolean
  saving: boolean
  trustedProxyCidrsText: string
  autoTuningRuntime?: AutoTuningRuntimePayload | null
  dropUnmatchedRequests: boolean
  dropUnmatchedRequestsDisabled?: boolean
}>()

const emit = defineEmits<{
  close: []
  save: []
  'update:form': [value: L7ConfigForm]
  'update:trustedProxyCidrsText': [value: string]
  'update:dropUnmatchedRequests': [value: boolean]
}>()
</script>

<template>
  <div
    v-if="isOpen"
    class="fixed inset-0 z-[120] flex items-center justify-center px-4 py-8"
  >
    <div
      class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm"
      @click="emit('close')"
    ></div>
    <div
      class="relative w-full max-w-6xl rounded-[28px] border border-white/85 bg-[linear-gradient(160deg,rgba(255,250,244,0.98),rgba(244,239,231,0.98))] p-5 shadow-[0_24px_80px_rgba(60,40,20,0.24)]"
    >
      <div class="flex items-start justify-between gap-4">
        <div>
          <p class="text-sm tracking-wide text-amber-700">L7 兼容模式</p>
          <h3 class="mt-2 text-2xl font-semibold text-stone-900">
            编辑历史 CC / 自动调优细粒度参数
          </h3>
          <p class="mt-2 text-sm leading-6 text-slate-500">
            这里修改的是归档到兼容层的旧版 L7 CC 阈值和自动调优细项。仅建议在旧策略回滚或专项排障时使用。
          </p>
        </div>
        <button
          class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-slate-200 bg-white/75 transition hover:border-blue-500/40 hover:text-blue-700"
          @click="emit('close')"
        >
          <X :size="18" />
        </button>
      </div>

      <div class="mt-5 max-h-[70vh] overflow-y-auto pr-1">
        <AdminL7ConfigSection
          :form="form"
          compatibility-mode
          :trusted-proxy-cidrs-text="trustedProxyCidrsText"
          :auto-tuning-runtime="autoTuningRuntime"
          :drop-unmatched-requests="dropUnmatchedRequests"
          :drop-unmatched-requests-disabled="dropUnmatchedRequestsDisabled"
          @update:form="emit('update:form', $event)"
          @update:drop-unmatched-requests="
            emit('update:dropUnmatchedRequests', $event)
          "
          @update:trusted-proxy-cidrs-text="
            emit('update:trustedProxyCidrsText', $event)
          "
        />
      </div>

      <div class="mt-5 flex flex-wrap items-center gap-3">
        <button
          :disabled="saving"
          class="inline-flex items-center gap-2 rounded-lg bg-amber-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-amber-600/90 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('save')"
        >
          <Save :size="14" />
          {{ saving ? '保存中...' : '保存兼容层参数' }}
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
