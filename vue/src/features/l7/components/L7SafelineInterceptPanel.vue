<script setup lang="ts">
import type { Ref, WritableComputedRef } from 'vue'
import L7ContentTypeDialog from '@/features/l7/components/L7ContentTypeDialog.vue'

type ModelRef<T> = Ref<T> | WritableComputedRef<T>

defineProps<{
  controls: {
    safelineInterceptEnabled: ModelRef<boolean>
    safelineInterceptAction: ModelRef<string>
    safelineInterceptMatchMode: ModelRef<string>
    safelineInterceptMaxBodyBytes: ModelRef<number>
    safelineInterceptBlockDuration: ModelRef<number>
    safelineResponseStatusCode: ModelRef<number>
    safelineResponseContentType: ModelRef<string>
    safelineResponseBodySource: ModelRef<string>
    contentTypeDialogOpen: Ref<boolean>
    contentTypeDraft: Ref<string>
    contentTypeOptions: string[]
    openContentTypeDialog: () => unknown
    selectContentTypeOption: (value: string) => unknown
    confirmContentTypeDialog: () => unknown
    closeContentTypeDialog: () => unknown
  }
  numberInputClass: string
}>()
</script>

<template>
    <div class="mt-3 border-t border-slate-200 pt-6">
      <div
        class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
      >
        <div>
          <p class="text-sm tracking-wider text-blue-700">
            SafeLine 响应接管（独立运行项）
          </p>
        </div>
        <div class="flex flex-wrap gap-3">
          <label
            class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-3 py-1.5 text-xs text-stone-700"
          >
            <span>启用响应接管</span>
            <input
              v-model="controls.safelineInterceptEnabled.value"
              type="checkbox"
              class="ui-switch"
            />
          </label>
        </div>
      </div>

      <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
        <label class="l7-inline-field text-sm text-stone-700">
          默认动作
          <select v-model="controls.safelineInterceptAction.value" class="l7-inline-select">
            <option value="replace">替换响应</option>
            <option value="pass">放行</option>
            <option value="drop">直接丢弃</option>
            <option value="replace_and_block_ip">替换并封禁 IP</option>
          </select>
        </label>
        <label class="l7-inline-field text-sm text-stone-700">
          匹配模式
          <select v-model="controls.safelineInterceptMatchMode.value" class="l7-inline-select">
            <option value="strict">严格匹配</option>
            <option value="relaxed">宽松匹配</option>
          </select>
        </label>
        <label class="l7-inline-field text-sm text-stone-700"
          >识别最大响应体(bytes)<input
            v-model.number="controls.safelineInterceptMaxBodyBytes.value"
            type="number"
            min="256"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >本地封禁时长(s)<input
            v-model.number="controls.safelineInterceptBlockDuration.value"
            type="number"
            min="30"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700"
          >替换状态码<input
            v-model.number="controls.safelineResponseStatusCode.value"
            type="number"
            min="100"
            max="599"
            :class="numberInputClass"
        /></label>
        <label class="l7-inline-field text-sm text-stone-700 md:col-span-2"
          >替换 Content-Type<button
            type="button"
            :class="`${numberInputClass} l7-inline-button`"
            @click="controls.openContentTypeDialog"
          >
            {{ controls.safelineResponseContentType.value || '点击选择或输入' }}
          </button>
        </label>
        <div class="text-sm text-stone-700">
          响应体来源
          <select
            v-model="controls.safelineResponseBodySource.value"
            class="mt-2 w-full rounded-[18px] border border-slate-200 bg-white px-4 py-3 text-sm outline-none transition focus:border-blue-500/40"
          >
            <option value="inline_text">内联文本</option>
            <option value="file">文件</option>
          </select>
        </div>
      </div>

      <L7ContentTypeDialog
        v-if="controls.contentTypeDialogOpen.value"
        v-model:content-type-draft="controls.contentTypeDraft.value"
        :content-type-options="controls.contentTypeOptions"
        :select-content-type-option="controls.selectContentTypeOption"
        :confirm-content-type-dialog="controls.confirmContentTypeDialog"
        :close-content-type-dialog="controls.closeContentTypeDialog"
      />
    </div>
</template>

<style scoped>
.l7-inline-field {
  display: flex;
  align-items: center;
  justify-content: flex-start;
  gap: 0.5rem;
  color: rgb(100 116 139);
  font-size: 0.75rem;
  font-weight: 500;
  white-space: nowrap;
}

.l7-inline-field :deep(input),
.l7-inline-field :deep(select),
.l7-inline-field :deep(.numberInputClass) {
  width: 5rem;
  margin-top: 0 !important;
  border-radius: 0.375rem;
  border: 1px solid rgb(203 213 225);
  background: transparent;
  padding: 0.25rem 0.5rem;
  box-shadow: none;
  text-align: center;
  transition: border-color 0.2s ease;
}

.l7-inline-field :deep(input[type='number']::-webkit-outer-spin-button),
.l7-inline-field :deep(input[type='number']::-webkit-inner-spin-button) {
  -webkit-appearance: none;
  margin: 0;
}

.l7-inline-field :deep(input[type='number']) {
  -moz-appearance: textfield;
  appearance: textfield;
}

.l7-inline-select {
  width: auto;
  min-width: 8.5rem;
}

.l7-inline-button {
  width: auto;
  min-width: 12rem;
  text-align: center;
  cursor: pointer;
}

.l7-inline-field :deep(input:focus),
.l7-inline-field :deep(select:focus) {
  border-color: rgba(59, 130, 246, 0.65);
}

.ui-switch {
  appearance: none;
  width: 2.25rem;
  height: 1.25rem;
  border-radius: 9999px;
  background: rgb(203 213 225);
  position: relative;
  cursor: pointer;
  transition: background-color 0.2s ease;
}

.ui-switch::after {
  content: '';
  position: absolute;
  top: 0.125rem;
  left: 0.125rem;
  width: 1rem;
  height: 1rem;
  border-radius: 9999px;
  background: white;
  transition: transform 0.2s ease;
}

.ui-switch:checked {
  background: rgb(37 99 235);
}

.ui-switch:checked::after {
  transform: translateX(1rem);
}
</style>
