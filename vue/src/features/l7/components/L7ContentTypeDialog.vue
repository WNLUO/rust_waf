<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  contentTypeDraft: string
  contentTypeOptions: string[]
  selectContentTypeOption: (option: string) => unknown
  confirmContentTypeDialog: () => unknown
  closeContentTypeDialog: () => unknown
}>()

const emit = defineEmits<{
  'update:contentTypeDraft': [value: string]
}>()

const contentTypeDraftModel = computed({
  get: () => props.contentTypeDraft,
  set: (value) => emit('update:contentTypeDraft', value),
})
</script>

<template>
      <div
        class="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/30 px-4"
        @click.self="closeContentTypeDialog"
      >
        <div
          class="w-full max-w-lg rounded-2xl border border-slate-200 bg-white p-5 shadow-[0_24px_60px_rgba(15,23,42,0.18)]"
        >
          <div class="flex items-start justify-between gap-4">
            <div>
              <p class="text-sm tracking-wider text-blue-700">Content-Type</p>
              <h3 class="mt-2 text-lg font-semibold text-stone-900">
                选择或输入替换 Content-Type
              </h3>
            </div>
            <button
              type="button"
              class="rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-stone-600 transition hover:border-slate-300 hover:text-stone-900"
              @click="closeContentTypeDialog"
            >
              关闭
            </button>
          </div>

          <div class="mt-4 flex flex-wrap gap-2">
            <button
              v-for="option in contentTypeOptions"
              :key="option"
              type="button"
              class="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs text-stone-700 transition hover:border-blue-300 hover:text-blue-700"
              @click="selectContentTypeOption(option)"
            >
              {{ option }}
            </button>
          </div>

          <label class="mt-4 block text-sm text-stone-700">
            自定义输入
            <input
              v-model="contentTypeDraftModel"
              type="text"
              placeholder="例如 text/html; charset=utf-8"
              class="mt-2 w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-left outline-none transition focus:border-blue-500"
            />
          </label>

          <div class="mt-5 flex justify-end gap-2">
            <button
              type="button"
              class="rounded-lg border border-slate-200 px-4 py-2 text-sm text-stone-700 transition hover:border-slate-300 hover:text-stone-900"
              @click="closeContentTypeDialog"
            >
              取消
            </button>
            <button
              type="button"
              class="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-700"
              @click="confirmContentTypeDialog"
            >
              确定
            </button>
          </div>
        </div>
      </div>
</template>
