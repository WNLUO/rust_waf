<script setup lang="ts">
import { computed } from 'vue'
import { Network, X } from 'lucide-vue-next'

const props = defineProps<{
  actions: {
    savingGlobalEntry: boolean
  }
  form: {
    http_port: string
    https_port: string
  }
  isOpen: boolean
}>()

const emit = defineEmits<{
  close: []
  save: []
  'update:form': [value: { http_port: string; https_port: string }]
}>()

function updateForm(patch: Partial<{ http_port: string; https_port: string }>) {
  emit('update:form', {
    ...props.form,
    ...patch,
  })
}

const httpPort = computed({
  get: () => props.form.http_port,
  set: (value: string) => updateForm({ http_port: value }),
})

const httpsPort = computed({
  get: () => props.form.https_port,
  set: (value: string) => updateForm({ https_port: value }),
})
</script>

<template>
  <teleport to="body">
    <div
      v-if="isOpen"
      class="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/35 px-4 py-6 backdrop-blur-sm"
    >
      <div class="w-full max-w-lg overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-2xl">
        <div class="flex items-center justify-between border-b border-slate-200 px-5 py-4">
          <div class="flex items-center gap-3">
            <div class="flex h-11 w-11 items-center justify-center rounded-2xl bg-blue-50 text-blue-700">
              <Network :size="20" />
            </div>
            <div>
              <p class="text-xs tracking-wide text-blue-700">Global Entry</p>
              <h3 class="text-lg font-semibold text-stone-900">全局入口</h3>
            </div>
          </div>
          <button
            class="rounded-full p-2 text-slate-500 transition hover:bg-slate-100 hover:text-slate-700"
            @click="emit('close')"
          >
            <X :size="18" />
          </button>
        </div>

        <div class="space-y-4 px-5 py-5">
          <p class="text-sm leading-6 text-slate-500">
            保存前会校验端口是否已被其他进程占用；如果端口可用，保存后 Rust 会立即接管监听。
          </p>

          <label class="space-y-1.5">
            <span class="text-xs text-slate-500">统一 HTTP 入口端口</span>
            <input
              v-model="httpPort"
              type="text"
              inputmode="numeric"
              placeholder="例如 8080"
              class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
            />
          </label>

          <label class="space-y-1.5">
            <span class="text-xs text-slate-500">统一 HTTPS 入口端口</span>
            <input
              v-model="httpsPort"
              type="text"
              inputmode="numeric"
              placeholder="例如 660，可留空关闭 HTTPS 入口"
              class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
            />
          </label>
        </div>

        <div class="flex items-center justify-end gap-2 border-t border-slate-200 px-5 py-4">
          <button
            class="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
            @click="emit('close')"
          >
            取消
          </button>
          <button
            :disabled="actions.savingGlobalEntry"
            class="rounded-lg bg-blue-600 px-3 py-2 text-xs font-medium text-white transition hover:bg-blue-600/90 disabled:cursor-not-allowed disabled:opacity-60"
            @click="emit('save')"
          >
            {{ actions.savingGlobalEntry ? '保存中...' : '保存入口' }}
          </button>
        </div>
      </div>
    </div>
  </teleport>
</template>
