<script setup lang="ts">
defineProps<{
  autoPushableCount: number
  preflightSummary: {
    total: number
    ok: number
    create: number
    conflict: number
  }
  pushingIdsCount: number
}>()

const emit = defineEmits<{
  pushAutoMatched: []
}>()
</script>

<template>
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
          :disabled="autoPushableCount === 0 || pushingIdsCount > 0"
          class="inline-flex items-center justify-center rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-700 transition hover:border-emerald-300 hover:bg-emerald-100 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('pushAutoMatched')"
        >
          仅同步可自动命中的证书
        </button>
        <span class="text-xs leading-8 text-slate-500">
          基于当前预检结果，仅推送“可自动更新”的证书。
        </span>
      </div>
    </div>
  </section>
</template>
