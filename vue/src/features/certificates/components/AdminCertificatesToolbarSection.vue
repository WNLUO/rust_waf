<script setup lang="ts">
defineProps<{
  deletingIdsCount: number
  generatingCertificate: boolean
  pullingSafeLine: boolean
  selectedCount: number
}>()

const emit = defineEmits<{
  create: []
  generate: []
  removeSelected: []
  sync: []
}>()
</script>

<template>
  <section class="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
    <div class="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
      <div>
        <p class="text-sm font-semibold text-stone-900">证书管理</p>
      </div>
      <div class="flex flex-wrap gap-2">
        <button
          :disabled="generatingCertificate"
          class="inline-flex items-center justify-center rounded-lg border border-emerald-500/25 bg-emerald-50 px-3 py-2 text-sm text-emerald-700 transition hover:bg-emerald-100 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('generate')"
        >
          {{ generatingCertificate ? '生成中...' : '生成随机证书' }}
        </button>
        <button
          :disabled="pullingSafeLine"
          class="inline-flex items-center justify-center rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('sync')"
        >
          {{ pullingSafeLine ? '同步中...' : '同步雷池证书' }}
        </button>
        <button
          class="inline-flex items-center justify-center rounded-lg bg-blue-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-blue-600/90"
          @click="emit('create')"
        >
          上传证书
        </button>
        <button
          :disabled="selectedCount === 0 || deletingIdsCount > 0"
          class="inline-flex items-center justify-center rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 transition hover:border-red-300 hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('removeSelected')"
        >
          批量删除
        </button>
      </div>
    </div>
  </section>
</template>
