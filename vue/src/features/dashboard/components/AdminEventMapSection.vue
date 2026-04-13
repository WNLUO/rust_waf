<script setup lang="ts">
defineProps<{
  metrics?: unknown
  events?: unknown[]
}>()
</script>

<template>
  <div class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
    <div class="rounded-lg border border-dashed border-slate-300 bg-slate-50 px-4 py-10 text-center">
      <h3 class="text-base font-semibold text-slate-900">事件地图</h3>
      <p class="mt-2 text-sm text-slate-500">
        当前地图样式与动画逻辑已清空，等待后续重新实现。
      </p>
    </div>
  </div>
</template>
