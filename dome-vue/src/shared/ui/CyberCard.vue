<script setup lang="ts">
defineProps<{
  title?: string
  subTitle?: string
  noPadding?: boolean
}>()
</script>

<template>
  <div
    class="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm"
  >
    <div
      v-if="title"
      class="flex items-center justify-between border-b border-slate-200 bg-slate-50 px-4 py-3"
    >
      <div>
        <h3 class="text-base font-semibold text-slate-900">{{ title }}</h3>
        <p v-if="subTitle" class="mt-0.5 text-xs text-slate-500">
          {{ subTitle }}
        </p>
      </div>
      <slot name="header-action"></slot>
    </div>
    <div :class="[noPadding ? '' : 'p-4']">
      <slot></slot>
    </div>
  </div>
</template>
