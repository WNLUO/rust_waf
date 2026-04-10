<script setup lang="ts">
defineProps<{
  title?: string
  subTitle?: string
  noPadding?: boolean
}>()
</script>

<template>
  <div class="overflow-hidden rounded-2xl border border-cyber-border/60 bg-white shadow-sm">
    <div v-if="title" class="flex items-center justify-between border-b border-cyber-border/60 bg-cyber-surface-strong px-6 py-4">
      <div>
        <h3 class="text-lg font-semibold text-stone-900">{{ title }}</h3>
        <p v-if="subTitle" class="mt-1 text-sm text-cyber-muted">{{ subTitle }}</p>
      </div>
      <slot name="header-action"></slot>
    </div>
    <div :class="[noPadding ? '' : 'p-6']">
      <slot></slot>
    </div>
  </div>
</template>
