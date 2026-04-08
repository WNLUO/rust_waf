<script setup lang="ts">
defineProps<{
  title?: string
  subTitle?: string
  noPadding?: boolean
}>()
</script>

<template>
  <div class="overflow-hidden rounded-[30px] border border-white/80 bg-white/75 shadow-[0_18px_48px_rgba(90,60,30,0.08)]">
    <div v-if="title" class="flex items-center justify-between border-b border-cyber-border/60 bg-gradient-to-r from-cyber-surface-strong to-white px-6 py-4">
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
