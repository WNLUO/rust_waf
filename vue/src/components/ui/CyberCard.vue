<script setup lang="ts">
defineProps<{
  title?: string
  subTitle?: string
  noPadding?: boolean
}>()
</script>

<template>
  <div class="bg-cyber-surface border border-cyber-border rounded-cyber overflow-hidden shadow-lg shadow-black/20">
    <div v-if="title" class="px-6 py-4 border-b border-cyber-border flex justify-between items-center bg-gradient-to-r from-white/5 to-transparent">
      <div>
        <h3 class="font-bold text-sm uppercase tracking-widest text-gray-100">{{ title }}</h3>
        <p v-if="subTitle" class="text-[10px] text-cyber-muted mt-0.5 font-mono">{{ subTitle }}</p>
      </div>
      <slot name="header-action"></slot>
    </div>
    <div :class="[noPadding ? '' : 'p-6']">
      <slot></slot>
    </div>
  </div>
</template>
