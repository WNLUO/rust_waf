<script setup lang="ts">
import type { Component } from 'vue'
import { TrendingUp, TrendingDown } from 'lucide-vue-next'

defineProps<{
  label: string
  value: string | number
  hint?: string
  trend?: 'up' | 'down' | 'neutral'
  icon?: Component
}>()
</script>

<template>
  <div class="group relative overflow-hidden rounded-[28px] border border-white/80 bg-white/75 p-5 shadow-[0_16px_44px_rgba(90,60,30,0.08)] transition-all duration-300 hover:-translate-y-1 hover:shadow-[0_22px_50px_rgba(127,47,18,0.14)]">
    <div class="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-cyber-accent to-cyber-success opacity-70"></div>
    <div class="absolute right-0 top-0 p-4 opacity-25 transition-opacity group-hover:opacity-90">
      <component :is="icon" v-if="icon" :size="24" class="text-cyber-accent-strong" />
    </div>

    <div class="space-y-2">
      <p class="text-xs tracking-[0.2em] text-cyber-muted">{{ label }}</p>
      <div class="flex items-end gap-3">
        <h3 class="font-mono text-3xl font-bold text-stone-900">{{ value }}</h3>
        <div v-if="trend" class="mb-1.5 flex items-center gap-1 text-xs" :class="[trend === 'up' ? 'text-cyber-error' : 'text-cyber-success']">
          <TrendingUp v-if="trend === 'up'" :size="10" />
          <TrendingDown v-if="trend === 'down'" :size="10" />
          <span>{{ trend === 'up' ? '上升' : '下降' }}</span>
        </div>
      </div>
      <p v-if="hint" class="mt-3 border-t border-cyber-border/40 pt-3 text-sm leading-6 text-cyber-muted">{{ hint }}</p>
    </div>
  </div>
</template>
