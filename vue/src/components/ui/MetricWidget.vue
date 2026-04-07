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
  <div class="bg-cyber-surface border border-cyber-border p-5 rounded-cyber relative group hover:border-cyber-accent/50 transition-all duration-300">
    <div class="absolute top-0 right-0 p-3 opacity-20 group-hover:opacity-100 transition-opacity">
      <component :is="icon" v-if="icon" :size="24" class="text-cyber-accent" />
    </div>
    
    <div class="space-y-1">
      <p class="text-[10px] uppercase font-mono tracking-widest text-cyber-muted">{{ label }}</p>
      <div class="flex items-end gap-3">
        <h3 class="text-2xl font-bold text-gray-100 font-mono">{{ value }}</h3>
        <div v-if="trend" class="flex items-center gap-1 text-[10px] mb-1.5" :class="[trend === 'up' ? 'text-cyber-error' : 'text-cyber-success']">
          <TrendingUp v-if="trend === 'up'" :size="10" />
          <TrendingDown v-if="trend === 'down'" :size="10" />
          <span>{{ trend === 'up' ? '+2.4%' : '-1.2%' }}</span>
        </div>
      </div>
      <p v-if="hint" class="text-[10px] text-cyber-muted/60 pt-2 border-t border-cyber-border/30 mt-2 truncate">{{ hint }}</p>
    </div>
    
    <div class="absolute bottom-0 left-0 h-[2px] bg-cyber-accent w-0 group-hover:w-full transition-all duration-500"></div>
  </div>
</template>
