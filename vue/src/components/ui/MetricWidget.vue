<script setup lang="ts">
import { computed } from 'vue'
import type { Component } from 'vue'
import { TrendingUp, TrendingDown } from 'lucide-vue-next'

const props = defineProps<{
  label: string
  value: string | number
  hint?: string
  trend?: 'up' | 'down' | 'neutral'
  icon?: Component
  series?: number[]
}>()

const chartPath = computed(() => {
  if (!props.series || props.series.length < 2) return ''
  const max = Math.max(...props.series)
  const min = Math.min(...props.series)
  const range = max - min || 1
  const step = 100 / (props.series.length - 1)

  return props.series
    .map((value, index) => {
      const x = index * step
      const normalized = 100 - ((value - min) / range) * 100
      return `${x},${normalized}`
    })
    .join(' ')
})
</script>

<template>
  <div
    class="relative overflow-hidden rounded-xl border border-slate-200 bg-white p-3 shadow-sm"
  >
    <div class="absolute inset-x-0 top-0 h-1 bg-blue-500"></div>
    <div class="absolute right-0 top-0 p-3 opacity-20">
      <component :is="icon" v-if="icon" :size="20" class="text-blue-600" />
    </div>

    <div class="space-y-1">
      <p class="text-xs font-medium text-slate-500">{{ label }}</p>
      <div class="flex flex-wrap items-end gap-1.5">
        <h3 class="text-xl font-semibold text-slate-900">{{ value }}</h3>
        <div
          v-if="trend"
          class="mb-0.5 flex items-center gap-1 text-xs font-medium"
          :class="[trend === 'up' ? 'text-red-600' : 'text-emerald-600']"
        >
          <TrendingUp v-if="trend === 'up'" :size="14" />
          <TrendingDown v-if="trend === 'down'" :size="14" />
          <span>{{ trend === 'up' ? '上升' : '下降' }}</span>
        </div>
      </div>
      <svg
        v-if="chartPath"
        class="mt-1 h-6 w-full text-blue-500"
        viewBox="0 0 100 100"
        preserveAspectRatio="none"
        aria-hidden="true"
      >
        <polyline
          :points="chartPath"
          fill="none"
          class="stroke-current"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
        <polyline
          :points="`${chartPath.split(' ')[0]} ${chartPath.split(' ').slice(-1)[0]}`"
          fill="none"
          class="stroke-blue-100"
          stroke-width="2"
        />
      </svg>
      <p
        v-if="hint"
        class="mt-2 border-t border-slate-100 pt-2 text-xs text-slate-500 truncate"
        :title="hint"
      >
        {{ hint }}
      </p>
    </div>
  </div>
</template>
