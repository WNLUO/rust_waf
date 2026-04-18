<script setup lang="ts">
import { computed } from 'vue'
import type { Component } from 'vue'
import { TrendingUp, TrendingDown } from 'lucide-vue-next'

const props = defineProps<{
  label: string
  value: string | number
  hint?: string
  trend?: 'up' | 'down' | 'neutral'
  trendPlacement?: 'inline' | 'corner'
  icon?: Component
  series?: number[]
  noTopLine?: boolean
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
    class="relative overflow-hidden rounded-xl border border-slate-200 bg-white px-3 py-2.5 shadow-sm"
  >
    <div
      v-if="!noTopLine"
      class="absolute inset-x-0 top-0 h-0.5 bg-blue-500"
    ></div>
    <div
      v-if="trend && trendPlacement === 'corner'"
      class="absolute right-2.5 top-2.5 flex items-center gap-1 text-xs font-medium"
      :class="[trend === 'up' ? 'text-red-600' : 'text-emerald-600']"
    >
      <TrendingUp v-if="trend === 'up'" :size="14" />
      <TrendingDown v-if="trend === 'down'" :size="14" />
      <span>{{ trend === 'up' ? '上升' : '下降' }}</span>
    </div>
    <div
      v-if="icon && trendPlacement !== 'corner'"
      class="absolute right-0 top-0 p-2.5 opacity-15"
    >
      <component :is="icon" v-if="icon" :size="18" class="text-blue-600" />
    </div>

    <div>
      <p
        class="truncate text-xs font-medium text-slate-500"
        :class="{ 'pr-12': icon || (trend && trendPlacement === 'corner') }"
      >
        {{ label }}
      </p>
      <div class="flex flex-wrap items-end gap-1.5">
        <h3 class="text-lg font-semibold text-slate-900">{{ value }}</h3>
        <div
          v-if="trend && trendPlacement !== 'corner'"
          class="mb-0.5 flex items-center gap-1 text-xs font-medium"
          :class="[trend === 'up' ? 'text-red-600' : 'text-emerald-600']"
        >
          <TrendingUp v-if="trend === 'up'" :size="14" />
          <TrendingDown v-if="trend === 'down'" :size="14" />
          <span>{{ trend === 'up' ? '上升' : '下降' }}</span>
        </div>
      </div>
      <p v-if="hint" class="truncate text-xs text-slate-500" :title="hint">
        {{ hint }}
      </p>
      <svg
        v-if="chartPath"
        class="mt-1 h-4 w-full text-blue-500"
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
    </div>
  </div>
</template>
