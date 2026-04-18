<script setup lang="ts">
import { computed } from 'vue'
import type { Component } from 'vue'
import { Minus, TrendingUp, TrendingDown } from 'lucide-vue-next'

const props = defineProps<{
  label: string
  value: string | number
  hint?: string
  trend?: 'up' | 'down' | 'neutral'
  trendPlacement?: 'inline' | 'corner'
  icon?: Component
  series?: number[]
  seriesMin?: number
  seriesMax?: number
  progress?: number
  ambientSeries?: boolean
  noTopLine?: boolean
  filled?: boolean
}>()

const chartPath = computed(() => {
  if (!props.series || props.series.length < 2) return ''
  const rawMax = Math.max(...props.series)
  const rawMin = Math.min(...props.series)
  const min = props.seriesMin ?? Math.min(0, rawMin)
  const max = Math.max(props.seriesMax ?? rawMax * 1.25, min + 1)
  const range = max - min
  const step = 100 / (props.series.length - 1)

  const points = props.series.map((value, index) => ({
    x: index * step,
    y: 100 - ((Math.max(min, Math.min(max, value)) - min) / range) * 100,
  }))

  if (points.length === 2) {
    return `M ${points[0].x},${points[0].y} L ${points[1].x},${points[1].y}`
  }

  return points.reduce((path, point, index) => {
    if (index === 0) return `M ${point.x},${point.y}`
    const previous = points[index - 1]
    const controlX = (previous.x + point.x) / 2
    return `${path} C ${controlX},${previous.y} ${controlX},${point.y} ${point.x},${point.y}`
  }, '')
})

const chartAreaPath = computed(() => {
  if (!chartPath.value || !props.series || props.series.length < 2) return ''
  return `${chartPath.value} L 100,100 L 0,100 Z`
})

const progressPercent = computed(() => {
  if (props.progress === undefined) return null
  return Math.max(0, Math.min(100, props.progress))
})

const trendText = computed(() => {
  if (props.trend === 'up') return '上升'
  if (props.trend === 'down') return '下降'
  if (props.trend === 'neutral') return '保持'
  return ''
})

const trendTone = computed(() => {
  if (props.trend === 'up') return 'text-red-600'
  if (props.trend === 'down') return 'text-emerald-600'
  return 'text-slate-500'
})
</script>

<template>
  <div
    class="relative overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm"
    :class="filled ? 'px-3 py-2' : 'px-3 py-2.5'"
  >
    <div
      v-if="!noTopLine"
      class="absolute inset-x-0 top-0 h-0.5 bg-blue-500"
    ></div>
    <svg
      v-if="chartPath && ambientSeries"
      class="pointer-events-none absolute inset-x-0 bottom-0 h-full w-full text-blue-500"
      viewBox="0 0 100 100"
      preserveAspectRatio="none"
      aria-hidden="true"
    >
      <line
        v-for="y in [25, 50, 75]"
        :key="y"
        x1="0"
        x2="100"
        :y1="y"
        :y2="y"
        class="stroke-slate-200/70"
        stroke-width="1"
        stroke-dasharray="3 3"
      />
      <path :d="chartAreaPath" class="fill-blue-500/10" />
      <path
        :d="chartPath"
        fill="none"
        class="stroke-current opacity-50"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
      />
    </svg>
    <div
      v-if="trend && trendPlacement === 'corner'"
      class="absolute right-2.5 top-2.5 flex items-center gap-1 text-xs font-medium"
      :class="trendTone"
    >
      <TrendingUp v-if="trend === 'up'" :size="14" />
      <TrendingDown v-if="trend === 'down'" :size="14" />
      <Minus v-if="trend === 'neutral'" :size="14" />
      <span>{{ trendText }}</span>
    </div>
    <div
      v-if="icon && trendPlacement !== 'corner'"
      class="absolute right-0 top-0 p-2.5 opacity-15"
    >
      <component :is="icon" v-if="icon" :size="18" class="text-blue-600" />
    </div>

    <div
      class="relative z-10 flex h-full flex-col"
      :class="filled ? 'min-h-[5.25rem]' : 'min-h-[4.4rem]'"
    >
      <p
        class="truncate text-xs font-medium text-slate-500"
        :class="{ 'pr-12': icon || (trend && trendPlacement === 'corner') }"
      >
        {{ label }}
      </p>
      <div
        class="flex flex-1 flex-wrap items-center justify-center gap-1.5 text-center"
        :class="filled ? 'py-1.5' : ''"
      >
        <h3
          class="font-semibold text-slate-900"
          :class="filled ? 'text-2xl leading-7' : 'text-lg'"
        >
          {{ value }}
        </h3>
        <div
          v-if="trend && trendPlacement !== 'corner'"
          class="mb-0.5 flex items-center gap-1 text-xs font-medium"
          :class="trendTone"
        >
          <TrendingUp v-if="trend === 'up'" :size="14" />
          <TrendingDown v-if="trend === 'down'" :size="14" />
          <Minus v-if="trend === 'neutral'" :size="14" />
          <span>{{ trendText }}</span>
        </div>
      </div>
      <p
        v-if="hint"
        class="truncate text-center text-slate-500"
        :class="filled ? 'text-[11px]' : 'text-xs'"
        :title="hint"
      >
        {{ hint }}
      </p>
      <svg
        v-if="chartPath && !ambientSeries"
        class="mt-1 h-4 w-full text-blue-500"
        viewBox="0 0 100 100"
        preserveAspectRatio="none"
        aria-hidden="true"
      >
        <line
          v-for="y in [25, 50, 75]"
          :key="y"
          x1="0"
          x2="100"
          :y1="y"
          :y2="y"
          class="stroke-slate-200"
          stroke-width="1"
          stroke-dasharray="3 3"
        />
        <path
          :d="chartAreaPath"
          class="fill-blue-500/10"
        />
        <path
          :d="chartPath"
          fill="none"
          class="stroke-current"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
      </svg>
      <div
        v-else-if="progressPercent !== null"
        class="mt-1 rounded-full bg-rose-100"
        :class="filled ? 'h-2' : 'h-4'"
        aria-hidden="true"
      >
        <div
          class="h-full rounded-full bg-emerald-500 transition-[width] duration-500"
          :style="{ width: `${progressPercent}%` }"
        ></div>
      </div>
    </div>
  </div>
</template>
