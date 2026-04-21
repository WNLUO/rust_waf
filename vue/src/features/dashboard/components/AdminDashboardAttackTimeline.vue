<script setup lang="ts">
import { computed } from 'vue'
import { Activity, Gauge, ShieldCheck, Zap } from 'lucide-vue-next'

type Timeline = {
  timestamps: number[]
  proxySuccesses: number[]
  proxyFailures: number[]
  fastPathBlocks: number[]
  hotCacheHits: number[]
  noDecisions: number[]
  verifiedPasses: number[]
  l4DegradeActions: number[]
  blockedL7: number[]
  pressureLevels: string[]
  defenseDepths: string[]
}

const props = defineProps<{
  timeline: Timeline
  currentPressure: string
  currentDepth: string
  cpuScore: number
  formatNumber: (value: number) => string
}>()

const width = 720
const height = 178
const chartTop = 16
const chartBottom = 152

const latest = (series: number[]) => series.at(-1) || 0
const sum = (series: number[]) =>
  series.reduce((total, item) => total + item, 0)

const maxValue = computed(() =>
  Math.max(
    ...props.timeline.fastPathBlocks,
    ...props.timeline.hotCacheHits,
    ...props.timeline.proxySuccesses,
    ...props.timeline.noDecisions,
    1,
  ),
)

const xAt = (index: number, length: number) => {
  if (length <= 1) return 0
  return (index / (length - 1)) * width
}

const yAt = (value: number) => {
  const ratio = Math.min(1, value / maxValue.value)
  return chartBottom - ratio * (chartBottom - chartTop)
}

const linePoints = (series: number[]) =>
  series
    .map((value, index) => `${xAt(index, series.length)},${yAt(value)}`)
    .join(' ')

const areaPoints = (series: number[]) => {
  if (series.length === 0) return ''
  return `0,${chartBottom} ${linePoints(series)} ${width},${chartBottom}`
}

const recentStatus = computed(() => {
  const length = props.timeline.timestamps.length
  return Array.from({ length }).map((_, index) => ({
    key: `${props.timeline.timestamps[index]}-${index}`,
    pressure: props.timeline.pressureLevels[index] || 'normal',
    depth: props.timeline.defenseDepths[index] || 'unknown',
  }))
})

const pressureClass = (pressure: string) => {
  if (pressure === 'attack') return 'bg-red-500'
  if (pressure === 'high') return 'bg-amber-500'
  if (pressure === 'elevated') return 'bg-sky-500'
  return 'bg-emerald-500'
}

const depthClass = (depth: string) => {
  if (depth === 'survival') return 'bg-red-500'
  if (depth === 'lean') return 'bg-amber-500'
  if (depth === 'balanced') return 'bg-sky-500'
  return 'bg-emerald-500'
}

const pressureLabel = (pressure: string) => {
  if (pressure === 'attack') return 'attack'
  if (pressure === 'high') return 'high'
  if (pressure === 'elevated') return 'elevated'
  return pressure || 'normal'
}

const depthLabel = (depth: string) => depth || 'unknown'

const cards = computed(() => [
  {
    label: '成功代理',
    value: latest(props.timeline.proxySuccesses),
    total: sum(props.timeline.proxySuccesses),
    icon: ShieldCheck,
    tone: 'text-emerald-700 bg-emerald-50 border-emerald-200',
  },
  {
    label: '快路径拦截',
    value: latest(props.timeline.fastPathBlocks),
    total: sum(props.timeline.fastPathBlocks),
    icon: Zap,
    tone: 'text-red-700 bg-red-50 border-red-200',
  },
  {
    label: '热缓存命中',
    value: latest(props.timeline.hotCacheHits),
    total: sum(props.timeline.hotCacheHits),
    icon: Activity,
    tone: 'text-sky-700 bg-sky-50 border-sky-200',
  },
  {
    label: 'L4降级',
    value: latest(props.timeline.l4DegradeActions),
    total: sum(props.timeline.l4DegradeActions),
    icon: Gauge,
    tone: 'text-amber-700 bg-amber-50 border-amber-200',
  },
])
</script>

<template>
  <section
    class="rounded-xl border border-slate-200 bg-white p-3 shadow-sm"
    aria-label="攻击过程时间序列"
  >
    <div
      class="flex flex-col gap-3 border-b border-slate-100 pb-3 lg:flex-row lg:items-center lg:justify-between"
    >
      <div>
        <p class="text-sm font-semibold text-slate-950">攻击过程</p>
        <p class="mt-1 text-xs text-slate-500">
          {{ timeline.timestamps.length }} 个采样点，峰值
          {{ formatNumber(maxValue) }}
        </p>
      </div>
      <div class="flex flex-wrap items-center gap-2 text-xs">
        <span
          class="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-2 py-1 text-slate-600"
        >
          压力 {{ pressureLabel(currentPressure) }}
        </span>
        <span
          class="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-2 py-1 text-slate-600"
        >
          深度 {{ depthLabel(currentDepth) }}
        </span>
        <span
          class="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-2 py-1 text-slate-600"
        >
          CPU分 {{ formatNumber(cpuScore) }}
        </span>
      </div>
    </div>

    <div class="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
      <div
        v-for="card in cards"
        :key="card.label"
        class="min-w-0 rounded-lg border px-3 py-2"
        :class="card.tone"
      >
        <div class="flex items-center justify-between gap-2">
          <p class="truncate text-xs font-medium">{{ card.label }}</p>
          <component :is="card.icon" :size="15" />
        </div>
        <div class="mt-1 flex items-end justify-between gap-2">
          <p class="truncate text-lg font-semibold leading-6">
            {{ formatNumber(card.value) }}
          </p>
          <p class="truncate text-[11px] opacity-75">
            累计 {{ formatNumber(card.total) }}
          </p>
        </div>
      </div>
    </div>

    <div
      class="mt-3 overflow-hidden rounded-lg border border-slate-100 bg-slate-950"
    >
      <svg
        class="h-52 w-full"
        :viewBox="`0 0 ${width} ${height}`"
        preserveAspectRatio="none"
        role="img"
      >
        <defs>
          <linearGradient id="attack-fast-area" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stop-color="#ef4444" stop-opacity="0.22" />
            <stop offset="100%" stop-color="#ef4444" stop-opacity="0.02" />
          </linearGradient>
          <linearGradient id="attack-success-area" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stop-color="#10b981" stop-opacity="0.18" />
            <stop offset="100%" stop-color="#10b981" stop-opacity="0.01" />
          </linearGradient>
        </defs>
        <g stroke="rgba(148, 163, 184, 0.16)" stroke-width="1">
          <line x1="0" :y1="chartTop" :x2="width" :y2="chartTop" />
          <line x1="0" y1="84" :x2="width" y2="84" />
          <line x1="0" :y1="chartBottom" :x2="width" :y2="chartBottom" />
        </g>
        <polygon
          :points="areaPoints(timeline.proxySuccesses)"
          fill="url(#attack-success-area)"
        />
        <polygon
          :points="areaPoints(timeline.fastPathBlocks)"
          fill="url(#attack-fast-area)"
        />
        <polyline
          :points="linePoints(timeline.proxySuccesses)"
          fill="none"
          stroke="#34d399"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="3"
        />
        <polyline
          :points="linePoints(timeline.fastPathBlocks)"
          fill="none"
          stroke="#fb7185"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="3"
        />
        <polyline
          :points="linePoints(timeline.hotCacheHits)"
          fill="none"
          stroke="#38bdf8"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2.4"
        />
        <polyline
          :points="linePoints(timeline.noDecisions)"
          fill="none"
          stroke="#facc15"
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2"
          stroke-dasharray="6 5"
        />
      </svg>
      <div
        class="grid grid-cols-2 gap-x-4 gap-y-2 border-t border-white/10 px-3 py-2 text-[11px] text-slate-300 md:grid-cols-4"
      >
        <span class="inline-flex items-center gap-1.5">
          <i class="h-2 w-4 rounded-full bg-emerald-400"></i>成功代理
        </span>
        <span class="inline-flex items-center gap-1.5">
          <i class="h-2 w-4 rounded-full bg-rose-400"></i>快路径拦截
        </span>
        <span class="inline-flex items-center gap-1.5">
          <i class="h-2 w-4 rounded-full bg-sky-400"></i>热缓存命中
        </span>
        <span class="inline-flex items-center gap-1.5">
          <i class="h-2 w-4 rounded-full bg-yellow-300"></i>未决放行
        </span>
      </div>
    </div>

    <div class="mt-3 grid gap-2 text-[11px] text-slate-500">
      <div class="flex items-center gap-2">
        <span class="w-12 shrink-0">压力</span>
        <div class="grid min-w-0 flex-1 grid-flow-col auto-cols-fr gap-0.5">
          <i
            v-for="item in recentStatus"
            :key="`pressure-${item.key}`"
            class="h-2 rounded-sm"
            :class="pressureClass(item.pressure)"
            :title="item.pressure"
          ></i>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <span class="w-12 shrink-0">深度</span>
        <div class="grid min-w-0 flex-1 grid-flow-col auto-cols-fr gap-0.5">
          <i
            v-for="item in recentStatus"
            :key="`depth-${item.key}`"
            class="h-2 rounded-sm"
            :class="depthClass(item.depth)"
            :title="item.depth"
          ></i>
        </div>
      </div>
    </div>
  </section>
</template>
