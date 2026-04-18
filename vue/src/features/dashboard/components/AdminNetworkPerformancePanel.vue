<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { LineChart } from 'echarts/charts'
import type { LineSeriesOption } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import type {
  GridComponentOption,
  TooltipComponentOption,
} from 'echarts/components'
import { init, use } from 'echarts/core'
import type { ComposeOption, ECharts } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { useFormatters } from '@/shared/composables/useFormatters'

use([LineChart, GridComponent, TooltipComponent, CanvasRenderer])

type NetworkChartOption = ComposeOption<
  GridComponentOption | TooltipComponentOption | LineSeriesOption
>

const props = defineProps<{
  rxRate: number
  txRate: number
  rxTotal: number
  txTotal: number
  timestamps: number[]
  rxSeries: number[]
  txSeries: number[]
  mapMode?: 'china' | 'global'
}>()

const chartEl = ref<HTMLDivElement | null>(null)
let chart: ECharts | null = null

const { formatBytes } = useFormatters()
const megabyte = 1024 * 1024
const stepMs = 1_000
const slotCountForMapMode = (mode?: 'china' | 'global') =>
  mode === 'china' ? 10 : 6
const targetSlotCount = computed(() => slotCountForMapMode(props.mapMode))
const displayedSlotCount = ref(targetSlotCount.value)
const slotCount = computed(() => displayedSlotCount.value)
const windowMs = computed(() => (slotCount.value - 1) * stepMs)
const timeFormatter = new Intl.DateTimeFormat('zh-CN', {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
})
let slotCountTransitionTimer: number | null = null

const statItems = computed(() => [
  {
    label: '上行',
    value: `${formatBytes(props.txRate)}/s`,
    dot: 'bg-emerald-500',
  },
  {
    label: '下行',
    value: `${formatBytes(props.rxRate)}/s`,
    dot: 'bg-amber-500',
  },
  {
    label: '总发送',
    value: formatBytes(props.txTotal),
    dot: 'bg-slate-500',
  },
  {
    label: '总接收',
    value: formatBytes(props.rxTotal),
    dot: 'bg-slate-500',
  },
])

const chartSlots = computed(() => {
  const latestTimestamp = props.timestamps.at(-1) || Date.now()
  const end = Math.floor(latestTimestamp / stepMs) * stepMs
  return Array.from(
    { length: slotCount.value },
    (_, index) => end - windowMs.value + index * stepMs,
  )
})

const currentLabels = computed(() =>
  chartSlots.value.map((timestamp, index, slots) =>
    index === slots.length - 1
      ? '现在'
      : timeFormatter.format(new Date(timestamp)),
  ),
)

const formatMegabytes = (value: number) =>
  `${(value / megabyte).toFixed(1)} MB`

const seriesForSlots = (series: number[]) =>
  chartSlots.value.map((slot) => {
    for (let index = props.timestamps.length - 1; index >= 0; index -= 1) {
      const timestamp = props.timestamps[index]
      if (timestamp <= slot && timestamp > slot - stepMs) {
        return series[index] || 0
      }
    }
    return 0
  })

const currentRxSeries = computed(() => seriesForSlots(props.rxSeries))
const currentTxSeries = computed(() => seriesForSlots(props.txSeries))
const chartPeak = computed(() =>
  Math.max(0, ...currentRxSeries.value, ...currentTxSeries.value),
)
const previousChartPeak = computed(() =>
  Math.max(
    0,
    ...currentRxSeries.value.slice(0, -1),
    ...currentTxSeries.value.slice(0, -1),
  ),
)
const yAxisMax = computed(() => {
  const peak = chartPeak.value
  if (peak <= 0) return megabyte

  const previousPeak = previousChartPeak.value
  const isBurst = previousPeak > 0 && peak >= previousPeak * 1.8
  const max = peak * (isBurst ? 1.5 : 2)
  return Math.max(megabyte, Math.ceil(max / megabyte) * megabyte)
})
const yAxisInterval = computed(() => yAxisMax.value / 4)

const renderChart = async () => {
  await nextTick()
  if (!chartEl.value) return
  if (!chart) chart = init(chartEl.value)

  const option: NetworkChartOption = {
    animation: true,
    animationDurationUpdate: 450,
    animationEasingUpdate: 'cubicOut',
    grid: {
      left: 58,
      right: 12,
      top: 28,
      bottom: 20,
      containLabel: false,
    },
    tooltip: {
      trigger: 'axis',
      backgroundColor: 'rgba(15, 23, 42, 0.94)',
      borderColor: 'rgba(148, 163, 184, 0.24)',
      textStyle: {
        color: '#e5e7eb',
        fontSize: 12,
      },
      valueFormatter: (value) => `${formatBytes(Number(value || 0))}/s`,
    },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: currentLabels.value,
      axisLine: {
        lineStyle: {
          color: 'rgba(148, 163, 184, 0.5)',
        },
      },
      axisTick: {
        show: false,
      },
      axisLabel: {
        color: '#aeb7c4',
        fontSize: 11,
        hideOverlap: true,
      },
    },
    yAxis: {
      type: 'value',
      min: 0,
      max: yAxisMax.value,
      interval: yAxisInterval.value,
      axisLabel: {
        color: '#aeb7c4',
        fontSize: 11,
        formatter: (value: number) => formatMegabytes(value),
      },
      splitLine: {
        lineStyle: {
          color: 'rgba(148, 163, 184, 0.32)',
          type: 'dashed',
        },
      },
    },
    series: [
      {
        name: '下行',
        type: 'line',
        smooth: true,
        symbol: 'circle',
        symbolSize: 5,
        data: currentRxSeries.value,
        lineStyle: {
          width: 2,
          color: '#f59e0b',
        },
        itemStyle: {
          color: '#f59e0b',
        },
        areaStyle: {
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(245, 158, 11, 0.32)' },
              { offset: 1, color: 'rgba(245, 158, 11, 0)' },
            ],
          },
        },
      },
      {
        name: '上行',
        type: 'line',
        smooth: true,
        symbol: 'circle',
        symbolSize: 5,
        data: currentTxSeries.value,
        lineStyle: {
          width: 2,
          color: '#22c55e',
        },
        itemStyle: {
          color: '#22c55e',
        },
      },
    ],
  }

  chart.setOption(option)
}

const resizeChart = () => chart?.resize()

function renderAndResizeChart() {
  void renderChart().then(() => {
    resizeChart()
  })
}

watch(
  targetSlotCount,
  (nextSlotCount) => {
    if (slotCountTransitionTimer !== null) {
      window.clearInterval(slotCountTransitionTimer)
      slotCountTransitionTimer = null
    }

    slotCountTransitionTimer = window.setInterval(() => {
      const currentSlotCount = displayedSlotCount.value
      if (currentSlotCount === nextSlotCount) {
        if (slotCountTransitionTimer !== null) {
          window.clearInterval(slotCountTransitionTimer)
          slotCountTransitionTimer = null
        }
        return
      }

      displayedSlotCount.value =
        currentSlotCount + (currentSlotCount < nextSlotCount ? 1 : -1)
    }, 90)
  },
)

watch(
  () => [
    displayedSlotCount.value,
    props.timestamps.length,
    props.timestamps.at(-1),
    props.rxSeries.length,
    props.rxSeries.at(-1),
    props.txSeries.length,
    props.txSeries.at(-1),
    props.rxRate,
    props.txRate,
    props.mapMode,
  ],
  renderAndResizeChart,
)

onMounted(() => {
  void renderChart()
  window.addEventListener('resize', resizeChart)
})

onBeforeUnmount(() => {
  if (slotCountTransitionTimer !== null) {
    window.clearInterval(slotCountTransitionTimer)
  }
  window.removeEventListener('resize', resizeChart)
  chart?.dispose()
  chart = null
})
</script>

<template>
  <section
    class="overflow-hidden rounded-lg border border-slate-800 bg-[#111418] p-3 shadow-sm"
  >
    <div class="grid grid-cols-4 gap-2">
      <div
        v-for="item in statItems"
        :key="item.label"
        class="min-w-0 rounded-lg border border-white/5 bg-white/[0.03] px-2 py-2"
      >
        <div class="min-w-0">
          <div class="flex min-w-0 items-center gap-1.5">
            <span
              class="h-2 w-2 shrink-0 rounded-full"
              :class="item.dot"
            ></span>
            <p class="truncate text-xs font-medium text-slate-300">
              {{ item.label }}
            </p>
          </div>
          <p
            class="mt-1 break-all text-xs font-semibold leading-tight text-slate-100"
            :title="item.value"
          >
            {{ item.value }}
          </p>
        </div>
      </div>
    </div>

    <div ref="chartEl" class="mt-4 h-[306px] w-full"></div>
  </section>
</template>
