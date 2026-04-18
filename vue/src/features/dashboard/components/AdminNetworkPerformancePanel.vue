<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { TrendingUp, TrendingDown, Minus } from 'lucide-vue-next'
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
const stepMs = 1_000
const slotCountForMapMode = (mode?: 'china' | 'global') =>
  mode === 'china' ? 10 : 6
const targetSlotCount = computed(() => slotCountForMapMode(props.mapMode))
const displayedSlotCount = ref(targetSlotCount.value)
const slotCount = computed(() => displayedSlotCount.value)
const windowMs = computed(() => (slotCount.value - 1) * stepMs)
let slotCountTransitionTimer: number | null = null

const getTrend = (series: number[]) => {
  const len = series.length
  if (len < 2) return { text: '保持', icon: Minus, color: 'text-slate-500' }
  const current = series[len - 1]
  const prev = series[len - 2]
  // 当流量差异超过 5% 时认为是有明显变化，否则认为是保持
  if (current > prev * 1.05) return { text: '升高', icon: TrendingUp, color: 'text-emerald-500' }
  if (current < prev * 0.95) return { text: '降低', icon: TrendingDown, color: 'text-amber-500' }
  return { text: '保持', icon: Minus, color: 'text-slate-500' }
}

const statItems = computed(() => [
  {
    label: '上行',
    value: `${formatBytes(props.txRate)}/s`,
    dot: 'bg-emerald-500',
    trend: getTrend(props.txSeries),
  },
  {
    label: '下行',
    value: `${formatBytes(props.rxRate)}/s`,
    dot: 'bg-amber-500',
    trend: getTrend(props.rxSeries),
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

const formatAxisRate = (value: number) => {
  if (value === 0) return '0 B'
  if (value < 1024) return `${value.toFixed(0)} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`
  return `${(value / (1024 * 1024)).toFixed(1)} MB`
}

const currentRxData = computed(() =>
  props.timestamps.map((t, i) => [t, props.rxSeries[i] || 0]),
)
const currentTxData = computed(() =>
  props.timestamps.map((t, i) => [t, props.txSeries[i] || 0]),
)

let rafId: number | null = null

const renderChart = async () => {
  await nextTick()
  if (!chartEl.value) return
  if (!chart) chart = init(chartEl.value)

  const now = Date.now()
  const option: NetworkChartOption = {
    animation: false, // 彻底禁用内置动画，完全由物理引擎逐帧驱动
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
      type: 'time',
      boundaryGap: ['0%', '0%'],
      min: now - windowMs.value,
      max: now,
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
        formatter: (value: number) => {
          const date = new Date(value)
          return `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}:${date.getSeconds().toString().padStart(2, '0')}`
        },
      },
      splitLine: {
        show: false,
      },
    },
    yAxis: {
      type: 'value',
      min: 0,
      max: 1024 * 10,
      interval: (1024 * 10) / 4,
      axisLabel: {
        color: '#aeb7c4',
        fontSize: 11,
        formatter: (value: number) => formatAxisRate(value),
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
        symbol: 'none',
        data: currentRxData.value,
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
        symbol: 'none',
        data: currentTxData.value,
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

let currentRenderYMax = 1024 * 10

const startAnimation = () => {
  const animate = () => {
    if (chart) {
      const now = Date.now()
      // 维持 1500ms 的延迟渲染缓冲区
      const renderTime = now - 1500
      const minTime = renderTime - windowMs.value

      // 关键修复：只计算当前“视口可见范围内”的数据峰值，忽略屏幕外的历史数据
      let visiblePeak = 0
      for (let i = 0; i < props.timestamps.length; i++) {
        // 多容忍一秒的余量，防止数据点刚划出屏幕时 Y 轴立刻暴跌导致抖动
        if (props.timestamps[i] >= minTime - 1000) {
          const rx = props.rxSeries[i] || 0
          const tx = props.txSeries[i] || 0
          if (rx > visiblePeak) visiblePeak = rx
          if (tx > visiblePeak) visiblePeak = tx
        }
      }

      // 目标最大值为屏幕可见数据峰值的 2 倍
      const targetYMax = Math.max(1024 * 10, visiblePeak * 2)
      // 平滑逼近，形成连续呼吸效果
      currentRenderYMax += (targetYMax - currentRenderYMax) * 0.08

      chart.setOption({
        xAxis: {
          min: minTime,
          max: renderTime,
        },
        yAxis: {
          max: currentRenderYMax,
          interval: currentRenderYMax / 4,
        },
      })
    }
    rafId = requestAnimationFrame(animate)
  }
  rafId = requestAnimationFrame(animate)
}

let resizeObserver: ResizeObserver | null = null

onMounted(() => {
  void renderChart().then(() => {
    startAnimation()
    if (chartEl.value) {
      resizeObserver = new ResizeObserver(() => {
        resizeChart()
      })
      resizeObserver.observe(chartEl.value)
    }
  })
  window.addEventListener('resize', resizeChart)
})

onBeforeUnmount(() => {
  resizeObserver?.disconnect()
  if (rafId !== null) {
    cancelAnimationFrame(rafId)
  }
  if (slotCountTransitionTimer !== null) {
    window.clearInterval(slotCountTransitionTimer)
  }
  window.removeEventListener('resize', resizeChart)
  chart?.dispose()
  chart = null
})

// 当真实数据到达时更新系列数据
watch(
  () => [currentRxData.value, currentTxData.value],
  () => {
    const rx = [...currentRxData.value]
    const tx = [...currentTxData.value]

    // 关键修复：向未来延伸一个虚拟点，保持当前最后的值。
    // 这样无论是在“全国模式”更宽的画布下，还是遇到网络微小抖动，
    // X 轴的右侧视口边缘永远会被这根平移线“填满”，不会再出现突然断开的留白。
    if (rx.length > 0) {
      const future = Date.now() + 10000
      rx.push([future, rx[rx.length - 1][1]])
      tx.push([future, tx[tx.length - 1][1]])
    }

    chart?.setOption({
      series: [
        { data: rx },
        { data: tx },
      ],
    })
  },
  { deep: true }
)

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
        <div class="flex min-w-0 items-center justify-between gap-2">
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

          <div
            v-if="props.mapMode === 'china' && item.trend"
            class="flex shrink-0 items-center gap-1 rounded-md bg-white/5 px-1.5 py-1"
            :class="item.trend.color"
          >
            <component :is="item.trend.icon" :size="14" />
            <span class="text-[10px] font-medium leading-none">{{ item.trend.text }}</span>
          </div>
        </div>
      </div>
    </div>

    <div ref="chartEl" class="mt-4 h-[306px] w-full"></div>
  </section>
</template>
