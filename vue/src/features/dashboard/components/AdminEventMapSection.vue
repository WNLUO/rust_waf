<script setup lang="ts">
import { ref, shallowRef, onMounted, watch, onBeforeUnmount, toRef } from 'vue'
import { EffectScatterChart, LinesChart } from 'echarts/charts'
import type {
  EffectScatterSeriesOption,
  LinesSeriesOption,
} from 'echarts/charts'
import { GeoComponent, TooltipComponent } from 'echarts/components'
import { init, registerMap, use } from 'echarts/core'
import type { ECharts } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { useAdminEventMap } from '../composables/useAdminEventMap'
import type {
  EventMapNode,
  TrafficEventDelta,
  TrafficMapResponse,
} from '@/shared/types'

use([
  CanvasRenderer,
  GeoComponent,
  TooltipComponent,
  LinesChart,
  EffectScatterChart,
])

const props = defineProps<{
  trafficMap?: TrafficMapResponse | null
  trafficEvents?: TrafficEventDelta[]
}>()

const chartRef = ref<HTMLElement | null>(null)
let chart: ECharts | null = null

const { snapshot } = useAdminEventMap({
  trafficMap: toRef(props, 'trafficMap'),
})

const isOriginPending = () => !hasGeo(snapshot.value.originNode)

type GeoNode = EventMapNode & { lat: number; lng: number }

type RealtimeNodeRecord = {
  node: GeoNode
  expireAt: number
}

type LocalLinesDataItem = {
  name: string
  coords: number[][]
  lineStyle: {
    color: string
    width: number
    opacity: number
    curveness: number
  }
  effect: {
    show: boolean
    period: number
    trailLength: number
    symbol: string
    symbolSize: number
    color: string
    shadowBlur?: number
    shadowColor?: string
    loop: boolean
  }
  expireAt: number
}

const PROJECTILE_CAP = 80 // 限制同屏最大炮弹数
const ACTIVE_TRAIL_OPACITY = 0.12
const NORMAL_RATE_LIMIT_MS = 800 // 正常流量频率限制：同节点同方向每800ms最多一发
const BLOCK_RATE_LIMIT_MS = 250 // 拦截流量频率限制：同节点同方向每250ms最多一发

// 使用基于 ID 的数组更新替代环形缓冲区，ECharts 通过 name (唯一标识) 进行 diff，不会重置旧动画
const activeLinesData = shallowRef<LocalLinesDataItem[]>([])

const processedTrafficEvents = new Set<string>()
const lastLaunchTime = new Map<string, number>()
const activeRealtimeNodes = new Map<string, RealtimeNodeRecord>()

let cleanupTimer: number | null = null
let renderTimeout: number | null = null
let lastRenderTime = 0

// 防抖/节流图表渲染，避免 ECharts 频繁 setOption 导致主线程阻塞
const scheduleRender = () => {
  const now = Date.now()
  if (now - lastRenderTime >= 150) {
    if (renderTimeout) {
      clearTimeout(renderTimeout)
      renderTimeout = null
    }
    lastRenderTime = now
    renderChart()
  } else if (!renderTimeout) {
    renderTimeout = window.setTimeout(
      () => {
        lastRenderTime = Date.now()
        renderTimeout = null
        renderChart()
      },
      150 - (now - lastRenderTime),
    )
  }
}

const resizeChart = () => chart?.resize()

function hasGeo(node: EventMapNode): node is GeoNode {
  return typeof node.lat === 'number' && typeof node.lng === 'number'
}

function projectilePalette(event: TrafficEventDelta) {
  if (event.decision === 'block') {
    return {
      color: '#ff4d4f', // 鲜艳的红色
      trailColor: 'rgba(255, 77, 79, 0.15)',
      symbolSize: 4.5,
    }
  }
  if (event.direction === 'egress') {
    return {
      color: '#00f2fe', // 亮青色
      trailColor: 'rgba(0, 242, 254, 0.12)',
      symbolSize: 3.5,
    }
  }
  return {
    color: '#70ff00', // 荧光绿
    trailColor: 'rgba(112, 255, 0, 0.12)',
    symbolSize: 3.5,
  }
}

function launchKey(event: TrafficEventDelta) {
  return [event.node.id, event.direction, event.decision].join(':')
}

function trafficEventKey(event: TrafficEventDelta) {
  return [
    event.timestamp_ms,
    event.direction,
    event.decision,
    event.source_ip,
    event.bytes,
    event.node.id,
  ].join(':')
}

function runCleanup() {
  const now = Date.now()
  let changed = false

  // 清理过期的线条
  const nextLines = activeLinesData.value.filter((line) => now < line.expireAt)
  if (nextLines.length !== activeLinesData.value.length) {
    activeLinesData.value = nextLines
    changed = true
  }

  // 清理过期的实时节点（超过 5 秒没有新流量的节点渐渐消失）
  for (const [id, record] of activeRealtimeNodes.entries()) {
    if (now > record.expireAt) {
      activeRealtimeNodes.delete(id)
      changed = true
    }
  }

  if (changed) {
    scheduleRender()
  }
}

function ensureCleanupTimer() {
  if (cleanupTimer !== null) return
  cleanupTimer = window.setInterval(runCleanup, 200)
}

function emitProjectiles(events: TrafficEventDelta[], originNode: GeoNode) {
  const now = Date.now()
  let hasNew = false

  events.forEach((event) => {
    const key = trafficEventKey(event)
    if (processedTrafficEvents.has(key)) return
    processedTrafficEvents.add(key)

    if (
      typeof event.node.lat === 'number' &&
      typeof event.node.lng === 'number'
    ) {
      activeRealtimeNodes.set(event.node.id, {
        node: event.node as GeoNode,
        expireAt: now + 5000, // 节点小圆圈 5 秒后渐渐消失
      })
    } else {
      return
    }

    const linkKey = launchKey(event)
    const limitMs =
      event.decision === 'block' ? BLOCK_RATE_LIMIT_MS : NORMAL_RATE_LIMIT_MS
    const lastTime = lastLaunchTime.get(linkKey) || 0

    if (now - lastTime >= limitMs) {
      const isIngress = event.direction === 'ingress'
      const coords = isIngress
        ? [
            [event.node.lng, event.node.lat],
            [originNode.lng, originNode.lat],
          ]
        : [
            [originNode.lng, originNode.lat],
            [event.node.lng, event.node.lat],
          ]
      const palette = projectilePalette(event)

      const durationMs = 1000 + Math.random() * 120

      const lineData: LocalLinesDataItem = {
        name: `${linkKey}-${now}`,
        coords,
        lineStyle: {
          color: palette.trailColor,
          width: 1,
          opacity: ACTIVE_TRAIL_OPACITY + 0.15,
          curveness: 0.15 + Math.random() * 0.3,
        },
        effect: {
          show: true,
          period: Math.max(durationMs / 1000, 0.5),
          trailLength: 0.22,
          symbol: 'path://M5 0 L10 5 L5 10 L0 5 Z',
          symbolSize: palette.symbolSize,
          color: palette.color,
          loop: false, // 动画播放一次即停止
        },
        expireAt: now + durationMs + 800,
      }

      activeLinesData.value = [...activeLinesData.value, lineData].slice(
        -PROJECTILE_CAP,
      )

      lastLaunchTime.set(linkKey, now)
      hasNew = true
    }
  })

  if (hasNew) {
    scheduleRender()
  }

  if (processedTrafficEvents.size > 256) {
    const retained = Array.from(processedTrafficEvents).slice(-128)
    processedTrafficEvents.clear()
    retained.forEach((value) => processedTrafficEvents.add(value))
  }

  if (lastLaunchTime.size > 100) {
    lastLaunchTime.clear()
  }
}

const baseGeoConfig = {
  map: 'china',
  roam: false,
  zoom: 1.75,
  center: [104.5, 36.5],
  emphasis: { disabled: true },
  label: { show: false },
  itemStyle: {
    areaColor: '#1e293b',
    borderColor: '#334155',
    borderWidth: 1,
    shadowColor: 'rgba(0, 0, 0, 0.5)',
    shadowBlur: 10,
  },
  regions: [
    { name: '南海诸岛', itemStyle: { opacity: 0 }, label: { show: false } },
  ],
}

// 加载地图并初始化
const initMap = async () => {
  if (!chartRef.value) return

  try {
    const response = await fetch('/maps/china-full.geojson')
    const geoJson = await response.json()

    registerMap('china', geoJson)

    chart = init(chartRef.value)

    chart.setOption({
      backgroundColor: 'transparent',
      tooltip: { show: false },
      geo: baseGeoConfig,
      series: [],
    })

    renderChart()
  } catch (error) {
    console.error('Failed to load map data:', error)
  }
}

const renderChart = () => {
  if (!chart) return

  const { nodes, originNode } = snapshot.value
  if (!hasGeo(originNode)) {
    chart.setOption({ series: [] })
    return
  }

  const snapshotNodeMap = new Map(nodes.filter(hasGeo).map((n) => [n.id, n]))
  activeRealtimeNodes.forEach((record, id) => {
    if (!snapshotNodeMap.has(id)) {
      snapshotNodeMap.set(id, { ...record.node, trafficWeight: 1 })
    }
  })
  const geoNodes = Array.from(snapshotNodeMap.values())

  const scatterData = geoNodes.map((node) => ({
    name: node.name,
    value: [node.lng, node.lat, node.trafficWeight],
    itemStyle: {
      color: node.id === snapshot.value.hottestNode?.id ? '#fbbf24' : '#60a5fa',
    },
  }))

  scatterData.push({
    name: originNode.name,
    value: [originNode.lng, originNode.lat, 2.5],
    itemStyle: {
      color: '#10b981',
    },
  })

  const linesSeries: LinesSeriesOption = {
    type: 'lines',
    coordinateSystem: 'geo',
    zlevel: 3,
    effect: {
      show: true,
      constantSpeed: 0,
      trailLength: 0.22,
      symbolSize: 3,
    },
    lineStyle: {
      curveness: 0.2,
    },
    data: activeLinesData.value,
  }

  const scatterSeries: EffectScatterSeriesOption = {
    type: 'effectScatter',
    coordinateSystem: 'geo',
    zlevel: 2,
    rippleEffect: {
      brushType: 'stroke',
      scale: 3,
    },
    label: {
      show: false,
    },
    symbolSize: (val: unknown) => {
      const point = Array.isArray(val) ? val : []
      const weight = typeof point[2] === 'number' ? point[2] : 0
      return 3 + weight * 2
    },
    data: scatterData,
  }

  chart.setOption({
    series: [linesSeries, scatterSeries],
  })
}

watch(
  () => snapshot.value,
  (value) => {
    if (!hasGeo(value.originNode)) {
      processedTrafficEvents.clear()
      activeLinesData.value = []
    }
    scheduleRender()
  },
  { deep: true },
)

watch(
  () => props.trafficEvents,
  (events) => {
    if (!events || events.length === 0) return
    const originNode = snapshot.value.originNode
    if (!hasGeo(originNode)) return
    emitProjectiles(events, originNode)
  },
)

onMounted(() => {
  initMap()
  ensureCleanupTimer()
  window.addEventListener('resize', resizeChart)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', resizeChart)
  if (renderTimeout !== null) {
    window.clearTimeout(renderTimeout)
    renderTimeout = null
  }
  if (cleanupTimer !== null) {
    window.clearInterval(cleanupTimer)
    cleanupTimer = null
  }
  lastLaunchTime.clear()
  activeRealtimeNodes.clear()
  chart?.dispose()
})
</script>

<template>
  <div class="cyber-card h-[410px] flex flex-col overflow-hidden">
    <div class="mb-2 flex items-center justify-between px-1">
      <div class="flex items-center gap-2">
        <div class="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></div>
        <h3 class="text-sm font-medium text-slate-300 uppercase tracking-wider">
          实时流量监控 (CDN ↔ 源站)
        </h3>
      </div>
      <div class="hidden items-center gap-3 text-xs text-slate-500 sm:flex">
        <div class="flex items-center gap-1">
          <span class="w-2 h-[2px] bg-blue-500"></span>
          <span>CDN 请求</span>
        </div>
        <div class="flex items-center gap-1">
          <span class="w-2 h-[2px] bg-emerald-500"></span>
          <span>源站响应</span>
        </div>
        <div class="flex items-center gap-1">
          <span class="w-2 h-[2px] bg-red-500"></span>
          <span>拦截异常</span>
        </div>
      </div>
    </div>

    <div class="relative flex-1">
      <!-- 地图容器 -->
      <div ref="chartRef" class="w-full h-full"></div>

      <div
        v-if="isOriginPending()"
        class="absolute inset-0 z-10 flex items-center justify-center bg-slate-950/45 backdrop-blur-[2px] pointer-events-none"
      >
        <div
          class="rounded-lg border border-slate-700/80 bg-slate-900/80 px-4 py-3 text-sm text-slate-200 shadow-xl"
        >
          后端正在获取物理位置中
        </div>
      </div>

      <!-- 装饰性网格/线条 (可选，增强科技感) -->
      <div class="absolute inset-0 pointer-events-none opacity-10">
        <div
          class="absolute inset-0"
          style="
            background-image: radial-gradient(#334155 1px, transparent 1px);
            background-size: 20px 20px;
          "
        ></div>
      </div>

      <!-- 状态覆盖层 -->
      <div
        class="absolute bottom-3 left-3 flex min-w-[132px] flex-col gap-1.5 rounded-lg border border-slate-700 bg-slate-900/60 p-2.5 backdrop-blur-md"
      >
        <div
          class="flex justify-between items-center text-[10px] text-slate-400"
        >
          <span>活跃节点</span>
          <span class="text-blue-400 font-mono">{{
            snapshot.activeNodeCount
          }}</span>
        </div>
        <div
          class="flex justify-between items-center text-[10px] text-slate-400"
        >
          <span>拦截流</span>
          <span class="text-red-400 font-mono">{{
            snapshot.blockedFlowCount
          }}</span>
        </div>
        <div
          class="flex justify-between items-center text-[10px] text-slate-400"
        >
          <span>最高带宽</span>
          <span class="text-emerald-400 font-mono"
            >{{ snapshot.peakBandwidthMbps.toFixed(1) }} Mbps</span
          >
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.cyber-card {
  background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
  border: 1px solid #334155;
  box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
  padding: 1rem;
  border-radius: 0.75rem;
}
</style>
