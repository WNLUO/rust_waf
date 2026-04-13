<script setup lang="ts">
import { ref, onMounted, watch, onBeforeUnmount, toRef } from 'vue'
import * as echarts from 'echarts'
import type {
  EChartsOption,
  EffectScatterSeriesOption,
  LinesSeriesOption,
} from 'echarts'
import { useAdminEventMap } from '../composables/useAdminEventMap'
import type { EventMapNode, TrafficEventDelta, TrafficMapResponse } from '@/shared/types'

const props = defineProps<{
  trafficMap?: TrafficMapResponse | null
  trafficEvents?: TrafficEventDelta[]
}>()

const chartRef = ref<HTMLElement | null>(null)
let chart: echarts.ECharts | null = null

const { snapshot } = useAdminEventMap({
  trafficMap: toRef(props, 'trafficMap'),
})

const isOriginPending = () => !hasGeo(snapshot.value.originNode)

type GeoNode = EventMapNode & { lat: number; lng: number }
type Projectile = {
  id: string
  coords: number[][]
  color: string
  trailColor: string
  symbolSize: number
  curveness: number
  createdAt: number
  durationMs: number
}
type PendingLaunch = {
  key: string
  event: TrafficEventDelta
  count: number
  timer: number | null
}
type LocalLinesDataItem = {
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
  }
}

const PROJECTILE_DURATION_MS = 1000
const PROJECTILE_CAP = 32
const ACTIVE_TRAIL_OPACITY = 0.12
const MERGE_WINDOW_MS = 150

const activeProjectiles = ref<Projectile[]>([])
const processedTrafficEvents = new Set<string>()
const pendingLaunches = new Map<string, PendingLaunch>()
let cleanupTimer: number | null = null

const resizeChart = () => chart?.resize()

function hasGeo(node: EventMapNode): node is GeoNode {
  return typeof node.lat === 'number' && typeof node.lng === 'number'
}

function projectilePalette(event: TrafficEventDelta) {
  if (event.decision === 'block') {
    return {
      color: '#ff4d4f', // 鲜艳的红色
      trailColor: 'rgba(255, 77, 79, 0.15)',
      symbolSize: 4,
    }
  }
  if (event.direction === 'egress') {
    return {
      color: '#00f2fe', // 亮青色
      trailColor: 'rgba(0, 242, 254, 0.12)',
      symbolSize: 3,
    }
  }
  return {
    color: '#70ff00', // 荧光绿
    trailColor: 'rgba(112, 255, 0, 0.12)',
    symbolSize: 3,
  }
}

function launchKey(event: TrafficEventDelta) {
  return [event.node.id, event.direction, event.decision, event.source_ip].join(':')
}

function projectileSize(baseSize: number, count: number, decision: TrafficEventDelta['decision']) {
  if (decision === 'block') {
    return Math.min(baseSize + Math.min(count - 1, 1) * 0.35, baseSize + 0.35)
  }
  return Math.min(baseSize + Math.log2(count + 1) * 0.45, baseSize + 1.1)
}

function flushPendingLaunch(launch: PendingLaunch, originNode: GeoNode) {
  if (typeof launch.event.node.lat !== 'number' || typeof launch.event.node.lng !== 'number') {
    pendingLaunches.delete(launch.key)
    return
  }

  const isIngress = launch.event.direction === 'ingress'
  const coords = isIngress
    ? [[launch.event.node.lng, launch.event.node.lat], [originNode.lng, originNode.lat]]
    : [[originNode.lng, originNode.lat], [launch.event.node.lng, launch.event.node.lat]]
  const palette = projectilePalette(launch.event)
  const createdAt = Date.now()

  activeProjectiles.value = [
    ...activeProjectiles.value,
    {
      id: `${launch.key}-${createdAt}`,
      coords,
      color: palette.color,
      trailColor: palette.trailColor,
      symbolSize: projectileSize(
        palette.symbolSize,
        launch.count,
        launch.event.decision,
      ),
      curveness: 0.15 + Math.random() * 0.3,
      createdAt,
      durationMs: PROJECTILE_DURATION_MS + Math.random() * 120,
    },
  ].slice(-PROJECTILE_CAP)

  pendingLaunches.delete(launch.key)
}

function syncProjectiles() {
  const now = Date.now()
  const next = activeProjectiles.value.filter(
    (projectile) => now - projectile.createdAt < projectile.durationMs,
  )
  if (next.length !== activeProjectiles.value.length) {
    activeProjectiles.value = next
    renderChart()
  }
}

function ensureCleanupTimer() {
  if (cleanupTimer !== null) return
  cleanupTimer = window.setInterval(() => {
    syncProjectiles()
  }, 100)
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

function emitProjectiles(events: TrafficEventDelta[], originNode: GeoNode) {
  events.forEach((event) => {
    const key = trafficEventKey(event)
    if (processedTrafficEvents.has(key)) return
    processedTrafficEvents.add(key)

    if (event.decision === 'block') {
      flushPendingLaunch(
        {
          key: `${launchKey(event)}:${event.timestamp_ms}`,
          event,
          count: 1,
          timer: null,
        },
        originNode,
      )
      return
    }

    const mergedKey = launchKey(event)
    const existing = pendingLaunches.get(mergedKey)
    if (existing) {
      existing.count += 1
      existing.event = event
      return
    }

    const launch: PendingLaunch = {
      key: mergedKey,
      event,
      count: 1,
      timer: window.setTimeout(() => {
        const pending = pendingLaunches.get(mergedKey)
        if (!pending) return
        flushPendingLaunch(pending, originNode)
        renderChart()
      }, MERGE_WINDOW_MS),
    }
    pendingLaunches.set(mergedKey, launch)
  })

  if (processedTrafficEvents.size > 256) {
    const retained = Array.from(processedTrafficEvents).slice(-128)
    processedTrafficEvents.clear()
    retained.forEach((value) => processedTrafficEvents.add(value))
  }

}

// 加载地图并初始化
const initMap = async () => {
  if (!chartRef.value) return

  // 获取 GeoJSON 数据
  try {
    const response = await fetch('/maps/china-full.geojson')
    const geoJson = await response.json()
    
    echarts.registerMap('china', geoJson)

    chart = echarts.init(chartRef.value)
    renderChart()
  } catch (error) {
    console.error('Failed to load map data:', error)
  }
}

const renderChart = () => {
  if (!chart) return

  const { nodes, originNode } = snapshot.value
  if (!hasGeo(originNode)) {
    // ... (unchanged fallback)
    chart.setOption({
      backgroundColor: 'transparent',
      tooltip: { show: false },
      geo: {
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
        },
        regions: [{ name: '南海诸岛', itemStyle: { opacity: 0 } }]
      },
      series: []
    })
    return
  }

  const geoNodes = nodes.filter(hasGeo)
  const projectileLinesData: LocalLinesDataItem[] = activeProjectiles.value.map((projectile) => ({
    coords: projectile.coords,
    lineStyle: {
      color: projectile.trailColor,
      width: 1,
      opacity: ACTIVE_TRAIL_OPACITY,
      curveness: projectile.curveness,
    },
    effect: {
      show: true,
      period: Math.max(projectile.durationMs / 1000, 0.5),
      trailLength: 0.22, // 稍微再长一点点
      symbol: 'path://M5 0 L10 5 L5 10 L0 5 Z', // 菱形符号
      symbolSize: projectile.symbolSize,
      color: projectile.color,
      shadowBlur: 12, // 增强发光
      shadowColor: projectile.color,
    },
  }))

  // 转换节点为散点数据
  const scatterData = geoNodes.map(node => ({
    name: node.name,
    value: [node.lng, node.lat, node.trafficWeight],
    itemStyle: {
      color: node.id === snapshot.value.hottestNode?.id ? '#fbbf24' : '#60a5fa',
      shadowBlur: 8,
      shadowColor: node.id === snapshot.value.hottestNode?.id ? '#fbbf24' : '#60a5fa'
    }
  }))

  // 添加源站节点
  scatterData.push({
    name: originNode.name,
    value: [originNode.lng, originNode.lat, 2.5],
    itemStyle: {
      color: '#10b981',
      shadowBlur: 15,
      shadowColor: '#10b981'
    }
  })

  const linesSeries: LinesSeriesOption = {
    type: 'lines',
    coordinateSystem: 'geo',
    zlevel: 3, // 提升到最上层
    effect: {
      show: true,
      constantSpeed: 0,
      trailLength: 0.22,
      symbolSize: 3,
    },
    lineStyle: {
      curveness: 0.2,
    },
    data: projectileLinesData,
  }

  const scatterSeries: EffectScatterSeriesOption = {
    type: 'effectScatter',
    coordinateSystem: 'geo',
    zlevel: 2,
    rippleEffect: {
      brushType: 'stroke',
      scale: 3
    },
    label: {
      show: false
    },
    symbolSize: (val: unknown) => {
      const point = Array.isArray(val) ? val : []
      const weight = typeof point[2] === 'number' ? point[2] : 0
      return 3 + weight * 2
    },
    data: scatterData
  }

  const option: EChartsOption = {
    backgroundColor: 'transparent',
    tooltip: {
      show: false
    },
    geo: {
      map: 'china',
      roam: false,
      zoom: 1.75, // 大幅增加放大比例，使得陆地几乎占满视口
      center: [104.5, 36.5], // 调整中心点到大陆腹地，彻底挤出南海等非必要留白区域
      emphasis: {
        disabled: true
      },
      label: {
        show: false
      },
      itemStyle: {
        areaColor: '#1e293b',
        borderColor: '#334155',
        borderWidth: 1,
        shadowColor: 'rgba(0, 0, 0, 0.5)',
        shadowBlur: 10
      },
      regions: [
        {
          name: '南海诸岛',
          itemStyle: {
            opacity: 0
          },
          label: {
            show: false
          }
        }
      ]
    },
    series: [linesSeries, scatterSeries]
  }

  chart.setOption(option)
}

watch(
  () => snapshot.value,
  (value) => {
    if (!hasGeo(value.originNode)) {
      processedTrafficEvents.clear()
      activeProjectiles.value = []
    }
    renderChart()
  },
  { deep: true },
)

watch(
  () => props.trafficEvents ?? [],
  (events) => {
    const originNode = snapshot.value.originNode
    if (!hasGeo(originNode)) return
    emitProjectiles(events, originNode)
    renderChart()
  },
  { deep: true },
)

// 监听数据变化更新图表
watch(() => activeProjectiles.value.length, () => {
  renderChart()
})

onMounted(() => {
  initMap()
  ensureCleanupTimer()
  window.addEventListener('resize', resizeChart)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', resizeChart)
  if (cleanupTimer !== null) {
    window.clearInterval(cleanupTimer)
    cleanupTimer = null
  }
  pendingLaunches.forEach((launch) => {
    if (launch.timer !== null) {
      window.clearTimeout(launch.timer)
    }
  })
  pendingLaunches.clear()
  chart?.dispose()
})
</script>

<template>
  <div class="cyber-card h-[500px] flex flex-col overflow-hidden">
    <div class="flex items-center justify-between mb-4 px-2">
      <div class="flex items-center gap-2">
        <div class="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></div>
        <h3 class="text-sm font-medium text-slate-300 uppercase tracking-wider">实时流量监控 (CDN ↔ 源站)</h3>
      </div>
      <div class="flex items-center gap-4 text-xs text-slate-500">
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
        <div class="rounded-lg border border-slate-700/80 bg-slate-900/80 px-4 py-3 text-sm text-slate-200 shadow-xl">
          后端正在获取物理位置中
        </div>
      </div>
      
      <!-- 装饰性网格/线条 (可选，增强科技感) -->
      <div class="absolute inset-0 pointer-events-none opacity-10">
        <div class="absolute inset-0" style="background-image: radial-gradient(#334155 1px, transparent 1px); background-size: 20px 20px;"></div>
      </div>

      <!-- 状态覆盖层 -->
      <div class="absolute bottom-4 left-4 bg-slate-900/60 backdrop-blur-md border border-slate-700 p-3 rounded-lg flex flex-col gap-2 min-w-[140px]">
        <div class="flex justify-between items-center text-[10px] text-slate-400">
          <span>活跃节点</span>
          <span class="text-blue-400 font-mono">{{ snapshot.activeNodeCount }}</span>
        </div>
        <div class="flex justify-between items-center text-[10px] text-slate-400">
          <span>拦截流</span>
          <span class="text-red-400 font-mono">{{ snapshot.blockedFlowCount }}</span>
        </div>
        <div class="flex justify-between items-center text-[10px] text-slate-400">
          <span>最高带宽</span>
          <span class="text-emerald-400 font-mono">{{ (snapshot.peakBandwidthMbps).toFixed(1) }} Mbps</span>
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
  padding: 1.5rem;
  border-radius: 0.75rem;
}
</style>
