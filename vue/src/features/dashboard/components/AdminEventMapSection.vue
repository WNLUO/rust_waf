<script setup lang="ts">
import { ref, onMounted, watch, onBeforeUnmount, toRef } from 'vue'
import * as echarts from 'echarts'
import type {
  EChartsOption,
  EffectScatterSeriesOption,
  LinesSeriesOption,
} from 'echarts'
import { useAdminEventMap } from '../composables/useAdminEventMap'
import type { EventMapFlow, EventMapNode, TrafficMapResponse } from '@/shared/types'

const props = defineProps<{
  trafficMap?: TrafficMapResponse | null
}>()

const chartRef = ref<HTMLElement | null>(null)
let chart: echarts.ECharts | null = null

const { snapshot } = useAdminEventMap({
  trafficMap: toRef(props, 'trafficMap'),
})

const isOriginPending = () => !hasGeo(snapshot.value.originNode)

type GeoNode = EventMapNode & { lat: number; lng: number }
type FlowCountSnapshot = Map<string, number>
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
const PROJECTILES_PER_TICK_CAP = 8
const ACTIVE_TRAIL_OPACITY = 0.12

const activeProjectiles = ref<Projectile[]>([])
const previousFlowCounts = new Map<string, number>()
let cleanupTimer: number | null = null

const resizeChart = () => chart?.resize()

function hasGeo(node: EventMapNode): node is GeoNode {
  return typeof node.lat === 'number' && typeof node.lng === 'number'
}

function projectilePalette(flow: EventMapFlow) {
  if (flow.decision === 'block') {
    return {
      color: '#ff4d4f', // 鲜艳的红色
      trailColor: 'rgba(255, 77, 79, 0.15)',
      symbolSize: 4,
    }
  }
  if (flow.direction === 'egress') {
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

function nextFlowCounts(flows: EventMapFlow[]) {
  const counts: FlowCountSnapshot = new Map()
  flows.forEach((flow) => {
    counts.set(flow.id, flow.requestCount ?? 0)
  })
  return counts
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

function emitProjectiles(flows: EventMapFlow[], originNode: GeoNode, geoNodes: GeoNode[]) {
  const flowNodeMap = new Map(geoNodes.map((node) => [node.id, node]))
  const incoming = flows.flatMap((flow) => {
    const currentCount = flow.requestCount ?? 0
    const previousCount = previousFlowCounts.get(flow.id) ?? 0
    const delta = Math.max(0, currentCount - previousCount)
    const targetNode = flowNodeMap.get(flow.nodeId)
    if (!targetNode || delta === 0) return []

    const projectileCount = Math.min(delta, PROJECTILES_PER_TICK_CAP)
    const isIngress = flow.direction === 'ingress'
    const coords = isIngress
      ? [[targetNode.lng, targetNode.lat], [originNode.lng, originNode.lat]]
      : [[originNode.lng, originNode.lat], [targetNode.lng, targetNode.lat]]
    const palette = projectilePalette(flow)
    const createdAt = Date.now()

    return Array.from({ length: projectileCount }, (_, index) => ({
      id: `${flow.id}-${createdAt}-${index}`,
      coords,
      color: palette.color,
      trailColor: palette.trailColor,
      symbolSize: palette.symbolSize,
      curveness: 0.15 + Math.random() * 0.3, // 随机曲率
      createdAt,
      durationMs: PROJECTILE_DURATION_MS + index * 40 + Math.random() * 100, // 随机时长
    }))
  })

  previousFlowCounts.clear()
  nextFlowCounts(flows).forEach((value, key) => {
    previousFlowCounts.set(key, value)
  })

  if (incoming.length === 0) return

  activeProjectiles.value = [...activeProjectiles.value, ...incoming].slice(-PROJECTILE_CAP)
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
    if (hasGeo(value.originNode)) {
      emitProjectiles(value.flows, value.originNode, value.nodes.filter(hasGeo))
    } else {
      previousFlowCounts.clear()
      activeProjectiles.value = []
    }
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
