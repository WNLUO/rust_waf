<script setup lang="ts">
import {
  computed,
  ref,
  shallowRef,
  onMounted,
  watch,
  onBeforeUnmount,
  toRef,
} from 'vue'
import { LinesChart, ScatterChart } from 'echarts/charts'
import type { LinesSeriesOption, ScatterSeriesOption } from 'echarts/charts'
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

use([CanvasRenderer, GeoComponent, TooltipComponent, LinesChart, ScatterChart])

type MapMode = 'china' | 'global'

const props = defineProps<{
  trafficMap?: TrafficMapResponse | null
  trafficEvents?: TrafficEventDelta[]
  mapMode?: MapMode
}>()

const emit = defineEmits<{
  'update:mapMode': [value: MapMode]
}>()

const chartRef = ref<HTMLElement | null>(null)
let chart: ECharts | null = null
const currentMapMode = computed<MapMode>({
  get: () => props.mapMode ?? 'china',
  set: (value) => emit('update:mapMode', value),
})

const { snapshot } = useAdminEventMap({
  trafficMap: toRef(props, 'trafficMap'),
})

const isOriginPending = () => !hasGeo(snapshot.value.originNode)

type GeoNode = EventMapNode & { lat: number; lng: number }

type RealtimeNodeRecord = {
  node: GeoNode
  decision: TrafficEventDelta['decision']
  direction: TrafficEventDelta['direction']
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
let mapsReady = false
let resizeObserver: ResizeObserver | null = null
let resizeFrame: number | null = null
let isTransitioning = false
let transitionTimeout: number | null = null

const MAP_CONTEXT = 'waf-world-context-pacific'
const PACIFIC_SHIFT_THRESHOLD_LNG = -25
const CHINA_REGION_NAMES = [
  '北京市',
  '天津市',
  '河北省',
  '山西省',
  '内蒙古自治区',
  '辽宁省',
  '吉林省',
  '黑龙江省',
  '上海市',
  '江苏省',
  '浙江省',
  '安徽省',
  '福建省',
  '江西省',
  '山东省',
  '河南省',
  '湖北省',
  '湖南省',
  '广东省',
  '广西壮族自治区',
  '海南省',
  '重庆市',
  '四川省',
  '贵州省',
  '云南省',
  '西藏自治区',
  '陕西省',
  '甘肃省',
  '青海省',
  '宁夏回族自治区',
  '新疆维吾尔自治区',
  '台湾省',
  '香港特别行政区',
  '澳门特别行政区',
]

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

const resizeChart = () => {
  if (isTransitioning) return
  if (resizeFrame !== null) {
    window.cancelAnimationFrame(resizeFrame)
  }
  resizeFrame = window.requestAnimationFrame(() => {
    resizeFrame = null
    chart?.resize()
  })
}

const getTargetWidth = (mode: MapMode) => {
  if (!chartRef.value) return undefined
  const section = chartRef.value.closest('section')
  if (!section) return undefined
  
  const totalWidth = section.clientWidth
  const paddingAndBorder = 34
  
  if (window.innerWidth < 1280) {
    return totalWidth - paddingAndBorder
  }
  
  if (mode === 'china') {
    const colWidth = Math.max(300, (totalWidth - 12) * (0.85 / 2.55))
    return colWidth - paddingAndBorder
  } else {
    let rightW = (totalWidth - 12) * (0.95 / 2.50)
    if (rightW < 360) rightW = 360
    const colWidth = totalWidth - 12 - rightW
    return colWidth - paddingAndBorder
  }
}

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
        decision: event.decision,
        direction: event.direction,
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
          trailLength: event.decision === 'block' ? 0.34 : 0.22,
          symbol: 'path://M5 0 L10 5 L5 10 L0 5 Z',
          symbolSize: palette.symbolSize,
          color: palette.color,
          shadowBlur: event.decision === 'block' ? 12 : 8,
          shadowColor: palette.color,
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

function isChinaWorldFeature(feature: {
  properties?: Record<string, unknown>
}) {
  const name = String(feature.properties?.name || '').toLowerCase()
  return (
    name === 'china' ||
    name === "people's republic of china" ||
    name === 'republic of china'
  )
}

function buildContextMap(
  worldGeoJson: {
    type: 'FeatureCollection'
    features: Array<{
      geometry?: { coordinates?: unknown }
      properties?: Record<string, unknown>
    }>
  },
  chinaGeoJson: {
    features: Array<{
      geometry?: { coordinates?: unknown }
      properties?: Record<string, unknown>
    }>
  },
) {
  return {
    ...worldGeoJson,
    type: 'FeatureCollection' as const,
    features: [
      ...worldGeoJson.features.filter(
        (feature) => !isChinaWorldFeature(feature),
      ),
      ...chinaGeoJson.features,
    ],
  }
}

function shiftLongitude(lng: number) {
  return lng < PACIFIC_SHIFT_THRESHOLD_LNG ? lng + 360 : lng
}

function mapPoint(lng: number, lat: number) {
  return [shiftLongitude(lng), lat]
}

function collectLongitudes(value: unknown, result: number[] = []) {
  if (!Array.isArray(value)) return result
  if (
    value.length >= 2 &&
    typeof value[0] === 'number' &&
    typeof value[1] === 'number'
  ) {
    result.push(value[0])
    return result
  }
  value.forEach((item) => collectLongitudes(item, result))
  return result
}

function shouldShiftFeature(coordinates: unknown) {
  const longitudes = collectLongitudes(coordinates)
  if (longitudes.length === 0) return false
  return Math.max(...longitudes) < PACIFIC_SHIFT_THRESHOLD_LNG
}

function shiftGeoJsonLongitudes<T>(value: T): T {
  if (typeof value === 'number') {
    return shiftLongitude(value) as T
  }
  if (!Array.isArray(value)) {
    return value
  }
  if (
    value.length >= 2 &&
    typeof value[0] === 'number' &&
    typeof value[1] === 'number'
  ) {
    return [shiftLongitude(value[0]), value[1], ...value.slice(2)] as T
  }
  return value.map((item) => shiftGeoJsonLongitudes(item)) as T
}

function buildPacificMap(geoJson: ReturnType<typeof buildContextMap>) {
  return {
    ...geoJson,
    features: geoJson.features.map((feature) => ({
      ...feature,
      geometry:
        feature.geometry && shouldShiftFeature(feature.geometry.coordinates)
          ? {
              ...feature.geometry,
              coordinates: shiftGeoJsonLongitudes(feature.geometry.coordinates),
            }
          : feature.geometry,
    })),
  }
}

function geoConfigForMode(mode: MapMode) {
  const chinaMode = mode === 'china'
  return {
    map: MAP_CONTEXT,
    roam: false,
    zoom: chinaMode ? 8 : 1.72,
    center: chinaMode ? [106.3, 36.1] : [158, 12],
    scaleLimit: { min: 0.8, max: 8.5 },
    emphasis: { disabled: true },
    label: { show: false },
    itemStyle: {
      areaColor: chinaMode ? '#111827' : '#172033',
      borderColor: chinaMode ? 'rgba(100, 116, 139, 0.36)' : '#334155',
      borderWidth: chinaMode ? 0.6 : 0.8,
    },
    regions: [
      ...CHINA_REGION_NAMES.map((name) => ({
        name,
        itemStyle: {
          areaColor: chinaMode ? '#1f3b57' : '#1d3a4f',
          borderColor: chinaMode ? '#38bdf8' : 'rgba(56, 189, 248, 0.45)',
          borderWidth: chinaMode ? 0.9 : 0.45,
        },
      })),
      { name: '南海诸岛', itemStyle: { opacity: 0 }, label: { show: false } },
    ],
    animation: false,
  }
}

function setMapMode(mode: MapMode) {
  if (currentMapMode.value === mode) return
  currentMapMode.value = mode
}

// 加载地图并初始化
const initMap = async () => {
  if (!chartRef.value) return

  try {
    const [worldResponse, chinaResponse] = await Promise.all([
      fetch('/maps/world.geojson'),
      fetch('/maps/china-full.geojson'),
    ])
    const [worldGeoJson, chinaGeoJson] = await Promise.all([
      worldResponse.json(),
      chinaResponse.json(),
    ])

    const contextMap = buildContextMap(worldGeoJson, chinaGeoJson)

    registerMap(
      MAP_CONTEXT,
      buildPacificMap(contextMap) as unknown as Parameters<
        typeof registerMap
      >[1],
    )
    mapsReady = true

    chart = init(chartRef.value)

    chart.setOption({
      backgroundColor: 'transparent',
      tooltip: { show: false },
      geo: geoConfigForMode(currentMapMode.value),
      animation: false,
      series: [],
    })

    resizeObserver = new ResizeObserver(() => {
      resizeChart()
    })
    resizeObserver.observe(chartRef.value)

    renderChart()
  } catch (error) {
    console.error('Failed to load map data:', error)
  }
}

const renderChart = () => {
  if (!chart || !mapsReady) return

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
    value: [...mapPoint(node.lng, node.lat), node.trafficWeight],
    itemStyle: {
      color: activeRealtimeNodes.has(node.id)
        ? activeRealtimeNodes.get(node.id)?.decision === 'block'
          ? '#ff4d4f'
          : '#70ff00'
        : node.id === snapshot.value.hottestNode?.id
          ? '#fbbf24'
          : node.geoScope === 'global'
            ? '#a78bfa'
            : '#60a5fa',
    },
  }))

  const burstData = Array.from(activeRealtimeNodes.values()).map((record) => ({
    name: record.node.name,
    value: [...mapPoint(record.node.lng, record.node.lat), 2.2],
    itemStyle: {
      color:
        record.decision === 'block'
          ? '#ff4d4f'
          : record.direction === 'egress'
            ? '#00f2fe'
            : '#70ff00',
    },
  }))

  scatterData.push({
    name: originNode.name,
    value: [...mapPoint(originNode.lng, originNode.lat), 1.8],
    itemStyle: {
      color: '#10b981',
    },
  })

  const linesSeries: LinesSeriesOption = {
    id: 'traffic-projectiles',
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
    data: activeLinesData.value.map((line) => ({
      ...line,
      coords: line.coords.map(([lng, lat]) => mapPoint(lng, lat)),
    })),
  }

  const scatterSeries: ScatterSeriesOption = {
    id: 'traffic-nodes',
    type: 'scatter',
    coordinateSystem: 'geo',
    zlevel: 2,
    label: {
      show: false,
    },
    symbolSize: (val: unknown) => {
      const point = Array.isArray(val) ? val : []
      const weight = typeof point[2] === 'number' ? point[2] : 0
      const base = currentMapMode.value === 'china' ? 2.2 : 2
      return Math.min(
        base + weight * 1.35,
        currentMapMode.value === 'china' ? 6 : 5,
      )
    },
    data: scatterData,
    animation: false,
  }

  const burstSeries: ScatterSeriesOption = {
    id: 'request-source-bursts',
    type: 'scatter',
    coordinateSystem: 'geo',
    zlevel: 4,
    label: { show: false },
    symbolSize: (val: unknown) => {
      const point = Array.isArray(val) ? val : []
      const weight = typeof point[2] === 'number' ? point[2] : 1
      return Math.min(4 + weight * 1.6, 7)
    },
    data: burstData,
    animation: false,
  }

  chart.setOption({
    animation: false,
    backgroundColor: 'transparent',
    tooltip: { show: false },
    geo: geoConfigForMode(currentMapMode.value),
    series: [linesSeries, scatterSeries, burstSeries],
  }, { replaceMerge: ['series'] })
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

watch(currentMapMode, (mode) => {
  activeLinesData.value = []
  
  if (chart && chartRef.value) {
    const targetW = getTargetWidth(mode)
    if (targetW) {
      isTransitioning = true
      chartRef.value.style.width = `${targetW}px`
      chart.resize({ width: targetW })
      
      if (transitionTimeout !== null) {
        window.clearTimeout(transitionTimeout)
      }
      transitionTimeout = window.setTimeout(() => {
        isTransitioning = false
        if (chartRef.value) {
          chartRef.value.style.width = '100%'
          chart.resize()
        }
      }, 550)
    }
  }

  scheduleRender()
})

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
  if (resizeFrame !== null) {
    window.cancelAnimationFrame(resizeFrame)
    resizeFrame = null
  }
  resizeObserver?.disconnect()
  resizeObserver = null
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
      <div
        class="flex items-center overflow-hidden rounded-md border border-slate-700 bg-slate-950/40 p-0.5 text-[11px] text-slate-400"
      >
        <button
          type="button"
          class="h-7 px-2.5 transition-colors"
          :class="
            currentMapMode === 'china'
              ? 'bg-sky-500/20 text-sky-200'
              : 'hover:text-slate-200'
          "
          @click="setMapMode('china')"
        >
          全国
        </button>
        <button
          type="button"
          class="h-7 px-2.5 transition-colors"
          :class="
            currentMapMode === 'global'
              ? 'bg-sky-500/20 text-sky-200'
              : 'hover:text-slate-200'
          "
          @click="setMapMode('global')"
        >
          全球
        </button>
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

      <!-- 流向图例 -->
      <div
        class="absolute bottom-3 right-3 flex flex-col gap-1.5 rounded-lg border border-slate-700 bg-slate-900/60 p-2.5 text-[10px] text-slate-400 backdrop-blur-md"
      >
        <div class="flex items-center gap-1.5">
          <span class="h-[2px] w-4 bg-blue-500"></span>
          <span>CDN 请求</span>
        </div>
        <div class="flex items-center gap-1.5">
          <span class="h-[2px] w-4 bg-emerald-500"></span>
          <span>源站响应</span>
        </div>
        <div class="flex items-center gap-1.5">
          <span class="h-[2px] w-4 bg-red-500"></span>
          <span>拦截异常</span>
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
