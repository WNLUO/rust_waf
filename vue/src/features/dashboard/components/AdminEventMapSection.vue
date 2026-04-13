<script setup lang="ts">
import { ref, onMounted, watch, onBeforeUnmount, toRef } from 'vue'
import * as echarts from 'echarts'
import type {
  EChartsOption,
  EffectScatterSeriesOption,
  LinesSeriesOption,
} from 'echarts'
import { useAdminEventMap } from '../composables/useAdminEventMap'
import type { EventMapNode, TrafficMapResponse } from '@/shared/types'

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
  }
}
const resizeChart = () => chart?.resize()

function hasGeo(node: EventMapNode): node is GeoNode {
  return typeof node.lat === 'number' && typeof node.lng === 'number'
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

  const { nodes, flows, originNode } = snapshot.value
  if (!hasGeo(originNode)) {
    chart.setOption({
      backgroundColor: 'transparent',
      tooltip: {
        show: false
      },
      geo: {
        map: 'china',
        roam: false,
        zoom: 1.75,
        center: [104.5, 36.5],
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
      series: []
    })
    return
  }

  const geoNodes = nodes.filter(hasGeo)

  // 转换节点为散点数据
  const scatterData = geoNodes.map(node => ({
    name: node.name,
    value: [node.lng, node.lat, node.trafficWeight],
    itemStyle: {
      color: node.id === snapshot.value.hottestNode?.id ? '#fbbf24' : '#60a5fa'
    }
  }))

  // 添加源站节点
  scatterData.push({
    name: originNode.name,
    value: [originNode.lng, originNode.lat, 2],
    itemStyle: {
      color: '#10b981'
    }
  })

  // 转换 flows 为线路动画数据
  const linesData = flows
    .map((flow): LocalLinesDataItem | null => {
    const targetNode = geoNodes.find(n => n.id === flow.nodeId)
    if (!targetNode) return null

    const isIngress = flow.direction === 'ingress'
    const coords = isIngress 
      ? [[targetNode.lng, targetNode.lat], [originNode.lng, originNode.lat]]
      : [[originNode.lng, originNode.lat], [targetNode.lng, targetNode.lat]]

    return {
      coords,
      lineStyle: {
        color: flow.decision === 'block' ? '#ef4444' : (isIngress ? '#3b82f6' : '#10b981'),
        width: 1,
        opacity: 0.6,
        curveness: 0.2
      },
      effect: {
        show: true,
        period: flow.durationMs / 1000,
        trailLength: 0.4,
        symbol: 'circle',
        symbolSize: flow.decision === 'block' ? 4 : 3,
        color: flow.decision === 'block' ? '#f87171' : (isIngress ? '#60a5fa' : '#34d399')
      }
    }
  })
    .filter((item): item is LocalLinesDataItem => item !== null)

  const linesSeries: LinesSeriesOption = {
    type: 'lines',
    coordinateSystem: 'geo',
    zlevel: 1,
    effect: {
      show: true,
      constantSpeed: 0,
      trailLength: 0.4,
      symbolSize: 3
    },
    lineStyle: {
      curveness: 0.2
    },
    data: linesData
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

// 监听数据变化更新图表
watch(() => snapshot.value, () => {
  renderChart()
}, { deep: true })

onMounted(() => {
  initMap()
  window.addEventListener('resize', resizeChart)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', resizeChart)
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
          <span>拦截请求</span>
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
