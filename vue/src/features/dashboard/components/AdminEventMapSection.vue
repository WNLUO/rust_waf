<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, toRef, watch } from 'vue'
import * as echarts from 'echarts'
import 'echarts-gl'
import type { ECharts } from 'echarts'
import CyberCard from '@/shared/ui/CyberCard.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useAdminEventMap } from '@/features/dashboard/composables/useAdminEventMap'
import type {
  EventMapFlow,
  EventMapNode,
  EventMapScope,
  MetricsResponse,
  SecurityEventItem,
} from '@/shared/types'
import {
  ArrowRightLeft,
  Globe2,
  Map,
  ServerCog,
  ShieldAlert,
  Waypoints,
} from 'lucide-vue-next'

const CHINA_MAP_NAME = 'admin-event-map-china-full'

const props = defineProps<{
  metrics: MetricsResponse | null | undefined
  events: SecurityEventItem[]
}>()

const chartRef = ref<HTMLDivElement | null>(null)
const chartInstance = ref<ECharts | null>(null)
const resizeObserver = ref<ResizeObserver | null>(null)
const chinaMapReady = ref(false)

const { formatNumber } = useFormatters()

const { scope, snapshot } = useAdminEventMap({
  metrics: toRef(props, 'metrics'),
  events: toRef(props, 'events'),
})

const recentFlows = computed(() =>
  [...snapshot.value.flows]
    .filter((flow) => flow.direction === 'ingress')
    .sort((left, right) => right.bandwidthMbps - left.bandwidthMbps)
    .slice(0, 4),
)

const stressLevel = computed(() => {
  const score = snapshot.value.liveTrafficScore
  if (score > 0.9) return '高压'
  if (score > 0.58) return '活跃'
  return '平稳'
})

const stressBadgeType = computed(() => {
  const score = snapshot.value.liveTrafficScore
  if (score > 0.9) return 'error'
  if (score > 0.58) return 'warning'
  return 'success'
})

const scopeLabel = (value: EventMapScope) =>
  value === 'china' ? '全国回源' : '全球回源'

const hottestNodeLabel = computed(
  () => snapshot.value.hottestNode?.name || '暂无热点',
)

const coordOf = (node: EventMapNode) => [node.lng ?? 0, node.lat ?? 0]

const buildLineColor = (flow: EventMapFlow) => {
  if (flow.decision === 'block') return '#fb7185'
  if (flow.direction === 'egress') return '#60a5fa'
  return '#67e8f9'
}

const buildChinaOption = () => {
  const origin = snapshot.value.originNode
  const nodes = snapshot.value.nodes.filter(
    (node) => typeof node.lng === 'number' && typeof node.lat === 'number',
  )
  const ingressFlows = snapshot.value.flows.filter(
    (flow) => flow.direction === 'ingress',
  )
  const egressFlows = snapshot.value.flows.filter(
    (flow) => flow.direction === 'egress',
  )

  const lineSeries = [
    {
      name: 'ingress',
      type: 'lines',
      coordinateSystem: 'geo',
      zlevel: 3,
      blendMode: 'lighter',
      effect: {
        show: true,
        period: Math.max(1.6, 3.6 - snapshot.value.liveTrafficScore * 1.7),
        trailLength: 0.12,
        symbol: 'circle',
        symbolSize: 4,
      },
      lineStyle: {
        width: 0,
        opacity: 0,
        curveness: 0.22,
      },
      data: ingressFlows.map((flow) => {
        const node = nodes.find((item) => item.id === flow.nodeId)
        return {
          coords: node ? [coordOf(node), coordOf(origin)] : [],
          lineStyle: {
            color: buildLineColor(flow),
            width: 0,
            opacity: 0,
          },
          effect: {
            color: buildLineColor(flow),
            symbolSize: flow.decision === 'block' ? 7 : 5,
          },
        }
      }),
    },
    {
      name: 'egress',
      type: 'lines',
      coordinateSystem: 'geo',
      zlevel: 4,
      blendMode: 'lighter',
      effect: {
        show: true,
        period: Math.max(1.2, 3 - snapshot.value.liveTrafficScore * 1.2),
        trailLength: 0.1,
        symbol: 'arrow',
        symbolSize: 6,
      },
      lineStyle: {
        width: 0,
        opacity: 0,
        curveness: 0.17,
      },
      data: egressFlows.map((flow) => {
        const node = nodes.find((item) => item.id === flow.nodeId)
        return {
          coords: node ? [coordOf(origin), coordOf(node)] : [],
          lineStyle: {
            color: buildLineColor(flow),
            width: 0,
            opacity: 0,
          },
          effect: {
            color: buildLineColor(flow),
            symbolSize: 6,
          },
        }
      }),
    },
  ]

  return {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item',
      backgroundColor: 'rgba(5, 14, 28, 0.94)',
      borderColor: 'rgba(103, 232, 249, 0.28)',
      textStyle: {
        color: '#e2e8f0',
      },
      formatter: (params: any) => params?.data?.label ?? '',
    },
    geo: {
      map: CHINA_MAP_NAME,
      roam: false,
      zoom: 1.05,
      top: 28,
      bottom: 18,
      itemStyle: {
        areaColor: '#10233f',
        borderColor: '#4cc9f0',
        borderWidth: 1,
        shadowColor: 'rgba(14, 165, 233, 0.35)',
        shadowBlur: 18,
      },
      emphasis: {
        disabled: true,
      },
      silent: true,
    },
    series: [
      {
        name: 'cdn-nodes',
        type: 'effectScatter',
        coordinateSystem: 'geo',
        zlevel: 5,
        itemStyle: {
          color: '#67e8f9',
          shadowBlur: 10,
          shadowColor: 'rgba(103, 232, 249, 0.35)',
        },
        label: {
          show: false,
          position: 'top',
          distance: 8,
          color: '#dbeafe',
          fontSize: 11,
          formatter: '{b}',
        },
        symbolSize: (value: number[]) => value[2],
        data: nodes.map((node) => {
          const ingress = ingressFlows.filter((flow) => flow.nodeId === node.id)
          const weight = ingress.reduce(
            (sum, flow) => sum + flow.bandwidthMbps,
            0,
          )
          return {
            name: node.name,
            value: [node.lng, node.lat, 4 + Math.min(weight / 320, 4)],
            label: `${node.name} ${node.region}`,
          }
        }),
      },
      {
        name: 'origin',
        type: 'scatter',
        coordinateSystem: 'geo',
        zlevel: 6,
        itemStyle: {
          color: '#fbbf24',
          borderColor: '#fff7ed',
          borderWidth: 1.2,
          shadowBlur: 10,
          shadowColor: 'rgba(251, 191, 36, 0.28)',
        },
        label: {
          show: false,
          position: 'bottom',
          distance: 8,
          color: '#fef3c7',
          fontSize: 12,
          fontWeight: 700,
          formatter: '{b}',
        },
        symbolSize: 6 + snapshot.value.liveTrafficScore * 2,
        data: [
          {
            name: origin.name,
            value: [origin.lng, origin.lat, 1],
            label: `${origin.name} ${origin.region}`,
          },
        ],
      },
      ...lineSeries,
    ],
  }
}

const buildGlobalOption = () => {
  const origin = snapshot.value.originNode
  const nodes = snapshot.value.nodes.filter(
    (node) => typeof node.lng === 'number' && typeof node.lat === 'number',
  )

  return {
    backgroundColor: 'transparent',
    globe: {
      baseTexture: '/textures/earth-day.jpg',
      environment: 'auto',
      shading: 'lambert',
      displacementScale: 0.01,
      globeOuterRadius: 100,
      atmosphere: {
        show: true,
        color: '#3b82f6',
        glowPower: 3.6,
      },
      light: {
        ambient: {
          intensity: 0.35,
        },
        main: {
          intensity: 0.95,
          shadow: false,
        },
      },
      viewControl: {
        autoRotate: true,
        autoRotateSpeed: 6,
        distance: 155,
        alpha: 26,
        beta: 158,
      },
    },
    series: [
      {
        name: 'cdn-nodes',
        type: 'scatter3D',
        coordinateSystem: 'globe',
        blendMode: 'lighter',
        symbolSize: 9,
        itemStyle: {
          color: '#67e8f9',
          opacity: 0.95,
        },
        label: {
          show: true,
          formatter: '{b}',
          position: 'top',
          textStyle: {
            color: '#dbeafe',
            fontSize: 11,
          },
        },
        data: nodes.map((node) => ({
          name: node.name,
          value: [node.lng, node.lat, 2 + node.trafficWeight * 2.5],
        })),
      },
      {
        name: 'origin',
        type: 'scatter3D',
        coordinateSystem: 'globe',
        blendMode: 'lighter',
        symbolSize: 15 + snapshot.value.liveTrafficScore * 5,
        itemStyle: {
          color: '#fbbf24',
          opacity: 1,
          borderColor: '#fef3c7',
          borderWidth: 1,
        },
        label: {
          show: true,
          formatter: '{b}',
          position: 'top',
          textStyle: {
            color: '#fef3c7',
            fontSize: 12,
            fontWeight: 'bold',
          },
        },
        data: [
          {
            name: origin.name,
            value: [origin.lng, origin.lat, 6],
          },
        ],
      },
      {
        name: 'ingress',
        type: 'lines3D',
        coordinateSystem: 'globe',
        blendMode: 'lighter',
        effect: {
          show: true,
          trailWidth: 3,
          trailLength: 0.26,
          trailOpacity: 0.9,
          trailColor: '#67e8f9',
        },
        lineStyle: {
          width: 2,
          color: '#67e8f9',
          opacity: 0.36,
        },
        data: snapshot.value.flows
          .filter((flow) => flow.direction === 'ingress')
          .map((flow) => {
            const node = nodes.find((item) => item.id === flow.nodeId)
            return {
              coords: node ? [coordOf(node), coordOf(origin)] : [],
              lineStyle: {
                color: buildLineColor(flow),
                width: 1.2 + flow.intensity * 2,
                opacity: flow.decision === 'block' ? 0.95 : 0.56,
              },
              effect: {
                show: true,
                trailColor: buildLineColor(flow),
                trailWidth: flow.decision === 'block' ? 4.5 : 3,
                trailLength: flow.decision === 'block' ? 0.4 : 0.24,
              },
            }
          }),
      },
      {
        name: 'egress',
        type: 'lines3D',
        coordinateSystem: 'globe',
        blendMode: 'lighter',
        effect: {
          show: true,
          trailWidth: 2.4,
          trailLength: 0.2,
          trailOpacity: 0.82,
          trailColor: '#60a5fa',
        },
        lineStyle: {
          width: 1.6,
          color: '#60a5fa',
          opacity: 0.28,
        },
        data: snapshot.value.flows
          .filter((flow) => flow.direction === 'egress')
          .map((flow) => {
            const node = nodes.find((item) => item.id === flow.nodeId)
            return {
              coords: node ? [coordOf(origin), coordOf(node)] : [],
              lineStyle: {
                color: buildLineColor(flow),
                width: 1 + flow.intensity * 1.5,
                opacity: 0.36,
              },
              effect: {
                show: true,
                trailColor: buildLineColor(flow),
              },
            }
          }),
      },
    ],
  }
}

const ensureChinaMap = async () => {
  if (chinaMapReady.value) return
  const response = await fetch('/maps/china-full.geojson')
  const geoJson = await response.json()
  echarts.registerMap(CHINA_MAP_NAME, geoJson)
  chinaMapReady.value = true
}

const renderChart = async () => {
  if (!chartRef.value) return
  if (!chartInstance.value) {
    chartInstance.value = echarts.init(chartRef.value, undefined, {
      renderer: 'canvas',
    })
  }
  if (scope.value === 'china') {
    await ensureChinaMap()
  }
  chartInstance.value.setOption(
    (scope.value === 'china' ? buildChinaOption() : buildGlobalOption()) as any,
    true,
  )
}

onMounted(async () => {
  await renderChart()
  if (chartRef.value) {
    resizeObserver.value = new ResizeObserver(() => {
      chartInstance.value?.resize()
    })
    resizeObserver.value.observe(chartRef.value)
  }
})

watch(
  [scope, snapshot],
  async () => {
    await renderChart()
  },
  { deep: true },
)

onBeforeUnmount(() => {
  resizeObserver.value?.disconnect()
  chartInstance.value?.dispose()
  chartInstance.value = null
})
</script>

<template>
  <CyberCard
    title="事件地图"
    sub-title="已切换为真实中国 GeoJSON 与 3D 地球纹理资产渲染"
    no-padding
  >
    <template #header-action>
      <div class="flex items-center gap-2">
        <button
          class="event-map__toggle"
          :class="{ 'event-map__toggle--active': scope === 'china' }"
          @click="scope = 'china'"
        >
          <Map :size="14" />
          全国
        </button>
        <button
          class="event-map__toggle"
          :class="{ 'event-map__toggle--active': scope === 'global' }"
          @click="scope = 'global'"
        >
          <Globe2 :size="14" />
          全球
        </button>
      </div>
    </template>

    <div class="event-map">
      <div class="event-map__hero">
        <div class="event-map__scene">
          <div ref="chartRef" class="event-map__chart"></div>
        </div>

        <div class="event-map__metrics">
          <div class="event-map__summary">
            <div>
              <p class="event-map__eyebrow">{{ scopeLabel(snapshot.scope) }}</p>
              <h4 class="event-map__title">回源链路脉冲</h4>
            </div>
            <StatusBadge :text="stressLevel" :type="stressBadgeType" />
          </div>

          <div class="event-map__metrics-grid">
            <div class="event-map__metric-card">
              <Waypoints :size="16" />
              <div>
                <p class="event-map__metric-label">活跃节点</p>
                <p class="event-map__metric-value">
                  {{ formatNumber(snapshot.activeNodeCount) }}
                </p>
              </div>
            </div>
            <div class="event-map__metric-card">
              <ShieldAlert :size="16" />
              <div>
                <p class="event-map__metric-label">拦截波次</p>
                <p class="event-map__metric-value">
                  {{ formatNumber(snapshot.blockedFlowCount) }}
                </p>
              </div>
            </div>
            <div class="event-map__metric-card">
              <ArrowRightLeft :size="16" />
              <div>
                <p class="event-map__metric-label">回包链路</p>
                <p class="event-map__metric-value">
                  {{ formatNumber(snapshot.allowedFlowCount) }}
                </p>
              </div>
            </div>
            <div class="event-map__metric-card">
              <ServerCog :size="16" />
              <div>
                <p class="event-map__metric-label">峰值带宽</p>
                <p class="event-map__metric-value">
                  {{ formatNumber(snapshot.peakBandwidthMbps) }} Mbps
                </p>
              </div>
            </div>
          </div>

          <div class="event-map__hotspot">
            <p class="event-map__hotspot-label">当前最热节点</p>
            <p class="event-map__hotspot-name">{{ hottestNodeLabel }}</p>
            <p class="event-map__hotspot-meta">
              全国视图使用完整中国 GeoJSON，全球视图使用下载的真实地球纹理。
            </p>
          </div>

          <div class="event-map__legend">
            <span><i class="event-map__legend-dot event-map__legend-dot--ingress"></i>CDN 向源站回源</span>
            <span><i class="event-map__legend-dot event-map__legend-dot--egress"></i>Rust 响应回送</span>
            <span><i class="event-map__legend-dot event-map__legend-dot--blocked"></i>命中拦截，无响应回送</span>
          </div>
        </div>
      </div>

      <div class="event-map__feed">
        <div class="event-map__feed-title">
          <p>实时波次</p>
          <span>当前为前端模拟流，后续可直接切到 Rust 实时事件流</span>
        </div>
        <div class="event-map__feed-list">
          <div
            v-for="flow in recentFlows"
            :key="flow.id"
            class="event-map__feed-item"
          >
            <div class="event-map__feed-main">
              <div class="event-map__feed-node">
                <span class="event-map__feed-pill">
                  {{ snapshot.nodes.find((node) => node.id === flow.nodeId)?.name }}
                </span>
                <span class="event-map__feed-arrow">→</span>
                <span class="event-map__feed-pill event-map__feed-pill--origin">
                  {{ snapshot.originNode.name }}
                </span>
              </div>
              <p class="event-map__feed-reason">{{ flow.reason }}</p>
            </div>
            <div class="event-map__feed-side">
              <StatusBadge
                :text="flow.decision === 'allow' ? '已回源' : '已拦截'"
                :type="flow.decision === 'allow' ? 'success' : 'error'"
              />
              <p>{{ formatNumber(flow.requestsPerSecond) }} req/s</p>
              <p>{{ formatNumber(flow.bandwidthMbps) }} Mbps</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </CyberCard>
</template>

<style scoped>
.event-map {
  background:
    radial-gradient(circle at 15% 18%, rgba(56, 189, 248, 0.16), transparent 30%),
    radial-gradient(circle at 83% 12%, rgba(59, 130, 246, 0.16), transparent 25%),
    linear-gradient(180deg, rgba(5, 13, 25, 1), rgba(4, 10, 20, 1));
  color: #dbeafe;
}

.event-map__hero {
  display: grid;
  gap: 1.25rem;
  padding: 1.25rem;
}

.event-map__scene {
  min-height: 29rem;
  overflow: hidden;
  border: 1px solid rgba(148, 163, 184, 0.16);
  border-radius: 1.5rem;
  background:
    radial-gradient(circle at 50% 100%, rgba(59, 130, 246, 0.14), transparent 40%),
    linear-gradient(135deg, rgba(7, 18, 36, 0.95), rgba(3, 10, 22, 0.98));
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
}

.event-map__chart {
  width: 100%;
  min-height: 29rem;
}

.event-map__metrics {
  display: grid;
  gap: 1rem;
}

.event-map__summary,
.event-map__metric-card,
.event-map__hotspot {
  border: 1px solid rgba(148, 163, 184, 0.14);
  background: rgba(8, 20, 38, 0.76);
}

.event-map__summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  border-radius: 1.2rem;
  padding: 1rem 1.1rem;
}

.event-map__eyebrow {
  color: rgba(125, 211, 252, 0.78);
  font-size: 0.75rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.event-map__title {
  margin-top: 0.18rem;
  color: #f8fafc;
  font-size: 1.12rem;
  font-weight: 700;
}

.event-map__metrics-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.85rem;
}

.event-map__metric-card {
  display: flex;
  gap: 0.75rem;
  align-items: flex-start;
  border-radius: 1rem;
  padding: 0.95rem 1rem;
  color: #bfdbfe;
}

.event-map__metric-label {
  color: rgba(191, 219, 254, 0.74);
  font-size: 0.76rem;
}

.event-map__metric-value {
  margin-top: 0.15rem;
  color: #f8fafc;
  font-size: 1.02rem;
  font-weight: 600;
}

.event-map__hotspot {
  border-radius: 1.15rem;
  padding: 1rem 1.1rem;
}

.event-map__hotspot-label {
  color: rgba(253, 230, 138, 0.8);
  font-size: 0.78rem;
}

.event-map__hotspot-name {
  margin-top: 0.3rem;
  color: #fef3c7;
  font-size: 1.18rem;
  font-weight: 700;
}

.event-map__hotspot-meta {
  margin-top: 0.35rem;
  color: rgba(226, 232, 240, 0.72);
  font-size: 0.82rem;
  line-height: 1.45;
}

.event-map__legend {
  display: flex;
  flex-wrap: wrap;
  gap: 0.85rem;
  color: rgba(191, 219, 254, 0.76);
  font-size: 0.8rem;
}

.event-map__legend span {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
}

.event-map__legend-dot {
  width: 0.68rem;
  height: 0.68rem;
  border-radius: 999px;
  box-shadow: 0 0 10px currentColor;
}

.event-map__legend-dot--ingress {
  background: #67e8f9;
  color: #67e8f9;
}

.event-map__legend-dot--egress {
  background: #60a5fa;
  color: #60a5fa;
}

.event-map__legend-dot--blocked {
  background: #fb7185;
  color: #fb7185;
}

.event-map__feed {
  border-top: 1px solid rgba(148, 163, 184, 0.14);
  background: rgba(5, 14, 28, 0.84);
  padding: 1rem 1.25rem 1.25rem;
}

.event-map__feed-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 0.9rem;
}

.event-map__feed-title p {
  color: #e2e8f0;
  font-size: 0.95rem;
  font-weight: 600;
}

.event-map__feed-title span {
  color: rgba(148, 163, 184, 0.84);
  font-size: 0.76rem;
}

.event-map__feed-list {
  display: grid;
  gap: 0.8rem;
}

.event-map__feed-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  border: 1px solid rgba(148, 163, 184, 0.14);
  border-radius: 1rem;
  background: rgba(9, 18, 34, 0.78);
  padding: 0.85rem 0.95rem;
}

.event-map__feed-main {
  min-width: 0;
}

.event-map__feed-node {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  flex-wrap: wrap;
}

.event-map__feed-pill {
  border-radius: 999px;
  background: rgba(8, 47, 73, 0.9);
  padding: 0.24rem 0.6rem;
  color: #a5f3fc;
  font-size: 0.78rem;
}

.event-map__feed-pill--origin {
  background: rgba(120, 53, 15, 0.78);
  color: #fde68a;
}

.event-map__feed-arrow {
  color: rgba(148, 163, 184, 0.66);
}

.event-map__feed-reason {
  margin-top: 0.35rem;
  color: rgba(226, 232, 240, 0.84);
  font-size: 0.82rem;
  line-height: 1.4;
}

.event-map__feed-side {
  display: grid;
  justify-items: end;
  gap: 0.2rem;
  color: rgba(191, 219, 254, 0.82);
  font-size: 0.78rem;
}

.event-map__toggle {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  border: 1px solid rgba(148, 163, 184, 0.25);
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.72);
  padding: 0.38rem 0.8rem;
  color: #0f172a;
  font-size: 0.76rem;
  transition:
    transform 180ms ease,
    border-color 180ms ease,
    background 180ms ease,
    color 180ms ease;
}

.event-map__toggle:hover {
  transform: translateY(-1px);
  border-color: rgba(37, 99, 235, 0.35);
}

.event-map__toggle--active {
  border-color: rgba(29, 78, 216, 0.4);
  background: rgba(219, 234, 254, 0.96);
  color: #1d4ed8;
}

@media (min-width: 1180px) {
  .event-map__hero {
    grid-template-columns: minmax(0, 1.35fr) minmax(320px, 0.65fr);
    align-items: stretch;
  }
}

@media (max-width: 920px) {
  .event-map__metrics-grid {
    grid-template-columns: 1fr;
  }

  .event-map__feed-item {
    align-items: flex-start;
    flex-direction: column;
  }

  .event-map__feed-side {
    justify-items: start;
  }
}

@media (max-width: 640px) {
  .event-map__hero {
    padding: 0.95rem;
  }

  .event-map__feed {
    padding: 0.95rem;
  }

  .event-map__feed-title {
    align-items: flex-start;
    flex-direction: column;
  }

  .event-map__scene,
  .event-map__chart {
    min-height: 23rem;
  }
}
</style>
