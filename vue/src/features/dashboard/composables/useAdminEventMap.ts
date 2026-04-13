import { computed, onBeforeUnmount, ref, watch, type Ref } from 'vue'
import type {
  EventMapFlow,
  EventMapNode,
  EventMapScope,
  EventMapSnapshot,
  MetricsResponse,
  SecurityEventItem,
} from '@/shared/types'

interface UseAdminEventMapOptions {
  metrics: Ref<MetricsResponse | null | undefined>
  events: Ref<SecurityEventItem[] | undefined>
}

const originNodeByScope: Record<EventMapScope, EventMapNode> = {
  china: {
    id: 'origin-cn',
    name: '本服务器',
    region: '华东源站',
    role: 'origin',
    x: 62,
    y: 52,
    lat: 31.23,
    lng: 121.47,
    trafficWeight: 1,
  },
  global: {
    id: 'origin-global',
    name: '本服务器',
    region: 'Shanghai Origin',
    role: 'origin',
    x: 56,
    y: 50,
    lat: 31.23,
    lng: 121.47,
    trafficWeight: 1,
  },
}

const chinaNodes: EventMapNode[] = [
  { id: 'cn-bj', name: '北京', region: '华北 CDN', role: 'cdn', x: 69, y: 24, lat: 39.90, lng: 116.40, trafficWeight: 0.88 },
  { id: 'cn-sh', name: '上海', region: '华东 CDN', role: 'cdn', x: 74, y: 44, lat: 31.23, lng: 121.47, trafficWeight: 1 },
  { id: 'cn-gz', name: '广州', region: '华南 CDN', role: 'cdn', x: 63, y: 70, lat: 23.13, lng: 113.26, trafficWeight: 0.82 },
  { id: 'cn-sz', name: '深圳', region: '华南边缘', role: 'cdn', x: 66, y: 75, lat: 22.54, lng: 114.06, trafficWeight: 0.78 },
  { id: 'cn-cd', name: '成都', region: '西南 CDN', role: 'cdn', x: 39, y: 56, lat: 30.57, lng: 104.06, trafficWeight: 0.72 },
  { id: 'cn-wh', name: '武汉', region: '华中 CDN', role: 'cdn', x: 55, y: 52, lat: 30.59, lng: 114.30, trafficWeight: 0.81 },
  { id: 'cn-xa', name: '西安', region: '西北 CDN', role: 'cdn', x: 46, y: 37, lat: 34.34, lng: 108.94, trafficWeight: 0.64 },
  { id: 'cn-sy', name: '沈阳', region: '东北 CDN', role: 'cdn', x: 75, y: 15, lat: 41.80, lng: 123.43, trafficWeight: 0.58 },
]

const globalNodes: EventMapNode[] = [
  { id: 'global-sg', name: 'Singapore', region: 'SEA POP', role: 'cdn', x: 67, y: 62, lat: 1.35, lng: 103.82, trafficWeight: 0.78 },
  { id: 'global-tokyo', name: 'Tokyo', region: 'Japan POP', role: 'cdn', x: 79, y: 37, lat: 35.68, lng: 139.69, trafficWeight: 0.74 },
  { id: 'global-frankfurt', name: 'Frankfurt', region: 'EU POP', role: 'cdn', x: 43, y: 33, lat: 50.11, lng: 8.68, trafficWeight: 0.69 },
  { id: 'global-sfo', name: 'San Jose', region: 'US West POP', role: 'cdn', x: 13, y: 42, lat: 37.33, lng: -121.89, trafficWeight: 0.9 },
  { id: 'global-ashburn', name: 'Ashburn', region: 'US East POP', role: 'cdn', x: 23, y: 37, lat: 39.04, lng: -77.49, trafficWeight: 0.86 },
  { id: 'global-sydney', name: 'Sydney', region: 'Oceania POP', role: 'cdn', x: 80, y: 79, lat: -33.86, lng: 151.21, trafficWeight: 0.56 },
  { id: 'global-dubai', name: 'Dubai', region: 'Middle East POP', role: 'cdn', x: 53, y: 44, lat: 25.2, lng: 55.27, trafficWeight: 0.52 },
  { id: 'global-saopaulo', name: 'Sao Paulo', region: 'SA POP', role: 'cdn', x: 30, y: 74, lat: -23.55, lng: -46.63, trafficWeight: 0.48 },
]

const flowReasons = [
  '静态资源回源',
  '缓存失效补拉',
  '热点资源突增',
  '动态接口穿透',
  '证书刷新握手',
  '边缘节点重试',
]

const clamp = (value: number, min: number, max: number) =>
  Math.min(max, Math.max(min, value))

const pickReason = (events: SecurityEventItem[]) =>
  events.find((event) => event.reason)?.reason || flowReasons[Math.floor(Math.random() * flowReasons.length)]

const createFlow = ({
  node,
  direction,
  decision,
  intensity,
  bandwidthMbps,
  requestsPerSecond,
  reason,
  event,
}: {
  node: EventMapNode
  direction: 'ingress' | 'egress'
  decision: 'allow' | 'block'
  intensity: number
  bandwidthMbps: number
  requestsPerSecond: number
  reason: string
  event?: SecurityEventItem
}): EventMapFlow => ({
  id: `${node.id}-${direction}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
  nodeId: node.id,
  direction,
  decision,
  intensity,
  bandwidthMbps,
  requestsPerSecond,
  startedAt: Date.now(),
  durationMs: direction === 'ingress' ? 1800 - Math.round(intensity * 400) : 1400 - Math.round(intensity * 300),
  reason,
  event,
})

export function useAdminEventMap({ metrics, events }: UseAdminEventMapOptions) {
  const scope = ref<EventMapScope>('china')
  const liveFlows = ref<EventMapFlow[]>([])
  const hottestNodeId = ref<string | null>(null)
  const trafficSeed = ref(0)
  let timer: number | null = null

  const nodes = computed(() =>
    scope.value === 'china' ? chinaNodes : globalNodes,
  )

  const originNode = computed(() => originNodeByScope[scope.value])

  const syncFromMetrics = () => {
    const currentMetrics = metrics.value
    const currentEvents = events.value ?? []
    const totalPackets = currentMetrics?.total_packets ?? 0
    const blockedPackets = currentMetrics?.blocked_packets ?? 0
    const proxySuccesses = currentMetrics?.proxy_successes ?? 0
    const proxyFailures = currentMetrics?.proxy_failures ?? 0
    const totalProxy = proxySuccesses + proxyFailures
    const blockRate = totalPackets > 0 ? blockedPackets / totalPackets : 0
    const trafficPressure = clamp(
      totalPackets > 0
        ? totalPackets / 5000 + totalProxy / 500 + (currentEvents.length || 1) / 8
        : currentEvents.length / 6,
      0.18,
      1.2,
    )

    trafficSeed.value = trafficPressure

    const desiredFlowCount = scope.value === 'global'
      ? Math.max(2, Math.round(trafficPressure * 4))
      : Math.max(3, Math.round(trafficPressure * 6))

    const rankedNodes = [...nodes.value].sort(
      (left, right) => right.trafficWeight - left.trafficWeight,
    )

    const chosenNodes = rankedNodes.slice(0, clamp(desiredFlowCount, 2, rankedNodes.length))
    const nextFlows: EventMapFlow[] = []
    let hottestId: string | null = null
    let hottestScore = -1

    chosenNodes.forEach((node, index) => {
      const event = currentEvents[index % Math.max(currentEvents.length, 1)]
      const reason = event?.reason || pickReason(currentEvents)
      const eventSuggestsBlock = event?.action === 'block'
      const decision: 'allow' | 'block' =
        eventSuggestsBlock || blockRate > 0.26 + index * 0.02 ? 'block' : 'allow'

      const burst = clamp(
        trafficPressure * (1.05 - index * 0.08) * node.trafficWeight,
        0.2,
        1.35,
      )
      const bandwidthMbps = Math.round(80 + burst * 920)
      const requestsPerSecond = Math.round(180 + burst * 2400)

      if (bandwidthMbps > hottestScore) {
        hottestScore = bandwidthMbps
        hottestId = node.id
      }

      nextFlows.push(
        createFlow({
          node,
          direction: 'ingress',
          decision,
          intensity: burst,
          bandwidthMbps,
          requestsPerSecond,
          reason,
          event,
        }),
      )

      if (decision === 'allow') {
        nextFlows.push(
          createFlow({
            node,
            direction: 'egress',
            decision,
            intensity: clamp(burst * 0.92, 0.18, 1.2),
            bandwidthMbps: Math.round(bandwidthMbps * 0.9),
            requestsPerSecond: Math.round(requestsPerSecond * 0.88),
            reason: 'Rust 响应回送',
            event,
          }),
        )
      }
    })

    hottestNodeId.value = hottestId
    liveFlows.value = nextFlows
  }

  const pulse = () => {
    syncFromMetrics()
  }

  watch([metrics, events, scope], () => {
    syncFromMetrics()
  }, { immediate: true, deep: true })

  timer = window.setInterval(pulse, 1600)

  onBeforeUnmount(() => {
    if (timer) {
      window.clearInterval(timer)
    }
  })

  const snapshot = computed<EventMapSnapshot>(() => {
    const blockedFlowCount = liveFlows.value.filter(
      (flow) => flow.decision === 'block' && flow.direction === 'ingress',
    ).length
    const allowedFlowCount = liveFlows.value.filter(
      (flow) => flow.decision === 'allow' && flow.direction === 'ingress',
    ).length
    const uniqueActiveNodeIds = new Set(liveFlows.value.map((flow) => flow.nodeId))
    const hottestNode =
      nodes.value.find((node) => node.id === hottestNodeId.value) ?? null

    return {
      scope: scope.value,
      nodes: nodes.value,
      flows: liveFlows.value,
      originNode: originNode.value,
      liveTrafficScore: trafficSeed.value,
      activeNodeCount: uniqueActiveNodeIds.size,
      peakBandwidthMbps:
        liveFlows.value.reduce(
          (max, flow) => Math.max(max, flow.bandwidthMbps),
          0,
        ) || 0,
      allowedFlowCount,
      blockedFlowCount,
      hottestNode,
    }
  })

  return {
    scope,
    snapshot,
  }
}
