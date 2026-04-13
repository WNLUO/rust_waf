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
  { id: 'cn-110000', name: '北京', region: '北京市', role: 'cdn', x: 0, y: 0, lat: 40.18994, lng: 116.41995, trafficWeight: 0.9 },
  { id: 'cn-120000', name: '天津', region: '天津市', role: 'cdn', x: 0, y: 0, lat: 39.288036, lng: 117.347043, trafficWeight: 0.72 },
  { id: 'cn-130000', name: '河北', region: '河北省', role: 'cdn', x: 0, y: 0, lat: 38.045474, lng: 114.502461, trafficWeight: 0.64 },
  { id: 'cn-140000', name: '山西', region: '山西省', role: 'cdn', x: 0, y: 0, lat: 37.618179, lng: 112.304436, trafficWeight: 0.45 },
  { id: 'cn-150000', name: '内蒙古', region: '内蒙古自治区', role: 'cdn', x: 0, y: 0, lat: 44.331087, lng: 114.077429, trafficWeight: 0.34 },
  { id: 'cn-210000', name: '辽宁', region: '辽宁省', role: 'cdn', x: 0, y: 0, lat: 41.299712, lng: 122.604994, trafficWeight: 0.52 },
  { id: 'cn-220000', name: '吉林', region: '吉林省', role: 'cdn', x: 0, y: 0, lat: 43.703954, lng: 126.171208, trafficWeight: 0.31 },
  { id: 'cn-230000', name: '黑龙江', region: '黑龙江省', role: 'cdn', x: 0, y: 0, lat: 48.040465, lng: 127.693027, trafficWeight: 0.28 },
  { id: 'cn-310000', name: '上海', region: '上海市', role: 'cdn', x: 0, y: 0, lat: 31.072559, lng: 121.438737, trafficWeight: 1 },
  { id: 'cn-320000', name: '江苏', region: '江苏省', role: 'cdn', x: 0, y: 0, lat: 32.983991, lng: 119.486506, trafficWeight: 0.86 },
  { id: 'cn-330000', name: '浙江', region: '浙江省', role: 'cdn', x: 0, y: 0, lat: 29.181466, lng: 120.109913, trafficWeight: 0.84 },
  { id: 'cn-340000', name: '安徽', region: '安徽省', role: 'cdn', x: 0, y: 0, lat: 31.849254, lng: 117.226884, trafficWeight: 0.57 },
  { id: 'cn-350000', name: '福建', region: '福建省', role: 'cdn', x: 0, y: 0, lat: 26.069925, lng: 118.006468, trafficWeight: 0.67 },
  { id: 'cn-360000', name: '江西', region: '江西省', role: 'cdn', x: 0, y: 0, lat: 27.636112, lng: 115.732975, trafficWeight: 0.44 },
  { id: 'cn-370000', name: '山东', region: '山东省', role: 'cdn', x: 0, y: 0, lat: 36.376092, lng: 118.187759, trafficWeight: 0.76 },
  { id: 'cn-410000', name: '河南', region: '河南省', role: 'cdn', x: 0, y: 0, lat: 33.902648, lng: 113.619717, trafficWeight: 0.62 },
  { id: 'cn-420000', name: '湖北', region: '湖北省', role: 'cdn', x: 0, y: 0, lat: 30.987527, lng: 112.271301, trafficWeight: 0.59 },
  { id: 'cn-430000', name: '湖南', region: '湖南省', role: 'cdn', x: 0, y: 0, lat: 27.629216, lng: 111.711649, trafficWeight: 0.51 },
  { id: 'cn-440000', name: '广东', region: '广东省', role: 'cdn', x: 0, y: 0, lat: 23.334643, lng: 113.429919, trafficWeight: 0.92 },
  { id: 'cn-450000', name: '广西', region: '广西壮族自治区', role: 'cdn', x: 0, y: 0, lat: 23.833381, lng: 108.7944, trafficWeight: 0.38 },
  { id: 'cn-460000', name: '海南', region: '海南省', role: 'cdn', x: 0, y: 0, lat: 19.189767, lng: 109.754859, trafficWeight: 0.29 },
  { id: 'cn-500000', name: '重庆', region: '重庆市', role: 'cdn', x: 0, y: 0, lat: 30.067297, lng: 107.8839, trafficWeight: 0.5 },
  { id: 'cn-510000', name: '四川', region: '四川省', role: 'cdn', x: 0, y: 0, lat: 30.674545, lng: 102.693453, trafficWeight: 0.56 },
  { id: 'cn-520000', name: '贵州', region: '贵州省', role: 'cdn', x: 0, y: 0, lat: 26.826368, lng: 106.880455, trafficWeight: 0.36 },
  { id: 'cn-530000', name: '云南', region: '云南省', role: 'cdn', x: 0, y: 0, lat: 25.008643, lng: 101.485106, trafficWeight: 0.33 },
  { id: 'cn-540000', name: '西藏', region: '西藏自治区', role: 'cdn', x: 0, y: 0, lat: 31.56375, lng: 88.388277, trafficWeight: 0.16 },
  { id: 'cn-610000', name: '陕西', region: '陕西省', role: 'cdn', x: 0, y: 0, lat: 35.263661, lng: 108.887114, trafficWeight: 0.48 },
  { id: 'cn-620000', name: '甘肃', region: '甘肃省', role: 'cdn', x: 0, y: 0, lat: 36.058039, lng: 103.823557, trafficWeight: 0.24 },
  { id: 'cn-630000', name: '青海', region: '青海省', role: 'cdn', x: 0, y: 0, lat: 35.726403, lng: 96.043533, trafficWeight: 0.18 },
  { id: 'cn-640000', name: '宁夏', region: '宁夏回族自治区', role: 'cdn', x: 0, y: 0, lat: 37.291332, lng: 106.169866, trafficWeight: 0.22 },
  { id: 'cn-650000', name: '新疆', region: '新疆维吾尔自治区', role: 'cdn', x: 0, y: 0, lat: 41.371801, lng: 85.294711, trafficWeight: 0.2 },
  { id: 'cn-710000', name: '台湾', region: '台湾省', role: 'cdn', x: 0, y: 0, lat: 23.749452, lng: 120.971485, trafficWeight: 0.54 },
  { id: 'cn-810000', name: '香港', region: '香港特别行政区', role: 'cdn', x: 0, y: 0, lat: 22.377366, lng: 114.134357, trafficWeight: 0.6 },
  { id: 'cn-820000', name: '澳门', region: '澳门特别行政区', role: 'cdn', x: 0, y: 0, lat: 22.159307, lng: 113.566988, trafficWeight: 0.32 },
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
  const queuedWaveFlows = ref<EventMapFlow[]>([])
  const hottestNodeId = ref<string | null>(null)
  const trafficSeed = ref(0)
  const pulseIndex = ref(0)
  let cycleTimer: number | null = null
  let emissionTimers: number[] = []

  const nodes = computed(() =>
    scope.value === 'china' ? chinaNodes : globalNodes,
  )

  const originNode = computed(() => originNodeByScope[scope.value])

  const buildWave = () => {
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
      : Math.max(8, Math.round(trafficPressure * 10))

    const rankedNodes = [...nodes.value].sort(
      (left, right) => right.trafficWeight - left.trafficWeight,
    )

    const startIndex =
      scope.value === 'china'
        ? pulseIndex.value % rankedNodes.length
        : 0

    const rotatedNodes =
      scope.value === 'china'
        ? rankedNodes
            .slice(startIndex)
            .concat(rankedNodes.slice(0, startIndex))
        : rankedNodes

    const chosenNodes = rotatedNodes.slice(
      0,
      clamp(desiredFlowCount, 2, rotatedNodes.length),
    )
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

      const ingressFlow = createFlow({
        node,
        direction: 'ingress',
        decision,
        intensity: burst,
        bandwidthMbps,
        requestsPerSecond,
        reason,
        event,
      })

      nextFlows.push(ingressFlow)

      if (decision === 'allow') {
        const egressFlow = createFlow({
          node,
          direction: 'egress',
          decision,
          intensity: clamp(burst * 0.92, 0.18, 1.2),
          bandwidthMbps: Math.round(bandwidthMbps * 0.9),
          requestsPerSecond: Math.round(requestsPerSecond * 0.88),
          reason: 'Rust 响应回送',
          event,
        })
        egressFlow.startedAt = ingressFlow.startedAt + ingressFlow.durationMs
        nextFlows.push(egressFlow)
      }
    })

    return {
      flows: nextFlows,
      hottestId,
      trafficPressure,
    }
  }

  const clearScheduledWave = () => {
    if (cycleTimer) {
      window.clearTimeout(cycleTimer)
      cycleTimer = null
    }
  }

  const clearEmissionTimers = () => {
    emissionTimers.forEach((timerId) => window.clearTimeout(timerId))
    emissionTimers = []
  }

  const scheduleNextPulse = (durationMs: number) => {
    if (cycleTimer) {
      window.clearTimeout(cycleTimer)
    }
    cycleTimer = window.setTimeout(() => {
      pulse()
    }, durationMs)
  }

  const playFlow = (flow: EventMapFlow, delayMs: number) => {
    const startTimer = window.setTimeout(() => {
      liveFlows.value = [...liveFlows.value, flow]
    }, delayMs)
    emissionTimers.push(startTimer)

    const endTimer = window.setTimeout(() => {
      liveFlows.value = liveFlows.value.filter((item) => item.id !== flow.id)
    }, delayMs + flow.durationMs + 90)
    emissionTimers.push(endTimer)
  }

  const pulse = (reset = false) => {
    pulseIndex.value += 3
    clearScheduledWave()
    if (reset) {
      clearEmissionTimers()
      liveFlows.value = []
    }

    const wave = buildWave()
    hottestNodeId.value = wave.hottestId
    trafficSeed.value = wave.trafficPressure
    queuedWaveFlows.value = wave.flows

    const ingressFlows = wave.flows.filter((flow) => flow.direction === 'ingress')
    const egressFlows = wave.flows.filter((flow) => flow.direction === 'egress')
    const gapAfterIngress = scope.value === 'china' ? 160 : 180
    const gapBetweenNodes = scope.value === 'china' ? 760 : 760

    let cursor = 0

    ingressFlows.forEach((ingressFlow) => {
      const ingressStart = cursor
      const timedIngress = {
        ...ingressFlow,
        startedAt: Date.now() + ingressStart,
      }
      playFlow(timedIngress, ingressStart)

      const pairedEgress = egressFlows.find(
        (flow) => flow.nodeId === ingressFlow.nodeId,
      )

      if (pairedEgress) {
        const egressStart = ingressStart + ingressFlow.durationMs + gapAfterIngress
        playFlow(
          {
            ...pairedEgress,
            startedAt: Date.now() + egressStart,
          },
          egressStart,
        )
        cursor = egressStart + pairedEgress.durationMs + gapBetweenNodes
      } else {
        cursor = ingressStart + ingressFlow.durationMs + gapBetweenNodes
      }
    })

    scheduleNextPulse(
      Math.max(cursor, scope.value === 'china' ? 4200 : 4800),
    )
  }

  watch([metrics, events, scope], () => {
    pulse(true)
  }, { immediate: true, deep: true })

  onBeforeUnmount(() => {
    clearScheduledWave()
    clearEmissionTimers()
  })

  const snapshot = computed<EventMapSnapshot>(() => {
    const basisFlows = queuedWaveFlows.value.length
      ? queuedWaveFlows.value
      : liveFlows.value

    const blockedFlowCount = basisFlows.filter(
      (flow) => flow.decision === 'block' && flow.direction === 'ingress',
    ).length
    const allowedFlowCount = basisFlows.filter(
      (flow) => flow.decision === 'allow' && flow.direction === 'ingress',
    ).length
    const uniqueActiveNodeIds = new Set(
      basisFlows
        .filter((flow) => flow.direction === 'ingress')
        .map((flow) => flow.nodeId),
    )
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
        basisFlows.reduce(
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
