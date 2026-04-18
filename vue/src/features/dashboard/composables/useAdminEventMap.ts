import { computed, type Ref } from 'vue'
import type {
  EventMapFlow,
  EventMapNode,
  EventMapSnapshot,
  TrafficMapResponse,
} from '@/shared/types'

interface UseAdminEventMapOptions {
  trafficMap: Ref<TrafficMapResponse | null | undefined>
}

function toNode(node: TrafficMapResponse['nodes'][number]): EventMapNode {
  return {
    id: node.id,
    name: node.name,
    region: node.region,
    role: node.role === 'origin' ? 'origin' : 'cdn',
    lat: node.lat,
    lng: node.lng,
    countryCode: node.country_code,
    countryName: node.country_name,
    geoScope: node.geo_scope,
    trafficWeight: node.traffic_weight,
    requestCount: node.request_count,
    blockedCount: node.blocked_count,
    bandwidthMbps: node.bandwidth_mbps,
    lastSeenAt: node.last_seen_at,
  }
}

export function useAdminEventMap({ trafficMap }: UseAdminEventMapOptions) {
  const snapshot = computed<EventMapSnapshot>(() => {
    const payload = trafficMap.value

    if (!payload) {
      return {
        scope: 'china',
        nodes: [],
        flows: [],
        originNode: {
          id: 'origin-pending',
          name: '源站定位中',
          region: '等待后端定位',
          role: 'origin',
          trafficWeight: 1,
        },
        liveTrafficScore: 0,
        activeNodeCount: 0,
        peakBandwidthMbps: 0,
        allowedFlowCount: 0,
        blockedFlowCount: 0,
        hottestNode: null,
      }
    }

    const nodes = payload.nodes.map(toNode)
    const originNode: EventMapNode = {
      id: payload.origin_node.id,
      name: payload.origin_node.name,
      region: payload.origin_node.region,
      role: 'origin',
      lat: payload.origin_node.lat,
      lng: payload.origin_node.lng,
      countryCode: payload.origin_node.country_code,
      countryName: payload.origin_node.country_name,
      geoScope: payload.origin_node.geo_scope,
      trafficWeight: payload.origin_node.traffic_weight,
      requestCount: payload.origin_node.request_count,
      blockedCount: payload.origin_node.blocked_count,
      bandwidthMbps: payload.origin_node.bandwidth_mbps,
      lastSeenAt: payload.origin_node.last_seen_at,
    }

    const flowNodeMap = new Map(nodes.map((node) => [node.id, node]))
    const flows: EventMapFlow[] = payload.flows.map((flow) => {
      const node = flowNodeMap.get(flow.node_id)
      const reason =
        flow.decision === 'block'
          ? '实时拦截'
          : flow.direction === 'egress'
            ? '源站响应回送'
            : '客户端请求进入'
      return {
        id: flow.id,
        nodeId: flow.node_id,
        direction: flow.direction,
        decision: flow.decision,
        intensity: node?.trafficWeight ?? 0.3,
        bandwidthMbps: flow.bandwidth_mbps,
        requestsPerSecond: Math.max(
          1,
          Math.round(flow.request_count / Math.max(payload.window_seconds, 1)),
        ),
        startedAt: flow.last_seen_at,
        durationMs: 1200,
        reason,
        requestCount: flow.request_count,
        bytes: flow.bytes,
        averageLatencyMs: flow.average_latency_ms,
      }
    })

    const hottestNode =
      nodes.find(
        (node) =>
          node.bandwidthMbps ===
          Math.max(...nodes.map((item) => item.bandwidthMbps || 0), 0),
      ) ?? null

    return {
      scope: payload.scope,
      nodes,
      flows,
      originNode,
      liveTrafficScore: payload.live_traffic_score,
      activeNodeCount: payload.active_node_count,
      peakBandwidthMbps: payload.peak_bandwidth_mbps,
      allowedFlowCount: payload.allowed_flow_count,
      blockedFlowCount: payload.blocked_flow_count,
      hottestNode,
    }
  })

  return {
    scope: computed(() => snapshot.value.scope),
    snapshot,
  }
}
