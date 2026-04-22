import { onBeforeUnmount, onMounted, reactive } from 'vue'
import { API_BASE, apiRequest } from '@/shared/api/core'

type AdminRealtimeTopic =
  | 'metrics'
  | 'l4_stats'
  | 'l7_stats'
  | 'recent_events'
  | 'recent_blocked_ips'
  | 'traffic_map'
  | 'traffic_event_delta'
  | 'security_event_delta'
  | 'blocked_ip_upsert'
  | 'blocked_ip_deleted'

interface AdminRealtimeEnvelope<T = unknown> {
  topic: AdminRealtimeTopic
  payload: T
}

type TopicHandler<T = unknown> = (payload: T) => void

const listeners = new Map<AdminRealtimeTopic, Set<TopicHandler>>()

const connectionState = reactive({
  connected: false,
  connecting: false,
  lastMessageAt: null as number | null,
})

interface AdminWsTicketResponse {
  ticket: string
  expires_at: number
}

let socket: WebSocket | null = null
let reconnectTimer: number | null = null
let reconnectAttempt = 0

function getAdminWsUrl() {
  if (typeof window === 'undefined') return ''

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const url = new URL(`${protocol}//${window.location.host}${API_BASE}/ws/admin`)
  return url.toString()
}

function hasListeners() {
  return Array.from(listeners.values()).some((handlers) => handlers.size > 0)
}

function clearReconnectTimer() {
  if (reconnectTimer !== null) {
    window.clearTimeout(reconnectTimer)
    reconnectTimer = null
  }
}

function scheduleReconnect() {
  if (typeof window === 'undefined' || !hasListeners()) return
  clearReconnectTimer()
  const delay = Math.min(1000 * 2 ** reconnectAttempt, 15000)
  reconnectAttempt += 1
  reconnectTimer = window.setTimeout(() => {
    reconnectTimer = null
    ensureConnected()
  }, delay)
}

function disconnectIfIdle() {
  if (hasListeners()) return
  clearReconnectTimer()
  if (socket) {
    socket.close()
    socket = null
  }
  connectionState.connected = false
  connectionState.connecting = false
}

function handleMessage(event: MessageEvent<string>) {
  try {
    const envelope = JSON.parse(
      event.data,
    ) as AdminRealtimeEnvelope<unknown>
    connectionState.lastMessageAt = Date.now()
    listeners.get(envelope.topic)?.forEach((handler) => {
      handler(envelope.payload)
    })
  } catch (error) {
    console.warn('Failed to parse admin realtime message', error)
  }
}

async function fetchWsTicket() {
  return apiRequest<AdminWsTicketResponse>('/ws/admin-ticket', {
    method: 'POST',
  })
}

async function ensureConnected() {
  if (
    typeof window === 'undefined' ||
    socket ||
    connectionState.connecting ||
    !hasListeners()
  ) {
    return
  }

  const url = getAdminWsUrl()
  if (!url) return

  clearReconnectTimer()
  connectionState.connecting = true

  let ticket: AdminWsTicketResponse
  try {
    ticket = await fetchWsTicket()
  } catch {
    connectionState.connecting = false
    scheduleReconnect()
    return
  }

  if (!hasListeners() || socket) {
    connectionState.connecting = false
    return
  }

  const wsUrl = new URL(url)
  wsUrl.searchParams.set('ticket', ticket.ticket)

  socket = new WebSocket(wsUrl)

  socket.addEventListener('open', () => {
    reconnectAttempt = 0
    connectionState.connected = true
    connectionState.connecting = false
  })

  socket.addEventListener('message', handleMessage)

  socket.addEventListener('close', () => {
    socket = null
    connectionState.connected = false
    connectionState.connecting = false
    scheduleReconnect()
  })

  socket.addEventListener('error', () => {
    connectionState.connected = false
    connectionState.connecting = false
  })
}

export function useAdminRealtimeState() {
  return connectionState
}

export function useAdminRealtimeTopic<T = unknown>(
  topic: AdminRealtimeTopic,
  handler: TopicHandler<T>,
) {
  onMounted(() => {
    const handlers = listeners.get(topic) ?? new Set<TopicHandler>()
    handlers.add(handler as TopicHandler)
    listeners.set(topic, handlers)
    ensureConnected()
  })

  onBeforeUnmount(() => {
    const handlers = listeners.get(topic)
    handlers?.delete(handler as TopicHandler)
    if (handlers && handlers.size === 0) {
      listeners.delete(topic)
    }
    disconnectIfIdle()
  })
}
