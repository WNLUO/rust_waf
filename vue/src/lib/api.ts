import type {
  BlockedIpsResponse,
  DashboardPayload,
  HealthResponse,
  MetricsResponse,
  RuleDraft,
  RulesResponse,
  SecurityEventsResponse,
  WriteStatusResponse,
} from './types'

const API_BASE = '/api'

async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
    ...init,
  })

  if (!response.ok) {
    let message = `Request failed: ${response.status}`

    try {
      const payload = (await response.json()) as { error?: string }
      if (payload.error) {
        message = payload.error
      }
    } catch {
      // Keep fallback message.
    }

    throw new Error(message)
  }

  return (await response.json()) as T
}

export async function fetchDashboardPayload(): Promise<DashboardPayload> {
  const [health, metrics, events, blockedIps, rules] = await Promise.all([
    apiRequest<HealthResponse>('/health'),
    apiRequest<MetricsResponse>('/metrics'),
    apiRequest<SecurityEventsResponse>('/events?limit=8&blocked_only=true'),
    apiRequest<BlockedIpsResponse>('/blocked-ips?limit=8&active_only=true'),
    apiRequest<RulesResponse>('/rules'),
  ])

  return { health, metrics, events, blockedIps, rules }
}

export function createRule(rule: RuleDraft) {
  return apiRequest<WriteStatusResponse>('/rules', {
    method: 'POST',
    body: JSON.stringify(rule),
  })
}

export function updateRule(rule: RuleDraft) {
  return apiRequest<WriteStatusResponse>(`/rules/${encodeURIComponent(rule.id)}`, {
    method: 'PUT',
    body: JSON.stringify(rule),
  })
}

export function deleteRule(id: string) {
  return apiRequest<WriteStatusResponse>(`/rules/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  })
}

export function unblockIp(id: number) {
  return apiRequest<WriteStatusResponse>(`/blocked-ips/${id}`, {
    method: 'DELETE',
  })
}
