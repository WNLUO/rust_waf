import type {
  BlockedIpsQuery,
  BlockedIpsResponse,
  EventsQuery,
  SecurityEventsResponse,
  WriteStatusResponse,
} from '@/shared/types'
import { apiRequest, buildQuery } from './core'

export function unblockIp(id: number) {
  return apiRequest<WriteStatusResponse>(`/blocked-ips/${id}`, {
    method: 'DELETE',
  })
}

export function fetchSecurityEvents(query?: EventsQuery) {
  return apiRequest<SecurityEventsResponse>(`/events${buildQuery(query)}`)
}

export function fetchBlockedIps(query?: BlockedIpsQuery) {
  return apiRequest<BlockedIpsResponse>(`/blocked-ips${buildQuery(query)}`)
}

export function markSecurityEventHandled(id: number, handled: boolean) {
  return apiRequest<WriteStatusResponse>(`/events/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ handled }),
  })
}
