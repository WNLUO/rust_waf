import type {
  BlockedIpCreatePayload,
  BlockedIpsBatchUnblockPayload,
  BlockedIpsBatchUnblockResponse,
  BlockedIpsCleanupExpiredPayload,
  BlockedIpsCleanupExpiredResponse,
  BlockedIpsQuery,
  BlockedIpsResponse,
  BehaviorProfilesResponse,
  BehaviorSessionsResponse,
  EventsQuery,
  FingerprintProfilesResponse,
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

export function fetchBehaviorProfiles() {
  return apiRequest<BehaviorProfilesResponse>('/behavior/profiles')
}

export function fetchFingerprintProfiles() {
  return apiRequest<FingerprintProfilesResponse>('/intelligence/fingerprints')
}

export function fetchBehaviorSessions() {
  return apiRequest<BehaviorSessionsResponse>('/intelligence/sessions')
}

export function fetchBlockedIps(query?: BlockedIpsQuery) {
  return apiRequest<BlockedIpsResponse>(`/blocked-ips${buildQuery(query)}`)
}

export function createBlockedIp(payload: BlockedIpCreatePayload) {
  return apiRequest<WriteStatusResponse>('/blocked-ips', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function unblockIpsBatch(payload: BlockedIpsBatchUnblockPayload) {
  return apiRequest<BlockedIpsBatchUnblockResponse>('/blocked-ips/unblock-batch', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function cleanupExpiredBlockedIps(payload: BlockedIpsCleanupExpiredPayload) {
  return apiRequest<BlockedIpsCleanupExpiredResponse>('/blocked-ips/cleanup-expired', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function markSecurityEventHandled(id: number, handled: boolean) {
  return apiRequest<WriteStatusResponse>(`/events/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ handled }),
  })
}
