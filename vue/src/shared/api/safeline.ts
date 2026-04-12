import type {
  SafeLineBlocklistPullResponse,
  SafeLineBlocklistSyncResponse,
  SafeLineEventSyncResponse,
  SafeLineMappingsResponse,
  SafeLineMappingsUpdateRequest,
  SafeLineSitesResponse,
  SafeLineSyncOverviewResponse,
  SafeLineTestResponse,
  SettingsPayload,
  SiteSyncLinkDraft,
  SiteSyncLinksResponse,
  WriteStatusResponse,
} from '@/shared/types'
import { apiRequest } from './core'

export function testSafeLineConnection(payload: SettingsPayload['safeline']) {
  return apiRequest<SafeLineTestResponse>('/integrations/safeline/test', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function fetchSafeLineSites(payload: SettingsPayload['safeline']) {
  return apiRequest<SafeLineSitesResponse>('/integrations/safeline/sites', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function fetchCachedSafeLineSites() {
  return apiRequest<SafeLineSitesResponse>(
    '/integrations/safeline/sites/cached',
  )
}

export function fetchSafeLineMappings() {
  return apiRequest<SafeLineMappingsResponse>('/integrations/safeline/mappings')
}

export function updateSafeLineMappings(payload: SafeLineMappingsUpdateRequest) {
  return apiRequest<WriteStatusResponse>('/integrations/safeline/mappings', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function fetchSiteSyncLinks() {
  return apiRequest<SiteSyncLinksResponse>('/integrations/safeline/site-links')
}

export function upsertSiteSyncLink(payload: SiteSyncLinkDraft) {
  return apiRequest<WriteStatusResponse>('/integrations/safeline/site-links', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function deleteSiteSyncLink(id: number) {
  return apiRequest<WriteStatusResponse>(
    `/integrations/safeline/site-links/${id}`,
    {
      method: 'DELETE',
    },
  )
}

export function syncSafeLineEvents() {
  return apiRequest<SafeLineEventSyncResponse>(
    '/integrations/safeline/sync/events',
    {
      method: 'POST',
    },
  )
}

export function fetchSafeLineSyncState() {
  return apiRequest<SafeLineSyncOverviewResponse>(
    '/integrations/safeline/sync/state',
  )
}

export function syncSafeLineBlockedIps() {
  return apiRequest<SafeLineBlocklistSyncResponse>(
    '/integrations/safeline/sync/blocked-ips',
    {
      method: 'POST',
    },
  )
}

export function pullSafeLineBlockedIps() {
  return apiRequest<SafeLineBlocklistPullResponse>(
    '/integrations/safeline/pull/blocked-ips',
    {
      method: 'POST',
    },
  )
}
