import type {
  GlobalEntryConfigPayload,
  LocalSiteDraft,
  LocalSiteItem,
  LocalSitesResponse,
  SafeLineSitePullOptions,
  SafeLineSitePullRequest,
  SafeLineSitesPullResponse,
  SafeLineSitesPushResponse,
  WriteStatusResponse,
} from '@/shared/types'
import { apiRequest } from './core'

export function fetchLocalSites() {
  return apiRequest<LocalSitesResponse>('/sites/local')
}

export function fetchGlobalEntryConfig() {
  return apiRequest<GlobalEntryConfigPayload>('/sites/global-entry')
}

export function updateGlobalEntryConfig(payload: GlobalEntryConfigPayload) {
  return apiRequest<WriteStatusResponse>('/sites/global-entry', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function fetchLocalSite(id: number) {
  return apiRequest<LocalSiteItem>(`/sites/local/${id}`)
}

export function createLocalSite(payload: LocalSiteDraft) {
  return apiRequest<LocalSiteItem>('/sites/local', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function updateLocalSite(id: number, payload: LocalSiteDraft) {
  return apiRequest<WriteStatusResponse>(`/sites/local/${id}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function deleteLocalSite(id: number) {
  return apiRequest<WriteStatusResponse>(`/sites/local/${id}`, {
    method: 'DELETE',
  })
}

export function clearLocalSiteData() {
  return apiRequest<WriteStatusResponse>('/sites/local/reset', {
    method: 'POST',
  })
}

export function pullSafeLineSites() {
  return apiRequest<SafeLineSitesPullResponse>(
    '/integrations/safeline/pull/sites',
    {
      method: 'POST',
    },
  )
}

export function pullSafeLineSite(
  remoteSiteId: string,
  options?: SafeLineSitePullOptions,
) {
  const payload: SafeLineSitePullRequest | undefined = options
    ? { options }
    : undefined
  return apiRequest<WriteStatusResponse>(
    `/integrations/safeline/pull/sites/${encodeURIComponent(remoteSiteId)}`,
    {
      method: 'POST',
      body: payload ? JSON.stringify(payload) : undefined,
    },
  )
}

export function pushSafeLineSites() {
  return apiRequest<SafeLineSitesPushResponse>(
    '/integrations/safeline/push/sites',
    {
      method: 'POST',
    },
  )
}

export function pushSafeLineSite(localSiteId: number) {
  return apiRequest<WriteStatusResponse>(
    `/integrations/safeline/push/sites/${localSiteId}`,
    {
      method: 'POST',
    },
  )
}
