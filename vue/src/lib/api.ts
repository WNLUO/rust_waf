import type {
  ActionIdeaPreset,
  ActionIdeaPresetsResponse,
  ApiQueryValue,
  BlockedIpsQuery,
  BlockedIpsResponse,
  DashboardPayload,
  DashboardQueryOptions,
  GeneratedLocalCertificateRequest,
  EventsQuery,
  HealthResponse,
  L4ConfigPayload,
  L4StatsPayload,
  L7ConfigPayload,
  L7StatsPayload,
  LocalCertificateDraft,
  LocalCertificateItem,
  LocalCertificatesResponse,
  LocalSiteDraft,
  LocalSiteItem,
  LocalSitesResponse,
  MetricsResponse,
  RuleActionPluginsResponse,
  RuleActionTemplatePreviewResponse,
  RuleActionTemplatesResponse,
  RuleDraft,
  RulesResponse,
  SafeLineBlocklistPullResponse,
  SafeLineBlocklistSyncResponse,
  SafeLineEventSyncResponse,
  SafeLineMappingsResponse,
  SafeLineMappingsUpdateRequest,
  SafeLineSitesPullResponse,
  SafeLineSitesPushResponse,
  SafeLineSitePullOptions,
  SafeLineSitePullRequest,
  SafeLineSyncOverviewResponse,
  SafeLineSitesResponse,
  SafeLineTestResponse,
  SecurityEventsResponse,
  SettingsPayload,
  SiteSyncLinkDraft,
  SiteSyncLinksResponse,
  WriteStatusResponse,
} from './types'

const API_BASE = '/api'
const ADMIN_TOKEN_STORAGE_KEY = 'waf-admin-api-token'

function getAuthHeaders() {
  if (typeof window === 'undefined') return {} as HeadersInit
  const token = window.localStorage.getItem(ADMIN_TOKEN_STORAGE_KEY)?.trim()
  return token
    ? ({ Authorization: `Bearer ${token}` } satisfies HeadersInit)
    : ({} as HeadersInit)
}

async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...getAuthHeaders(),
      ...(init?.headers ?? {}),
    },
    ...init,
  })

  if (!response.ok) {
    let message = `请求失败：${response.status}`

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

type QueryParams = Record<string, ApiQueryValue>

const buildQuery = (params?: QueryParams) => {
  if (!params) return ''
  const search = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => {
    if (
      value === undefined ||
      value === null ||
      value === '' ||
      value === 'all'
    )
      return
    search.append(key, String(value))
  })
  const query = search.toString()
  return query ? `?${query}` : ''
}

const withDefaults = <T extends QueryParams>(
  defaults: T,
  overrides?: Partial<T>,
): T => ({
  ...defaults,
  ...(overrides || {}),
})

export async function fetchDashboardPayload(
  options: DashboardQueryOptions = {},
): Promise<DashboardPayload> {
  const eventsQuery = withDefaults<EventsQuery>(
    { limit: 8, sort_direction: 'desc', sort_by: 'created_at' },
    options.events,
  )
  const blockedQuery = withDefaults<BlockedIpsQuery>(
    {
      limit: 8,
      active_only: true,
      sort_direction: 'desc',
      sort_by: 'blocked_at',
    },
    options.blockedIps,
  )
  const eventsPath = `/events${buildQuery(eventsQuery)}`
  const blockedPath = `/blocked-ips${buildQuery(blockedQuery)}`

  const [health, metrics, events, blockedIps, rules] = await Promise.all([
    apiRequest<HealthResponse>('/health'),
    apiRequest<MetricsResponse>('/metrics'),
    apiRequest<SecurityEventsResponse>(eventsPath),
    apiRequest<BlockedIpsResponse>(blockedPath),
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
  return apiRequest<WriteStatusResponse>(
    `/rules/${encodeURIComponent(rule.id)}`,
    {
      method: 'PUT',
      body: JSON.stringify(rule),
    },
  )
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

export function fetchSecurityEvents(query?: EventsQuery) {
  return apiRequest<SecurityEventsResponse>(`/events${buildQuery(query)}`)
}

export function fetchBlockedIps(query?: BlockedIpsQuery) {
  return apiRequest<BlockedIpsResponse>(`/blocked-ips${buildQuery(query)}`)
}

export function fetchRulesList() {
  return apiRequest<RulesResponse>('/rules')
}

export function fetchRuleActionPlugins() {
  return apiRequest<RuleActionPluginsResponse>('/rule-action-plugins')
}

export function fetchRuleActionTemplates() {
  return apiRequest<RuleActionTemplatesResponse>('/rule-action-templates')
}

export function fetchRuleActionTemplatePreview(templateId: string) {
  return apiRequest<RuleActionTemplatePreviewResponse>(
    `/rule-action-templates/${encodeURIComponent(templateId)}/preview`,
  )
}

export function fetchActionIdeaPresets() {
  return apiRequest<ActionIdeaPresetsResponse>('/action-idea-presets')
}

export function updateActionIdeaPreset(
  ideaId: string,
  payload: Pick<
    ActionIdeaPreset,
    'title' | 'status_code' | 'content_type' | 'response_content'
  >,
) {
  return apiRequest<ActionIdeaPreset>(`/action-idea-presets/${encodeURIComponent(ideaId)}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  })
}

export async function uploadActionIdeaGzip(ideaId: string, file: File) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await fetch(
    `${API_BASE}/action-idea-presets/${encodeURIComponent(ideaId)}/upload-gzip`,
    {
      method: 'POST',
      headers: {
        ...getAuthHeaders(),
      },
      body: formData,
    },
  )

  if (!response.ok) {
    let message = `请求失败：${response.status}`
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

  return (await response.json()) as { idea: ActionIdeaPreset }
}

export function installRuleActionPlugin(
  packageUrl: string,
  sha256?: string,
) {
  return apiRequest<WriteStatusResponse>('/rule-action-plugins/install', {
    method: 'POST',
    body: JSON.stringify({ package_url: packageUrl, sha256 }),
  })
}

export async function uploadRuleActionPlugin(file: File, sha256?: string) {
  const formData = new FormData()
  formData.append('package', file)
  if (sha256?.trim()) {
    formData.append('sha256', sha256.trim())
  }

  const response = await fetch(`${API_BASE}/rule-action-plugins/upload`, {
    method: 'POST',
    headers: {
      ...getAuthHeaders(),
    },
    body: formData,
  })

  if (!response.ok) {
    let message = `请求失败：${response.status}`

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

  return (await response.json()) as WriteStatusResponse
}

export function updateRuleActionPlugin(pluginId: string, enabled: boolean) {
  return apiRequest<WriteStatusResponse>(
    `/rule-action-plugins/${encodeURIComponent(pluginId)}`,
    {
      method: 'PATCH',
      body: JSON.stringify({ enabled }),
    },
  )
}

export function deleteRuleActionPlugin(pluginId: string) {
  return apiRequest<WriteStatusResponse>(
    `/rule-action-plugins/${encodeURIComponent(pluginId)}`,
    {
      method: 'DELETE',
    },
  )
}

export function fetchHealth() {
  return apiRequest<HealthResponse>('/health')
}

export function fetchMetrics() {
  return apiRequest<MetricsResponse>('/metrics')
}

export function markSecurityEventHandled(id: number, handled: boolean) {
  return apiRequest<WriteStatusResponse>(`/events/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ handled }),
  })
}

export function fetchSettings() {
  return apiRequest<SettingsPayload>('/settings')
}

export function updateSettings(payload: SettingsPayload) {
  return apiRequest<WriteStatusResponse>('/settings', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function fetchL4Config() {
  return apiRequest<L4ConfigPayload>('/l4/config')
}

export function updateL4Config(
  payload: Omit<
    L4ConfigPayload,
    | 'runtime_enabled'
    | 'bloom_enabled'
    | 'bloom_false_positive_verification'
    | 'runtime_profile'
  >,
) {
  return apiRequest<WriteStatusResponse>('/l4/config', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function fetchL4Stats() {
  return apiRequest<L4StatsPayload>('/l4/stats')
}

export function fetchL7Config() {
  return apiRequest<L7ConfigPayload>('/l7/config')
}

export function updateL7Config(
  payload: Omit<L7ConfigPayload, 'runtime_enabled'>,
) {
  return apiRequest<WriteStatusResponse>('/l7/config', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function fetchL7Stats() {
  return apiRequest<L7StatsPayload>('/l7/stats')
}

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

export function getAdminApiToken() {
  if (typeof window === 'undefined') return ''
  return window.localStorage.getItem(ADMIN_TOKEN_STORAGE_KEY) ?? ''
}

export function setAdminApiToken(token: string) {
  if (typeof window === 'undefined') return
  window.localStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, token.trim())
}

export function clearAdminApiToken() {
  if (typeof window === 'undefined') return
  window.localStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY)
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

export function fetchLocalSites() {
  return apiRequest<LocalSitesResponse>('/sites/local')
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

export function fetchLocalCertificates() {
  return apiRequest<LocalCertificatesResponse>('/certificates/local')
}

export function fetchLocalCertificate(id: number) {
  return apiRequest<LocalCertificateItem>(`/certificates/local/${id}`)
}

export function createLocalCertificate(payload: LocalCertificateDraft) {
  return apiRequest<LocalCertificateItem>('/certificates/local', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function generateLocalCertificate(
  payload: GeneratedLocalCertificateRequest,
) {
  return apiRequest<LocalCertificateItem>('/certificates/local/generate', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function updateLocalCertificate(
  id: number,
  payload: LocalCertificateDraft,
) {
  return apiRequest<WriteStatusResponse>(`/certificates/local/${id}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function deleteLocalCertificate(id: number) {
  return apiRequest<WriteStatusResponse>(`/certificates/local/${id}`, {
    method: 'DELETE',
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
