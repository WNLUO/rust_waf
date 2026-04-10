import type {
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
  SafeLineSyncOverviewResponse,
  SafeLineSitesResponse,
  SafeLineTestResponse,
  SecurityEventsResponse,
  SettingsPayload,
  SiteSyncLinkDraft,
  SiteSyncLinksResponse,
  WriteStatusResponse,
} from "./types";

const API_BASE = "/api";

async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    ...init,
  });

  if (!response.ok) {
    let message = `请求失败：${response.status}`;

    try {
      const payload = (await response.json()) as { error?: string };
      if (payload.error) {
        message = payload.error;
      }
    } catch {
      // Keep fallback message.
    }

    throw new Error(message);
  }

  return (await response.json()) as T;
}

type QueryParams = Record<string, ApiQueryValue>;

const buildQuery = (params?: QueryParams) => {
  if (!params) return "";
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (
      value === undefined ||
      value === null ||
      value === "" ||
      value === "all"
    )
      return;
    search.append(key, String(value));
  });
  const query = search.toString();
  return query ? `?${query}` : "";
};

const withDefaults = <T extends QueryParams>(
  defaults: T,
  overrides?: Partial<T>,
): T => ({
  ...defaults,
  ...(overrides || {}),
});

export async function fetchDashboardPayload(
  options: DashboardQueryOptions = {},
): Promise<DashboardPayload> {
  const eventsQuery = withDefaults<EventsQuery>(
    { limit: 8, sort_direction: "desc", sort_by: "created_at" },
    options.events,
  );
  const blockedQuery = withDefaults<BlockedIpsQuery>(
    {
      limit: 8,
      active_only: true,
      sort_direction: "desc",
      sort_by: "blocked_at",
    },
    options.blockedIps,
  );
  const eventsPath = `/events${buildQuery(eventsQuery)}`;
  const blockedPath = `/blocked-ips${buildQuery(blockedQuery)}`;

  const [health, metrics, events, blockedIps, rules] = await Promise.all([
    apiRequest<HealthResponse>("/health"),
    apiRequest<MetricsResponse>("/metrics"),
    apiRequest<SecurityEventsResponse>(eventsPath),
    apiRequest<BlockedIpsResponse>(blockedPath),
    apiRequest<RulesResponse>("/rules"),
  ]);

  return { health, metrics, events, blockedIps, rules };
}

export function createRule(rule: RuleDraft) {
  return apiRequest<WriteStatusResponse>("/rules", {
    method: "POST",
    body: JSON.stringify(rule),
  });
}

export function updateRule(rule: RuleDraft) {
  return apiRequest<WriteStatusResponse>(
    `/rules/${encodeURIComponent(rule.id)}`,
    {
      method: "PUT",
      body: JSON.stringify(rule),
    },
  );
}

export function deleteRule(id: string) {
  return apiRequest<WriteStatusResponse>(`/rules/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export function unblockIp(id: number) {
  return apiRequest<WriteStatusResponse>(`/blocked-ips/${id}`, {
    method: "DELETE",
  });
}

export function fetchSecurityEvents(query?: EventsQuery) {
  return apiRequest<SecurityEventsResponse>(`/events${buildQuery(query)}`);
}

export function fetchBlockedIps(query?: BlockedIpsQuery) {
  return apiRequest<BlockedIpsResponse>(`/blocked-ips${buildQuery(query)}`);
}

export function fetchRulesList() {
  return apiRequest<RulesResponse>("/rules");
}

export function fetchRuleActionPlugins() {
  return apiRequest<RuleActionPluginsResponse>("/rule-action-plugins");
}

export function fetchRuleActionTemplates() {
  return apiRequest<RuleActionTemplatesResponse>("/rule-action-templates");
}

export function installRuleActionPlugin(packageUrl: string) {
  return apiRequest<WriteStatusResponse>("/rule-action-plugins/install", {
    method: "POST",
    body: JSON.stringify({ package_url: packageUrl }),
  });
}

export function fetchHealth() {
  return apiRequest<HealthResponse>("/health");
}

export function fetchMetrics() {
  return apiRequest<MetricsResponse>("/metrics");
}

export function markSecurityEventHandled(id: number, handled: boolean) {
  return apiRequest<WriteStatusResponse>(`/events/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ handled }),
  });
}

export function fetchSettings() {
  return apiRequest<SettingsPayload>("/settings");
}

export function updateSettings(payload: SettingsPayload) {
  return apiRequest<WriteStatusResponse>("/settings", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function fetchL4Config() {
  return apiRequest<L4ConfigPayload>("/l4/config");
}

export function updateL4Config(
  payload: Omit<
    L4ConfigPayload,
    | "runtime_enabled"
    | "bloom_enabled"
    | "bloom_false_positive_verification"
    | "runtime_profile"
  >,
) {
  return apiRequest<WriteStatusResponse>("/l4/config", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function fetchL4Stats() {
  return apiRequest<L4StatsPayload>("/l4/stats");
}

export function fetchL7Config() {
  return apiRequest<L7ConfigPayload>("/l7/config");
}

export function updateL7Config(
  payload: Omit<L7ConfigPayload, "runtime_enabled">,
) {
  return apiRequest<WriteStatusResponse>("/l7/config", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function fetchL7Stats() {
  return apiRequest<L7StatsPayload>("/l7/stats");
}

export function testSafeLineConnection(payload: SettingsPayload["safeline"]) {
  return apiRequest<SafeLineTestResponse>("/integrations/safeline/test", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function fetchSafeLineSites(payload: SettingsPayload["safeline"]) {
  return apiRequest<SafeLineSitesResponse>("/integrations/safeline/sites", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function fetchCachedSafeLineSites() {
  return apiRequest<SafeLineSitesResponse>("/integrations/safeline/sites/cached");
}

export function fetchSafeLineMappings() {
  return apiRequest<SafeLineMappingsResponse>(
    "/integrations/safeline/mappings",
  );
}

export function updateSafeLineMappings(payload: SafeLineMappingsUpdateRequest) {
  return apiRequest<WriteStatusResponse>("/integrations/safeline/mappings", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function pullSafeLineSites() {
  return apiRequest<SafeLineSitesPullResponse>("/integrations/safeline/pull/sites", {
    method: "POST",
  });
}

export function pullSafeLineSite(remoteSiteId: string) {
  return apiRequest<WriteStatusResponse>(
    `/integrations/safeline/pull/sites/${encodeURIComponent(remoteSiteId)}`,
    {
      method: "POST",
    },
  );
}

export function pushSafeLineSites() {
  return apiRequest<SafeLineSitesPushResponse>("/integrations/safeline/push/sites", {
    method: "POST",
  });
}

export function pushSafeLineSite(localSiteId: number) {
  return apiRequest<WriteStatusResponse>(`/integrations/safeline/push/sites/${localSiteId}`, {
    method: "POST",
  });
}

export function fetchLocalSites() {
  return apiRequest<LocalSitesResponse>("/sites/local");
}

export function fetchLocalSite(id: number) {
  return apiRequest<LocalSiteItem>(`/sites/local/${id}`);
}

export function createLocalSite(payload: LocalSiteDraft) {
  return apiRequest<LocalSiteItem>("/sites/local", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function updateLocalSite(id: number, payload: LocalSiteDraft) {
  return apiRequest<WriteStatusResponse>(`/sites/local/${id}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function deleteLocalSite(id: number) {
  return apiRequest<WriteStatusResponse>(`/sites/local/${id}`, {
    method: "DELETE",
  });
}

export function fetchLocalCertificates() {
  return apiRequest<LocalCertificatesResponse>("/certificates/local");
}

export function fetchLocalCertificate(id: number) {
  return apiRequest<LocalCertificateItem>(`/certificates/local/${id}`);
}

export function createLocalCertificate(payload: LocalCertificateDraft) {
  return apiRequest<LocalCertificateItem>("/certificates/local", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function generateLocalCertificate(payload: GeneratedLocalCertificateRequest) {
  return apiRequest<LocalCertificateItem>("/certificates/local/generate", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function updateLocalCertificate(id: number, payload: LocalCertificateDraft) {
  return apiRequest<WriteStatusResponse>(`/certificates/local/${id}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function deleteLocalCertificate(id: number) {
  return apiRequest<WriteStatusResponse>(`/certificates/local/${id}`, {
    method: "DELETE",
  });
}

export function fetchSiteSyncLinks() {
  return apiRequest<SiteSyncLinksResponse>("/integrations/safeline/site-links");
}

export function upsertSiteSyncLink(payload: SiteSyncLinkDraft) {
  return apiRequest<WriteStatusResponse>("/integrations/safeline/site-links", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function deleteSiteSyncLink(id: number) {
  return apiRequest<WriteStatusResponse>(`/integrations/safeline/site-links/${id}`, {
    method: "DELETE",
  });
}

export function syncSafeLineEvents() {
  return apiRequest<SafeLineEventSyncResponse>(
    "/integrations/safeline/sync/events",
    {
      method: "POST",
    },
  );
}

export function fetchSafeLineSyncState() {
  return apiRequest<SafeLineSyncOverviewResponse>(
    "/integrations/safeline/sync/state",
  );
}

export function syncSafeLineBlockedIps() {
  return apiRequest<SafeLineBlocklistSyncResponse>(
    "/integrations/safeline/sync/blocked-ips",
    {
      method: "POST",
    },
  );
}

export function pullSafeLineBlockedIps() {
  return apiRequest<SafeLineBlocklistPullResponse>(
    "/integrations/safeline/pull/blocked-ips",
    {
      method: "POST",
    },
  );
}
