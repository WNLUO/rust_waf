<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import AppLayout from "../components/layout/AppLayout.vue";
import StatusBadge from "../components/ui/StatusBadge.vue";
import {
  createLocalSite,
  deleteLocalSite,
  fetchCachedSafeLineSites,
  fetchLocalCertificates,
  fetchLocalSites,
  fetchSafeLineMappings,
  fetchSafeLineSites,
  fetchSiteSyncLinks,
  fetchSettings,
  pullSafeLineSite,
  pushSafeLineSite,
  testSafeLineConnection,
  updateLocalSite,
} from "../lib/api";
import type {
  LocalCertificateItem,
  LocalSiteDraft,
  LocalSiteItem,
  SafeLineMappingItem,
  SafeLineSiteItem,
  SafeLineTestResponse,
  SettingsPayload,
  SiteSyncLinkItem,
} from "../lib/types";
import { useFormatters } from "../composables/useFormatters";
import {
  Link2,
  PencilLine,
  Plus,
  PlugZap,
  RefreshCw,
  RotateCcw,
  Search,
  ServerCog,
  Settings2,
  Trash2,
  X,
} from "lucide-vue-next";

type ScopeFilter =
  | "all"
  | "mapped"
  | "unmapped"
  | "orphaned"
  | "local_only"
  | "missing_remote";
type StateFilter = "all" | "enabled" | "disabled" | "primary";
type RowKind =
  | "linked"
  | "remote_only"
  | "local_only"
  | "missing_remote"
  | "orphaned_mapping";

interface SiteRowDraft {
  row_key: string;
  row_kind: RowKind;
  link_id: number | null;
  remote_present: boolean;
  local_present: boolean;
  safeline_site_id: string;
  safeline_site_name: string;
  safeline_site_domain: string;
  remote_enabled: boolean | null;
  status: string;
  server_names: string[];
  remote_ports: string[];
  remote_ssl_ports: string[];
  remote_upstreams: string[];
  remote_ssl_enabled: boolean;
  local_site_id: number | null;
  local_site_name: string;
  local_primary_hostname: string;
  local_hostnames: string[];
  local_listen_ports: string[];
  local_upstreams: string[];
  local_enabled: boolean;
  local_notes: string;
  local_updated_at: number | null;
  local_sync_mode: string;
  local_alias: string;
  enabled: boolean;
  is_primary: boolean;
  notes: string;
  saved: boolean;
  orphaned: boolean;
  link_last_error: string | null;
  link_last_synced_at: number | null;
}

const { formatNumber, formatTimestamp } = useFormatters();

const loading = ref(true);
const error = ref("");
const successMessage = ref("");
const settings = ref<SettingsPayload | null>(null);
const mappings = ref<SafeLineMappingItem[]>([]);
const sites = ref<SafeLineSiteItem[]>([]);
const localSites = ref<LocalSiteItem[]>([]);
const localCertificates = ref<LocalCertificateItem[]>([]);
const siteLinks = ref<SiteSyncLinkItem[]>([]);
const testResult = ref<SafeLineTestResponse | null>(null);
const siteRows = ref<SiteRowDraft[]>([]);
const sitesLoadedAt = ref<number | null>(null);
const editingLocalSiteId = ref<number | null>(null);
const isLocalSiteModalOpen = ref(false);

const actions = reactive({
  refreshing: false,
  testing: false,
  loadingSites: false,
  loadingCertificates: false,
  savingLocalSite: false,
  deletingLocalSite: false,
});

const rowActions = reactive<Record<string, "pull" | "push" | undefined>>({});

const filters = reactive({
  keyword: "",
  scope: "all" as ScopeFilter,
  state: "all" as StateFilter,
});

const localSiteForm = reactive<LocalSiteDraft>({
  name: "",
  primary_hostname: "",
  hostnames: [],
  listen_ports: [],
  upstreams: [],
  enabled: true,
  tls_enabled: true,
  local_certificate_id: null,
  source: "manual",
  sync_mode: "manual",
  notes: "",
  last_synced_at: null,
});

function clearFeedback() {
  error.value = "";
  successMessage.value = "";
}

const hostnamesText = computed({
  get: () => localSiteForm.hostnames.join(", "),
  set: (value: string) => {
    localSiteForm.hostnames = splitEditorList(value);
  },
});

const listenPortsText = computed({
  get: () => localSiteForm.listen_ports.join(", "),
  set: (value: string) => {
    localSiteForm.listen_ports = splitEditorList(value);
  },
});

const upstreamsText = computed({
  get: () => localSiteForm.upstreams.join(", "),
  set: (value: string) => {
    localSiteForm.upstreams = splitEditorList(value);
  },
});

const currentLocalSite = computed(() =>
  editingLocalSiteId.value === null
    ? null
    : localSites.value.find((item) => item.id === editingLocalSiteId.value) ?? null,
);

const editorTitle = computed(() =>
  editingLocalSiteId.value === null ? "新建本地站点" : `编辑本地站点 #${editingLocalSiteId.value}`,
);

function statusNormalized(value: string) {
  return value.trim().toLowerCase();
}

function isSiteOnline(status: string) {
  return [
    "1",
    "true",
    "online",
    "enabled",
    "active",
    "running",
    "healthy",
    "on",
  ].includes(statusNormalized(status));
}

function isSiteOffline(status: string) {
  return [
    "0",
    "false",
    "offline",
    "disabled",
    "inactive",
    "stopped",
    "off",
  ].includes(statusNormalized(status));
}

function remoteStatusType(status: string) {
  if (!status.trim()) return "muted";
  if (isSiteOnline(status)) return "success";
  if (isSiteOffline(status)) return "warning";
  return "info";
}

function remoteStatusText(status: string) {
  if (!status.trim()) return "未读取远端状态";
  if (isSiteOnline(status)) return `远端在线 · ${status}`;
  if (isSiteOffline(status)) return `远端停用 · ${status}`;
  return `远端状态 · ${status}`;
}

function createSiteRow({
  site,
  mapping,
  local,
  link,
}: {
  site?: SafeLineSiteItem | null;
  mapping?: SafeLineMappingItem | null;
  local?: LocalSiteItem | null;
  link?: SiteSyncLinkItem | null;
}): SiteRowDraft {
  const remote = site ?? null;
  const savedMapping = mapping ?? null;
  const localSite = local ?? null;
  const siteLink = link ?? null;

  let rowKind: RowKind = "orphaned_mapping";
  if (remote && localSite) {
    rowKind = "linked";
  } else if (remote) {
    rowKind = "remote_only";
  } else if (localSite && siteLink) {
    rowKind = "missing_remote";
  } else if (localSite) {
    rowKind = "local_only";
  }

  return {
    row_key: remote?.id
      ? `remote:${remote.id}`
      : localSite
        ? `local:${localSite.id}`
        : `mapping:${savedMapping?.safeline_site_id || savedMapping?.id || "unknown"}`,
    row_kind: rowKind,
    link_id: siteLink?.id ?? null,
    remote_present: Boolean(remote),
    local_present: Boolean(localSite),
    safeline_site_id:
      remote?.id ?? savedMapping?.safeline_site_id ?? siteLink?.remote_site_id ?? "",
    safeline_site_name:
      remote?.name ?? savedMapping?.safeline_site_name ?? siteLink?.remote_site_name ?? "",
    safeline_site_domain: remote?.domain ?? savedMapping?.safeline_site_domain ?? "",
    remote_enabled: remote?.enabled ?? null,
    status: remote?.status ?? "",
    server_names: remote?.server_names ?? [],
    remote_ports: remote?.ports ?? [],
    remote_ssl_ports: remote?.ssl_ports ?? [],
    remote_upstreams: remote?.upstreams ?? [],
    remote_ssl_enabled: remote?.ssl_enabled ?? false,
    local_site_id: localSite?.id ?? null,
    local_site_name: localSite?.name ?? "",
    local_primary_hostname: localSite?.primary_hostname ?? "",
    local_hostnames: localSite?.hostnames ?? [],
    local_listen_ports: localSite?.listen_ports ?? [],
    local_upstreams: localSite?.upstreams ?? [],
    local_enabled: localSite?.enabled ?? false,
    local_notes: localSite?.notes ?? "",
    local_updated_at: localSite?.updated_at ?? null,
    local_sync_mode: siteLink?.sync_mode ?? localSite?.sync_mode ?? "manual",
    local_alias: savedMapping?.local_alias ?? remote?.name ?? remote?.domain ?? localSite?.name ?? "",
    enabled: savedMapping?.enabled ?? (remote ? true : localSite?.enabled ?? true),
    is_primary: savedMapping?.is_primary ?? false,
    notes: savedMapping?.notes ?? (remote ? "" : localSite?.notes ?? ""),
    saved: Boolean(savedMapping),
    orphaned: Boolean(savedMapping && !remote),
    link_last_error: siteLink?.last_error ?? null,
    link_last_synced_at: siteLink?.last_synced_at ?? localSite?.last_synced_at ?? null,
  };
}

function mergeSiteRows(
  siteList: SafeLineSiteItem[],
  mappingList: SafeLineMappingItem[],
  localSiteList: LocalSiteItem[],
  linkList: SiteSyncLinkItem[],
) {
  const rows: SiteRowDraft[] = [];
  const localById = new Map(localSiteList.map((item) => [item.id, item]));
  const safeLineLinks = linkList.filter((item) => item.provider === "safeline");
  const linkByRemoteId = new Map(safeLineLinks.map((item) => [item.remote_site_id, item]));
  const linkByLocalId = new Map(safeLineLinks.map((item) => [item.local_site_id, item]));
  const mappingByRemoteId = new Map(mappingList.map((item) => [item.safeline_site_id, item]));
  const usedLocalIds = new Set<number>();
  const usedMappingIds = new Set<string>();

  for (const site of siteList) {
    const mapping = mappingByRemoteId.get(site.id) ?? null;
    const link = linkByRemoteId.get(site.id) ?? null;
    const local = link ? localById.get(link.local_site_id) ?? null : null;
    rows.push(createSiteRow({ site, mapping, local, link }));
    if (mapping) usedMappingIds.add(mapping.safeline_site_id);
    if (local) usedLocalIds.add(local.id);
  }

  for (const mapping of mappingList) {
    if (usedMappingIds.has(mapping.safeline_site_id)) continue;
    const link = linkByRemoteId.get(mapping.safeline_site_id) ?? null;
    const local = link ? localById.get(link.local_site_id) ?? null : null;
    rows.push(createSiteRow({ mapping, local, link }));
    usedMappingIds.add(mapping.safeline_site_id);
    if (local) usedLocalIds.add(local.id);
  }

  for (const local of localSiteList) {
    if (usedLocalIds.has(local.id)) continue;
    const link = linkByLocalId.get(local.id) ?? null;
    const site = link ? siteList.find((item) => item.id === link.remote_site_id) ?? null : null;
    const mapping = link ? mappingByRemoteId.get(link.remote_site_id) ?? null : null;
    rows.push(createSiteRow({ site, mapping, local, link }));
  }

  siteRows.value = rows;
}

function rebuildRows() {
  mergeSiteRows(sites.value, mappings.value, localSites.value, siteLinks.value);
}

function mappingStateText(item: SiteRowDraft) {
  switch (item.row_kind) {
    case "linked":
      return item.saved ? "已映射" : "已建链";
    case "remote_only":
      return item.saved ? "仅映射" : "仅雷池";
    case "local_only":
      return "仅本地";
    case "missing_remote":
      return "远端缺失";
    case "orphaned_mapping":
      return "孤儿映射";
  }
}

function mappingStateType(item: SiteRowDraft) {
  switch (item.row_kind) {
    case "linked":
      return item.saved ? "success" : "info";
    case "remote_only":
      return item.saved ? "warning" : "muted";
    case "local_only":
      return "info";
    case "missing_remote":
    case "orphaned_mapping":
      return "warning";
  }
}

function syncModeLabel(value: string) {
  switch (value.trim()) {
    case "remote_to_local":
    case "pull_only":
      return "仅回流";
    case "local_to_remote":
    case "push_only":
      return "仅推送";
    case "bidirectional":
      return "双向同步";
    case "manual":
      return "手动";
    default:
      return value.trim() || "未设置";
  }
}

function splitEditorList(value: string) {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function defaultListenPorts() {
  const httpsListenAddr = settings.value?.https_listen_addr?.trim() ?? "";
  if (!httpsListenAddr) return [];
  const port = httpsListenAddr.split(":").pop()?.trim();
  return port ? [port] : [];
}

function resetLocalSiteForm() {
  editingLocalSiteId.value = null;
  localSiteForm.name = "";
  localSiteForm.primary_hostname = "";
  localSiteForm.hostnames = [];
  localSiteForm.listen_ports = defaultListenPorts();
  localSiteForm.upstreams = [];
  localSiteForm.enabled = true;
  localSiteForm.tls_enabled = true;
  localSiteForm.local_certificate_id = settings.value?.default_certificate_id ?? null;
  localSiteForm.source = "manual";
  localSiteForm.sync_mode = "manual";
  localSiteForm.notes = "";
  localSiteForm.last_synced_at = null;
}

function openCreateLocalSiteModal() {
  resetLocalSiteForm();
  isLocalSiteModalOpen.value = true;
}

function closeLocalSiteModal() {
  isLocalSiteModalOpen.value = false;
}

function populateLocalSiteForm(site: LocalSiteDraft, localSiteId: number | null) {
  editingLocalSiteId.value = localSiteId;
  localSiteForm.name = site.name;
  localSiteForm.primary_hostname = site.primary_hostname;
  localSiteForm.hostnames = [...site.hostnames];
  localSiteForm.listen_ports = [...site.listen_ports];
  localSiteForm.upstreams = [...site.upstreams];
  localSiteForm.enabled = site.enabled;
  localSiteForm.tls_enabled = site.tls_enabled;
  localSiteForm.local_certificate_id = site.local_certificate_id;
  localSiteForm.source = site.source;
  localSiteForm.sync_mode = site.sync_mode;
  localSiteForm.notes = site.notes;
  localSiteForm.last_synced_at = site.last_synced_at;
}

function siteDraftFromItem(site: LocalSiteItem): LocalSiteDraft {
  return {
    name: site.name,
    primary_hostname: site.primary_hostname,
    hostnames: [...site.hostnames],
    listen_ports: [...site.listen_ports],
    upstreams: [...site.upstreams],
    enabled: site.enabled,
    tls_enabled: site.tls_enabled,
    local_certificate_id: site.local_certificate_id,
    source: site.source,
    sync_mode: site.sync_mode,
    notes: site.notes,
    last_synced_at: site.last_synced_at,
  };
}

function siteDraftFromRow(row: SiteRowDraft): LocalSiteDraft {
  const localSite =
    row.local_present && row.local_site_id
      ? localSites.value.find((item) => item.id === row.local_site_id) ?? null
      : null;
  const primaryHostname =
    row.local_primary_hostname ||
    row.safeline_site_domain ||
    row.server_names[0] ||
    "";
  const hostnames = row.local_hostnames.length
    ? [...row.local_hostnames]
    : row.server_names.length
      ? [...row.server_names]
      : primaryHostname
        ? [primaryHostname]
        : [];
  const listenPorts = row.local_listen_ports.length
    ? [...row.local_listen_ports]
    : row.remote_ssl_ports.length
      ? [...row.remote_ssl_ports]
      : row.remote_ports.length
        ? [...row.remote_ports]
        : defaultListenPorts();
  const upstreams = row.local_upstreams.length
    ? [...row.local_upstreams]
    : row.remote_upstreams.length
      ? [...row.remote_upstreams]
      : [];

  return {
    name: row.local_site_name || row.local_alias || row.safeline_site_name || primaryHostname,
    primary_hostname: primaryHostname,
    hostnames,
    listen_ports: listenPorts,
    upstreams,
    enabled: row.local_present ? row.local_enabled : true,
    tls_enabled: localSite?.tls_enabled ?? row.remote_ssl_enabled ?? false,
    local_certificate_id: localSite?.local_certificate_id ?? settings.value?.default_certificate_id ?? null,
    source: row.local_present ? "manual" : "manual",
    sync_mode: row.local_sync_mode || "manual",
    notes: row.local_notes || row.notes || "",
    last_synced_at: row.link_last_synced_at,
  };
}

function editLocalSite(row: SiteRowDraft) {
  if (row.local_present && row.local_site_id) {
    const site = localSites.value.find((item) => item.id === row.local_site_id);
    if (site) {
      populateLocalSiteForm(siteDraftFromItem(site), site.id);
      isLocalSiteModalOpen.value = true;
      return;
    }
  }

  populateLocalSiteForm(siteDraftFromRow(row), null);
  isLocalSiteModalOpen.value = true;
}

const hasSavedConfig = computed(() =>
  Boolean(settings.value?.safeline.base_url.trim()),
);

const totalMapped = computed(() => siteRows.value.filter((item) => item.saved).length);

const totalUnmapped = computed(
  () => siteRows.value.filter((item) => item.remote_present && !item.saved).length,
);

const totalOrphaned = computed(
  () => siteRows.value.filter((item) => item.orphaned).length,
);

const totalLocalOnly = computed(
  () => siteRows.value.filter((item) => item.row_kind === "local_only").length,
);

const totalMissingRemote = computed(
  () => siteRows.value.filter((item) => item.row_kind === "missing_remote").length,
);

const totalLocalSites = computed(() => localSites.value.length);

const totalLinkedSites = computed(
  () => siteLinks.value.filter((item) => item.provider === "safeline").length,
);

const totalSyncErrors = computed(
  () => siteLinks.value.filter((item) => Boolean(item.last_error)).length,
);

const primaryDraft = computed(
  () => siteRows.value.find((item) => item.safeline_site_id && item.is_primary) ?? null,
);

const filteredRows = computed(() => {
  const keyword = filters.keyword.trim().toLowerCase();

  return [...siteRows.value]
    .filter((item) => {
      if (filters.scope === "mapped" && !item.saved) return false;
      if (filters.scope === "unmapped" && (!item.remote_present || item.saved)) {
        return false;
      }
      if (filters.scope === "orphaned" && !item.orphaned) return false;
      if (filters.scope === "local_only" && item.row_kind !== "local_only") return false;
      if (filters.scope === "missing_remote" && item.row_kind !== "missing_remote") {
        return false;
      }

      if (filters.state === "enabled" && !item.enabled) return false;
      if (filters.state === "disabled" && item.enabled) return false;
      if (filters.state === "primary" && !item.is_primary) return false;

      if (!keyword) return true;

      return [
        item.local_alias,
        item.local_site_name,
        item.local_primary_hostname,
        item.safeline_site_name,
        item.safeline_site_domain,
        item.safeline_site_id,
        item.local_listen_ports.join(" "),
        item.local_upstreams.join(" "),
        item.server_names.join(" "),
        item.notes,
        item.local_notes,
        item.link_last_error ?? "",
      ]
        .join(" ")
        .toLowerCase()
        .includes(keyword);
    })
    .sort((left, right) => {
      if (left.is_primary !== right.is_primary) return left.is_primary ? -1 : 1;
      if (left.saved !== right.saved) return left.saved ? -1 : 1;
      if (left.remote_present !== right.remote_present) return left.remote_present ? -1 : 1;
      return (left.local_alias || left.local_site_name || left.safeline_site_name).localeCompare(
        right.local_alias || right.local_site_name || right.safeline_site_name,
        "zh-CN",
      );
    });
});

async function refreshCollections(remoteSource: "none" | "cached" | "live") {
  const [mappingsResponse, localSitesResponse, siteLinksResponse, remoteSitesResponse] =
    await Promise.all([
      fetchSafeLineMappings(),
      fetchLocalSites(),
      fetchSiteSyncLinks(),
      remoteSource === "live" && settings.value && hasSavedConfig.value
        ? fetchSafeLineSites(settings.value.safeline)
        : remoteSource === "cached"
          ? fetchCachedSafeLineSites()
        : Promise.resolve(null),
    ]);

  mappings.value = mappingsResponse.mappings;
  localSites.value = localSitesResponse.sites;
  siteLinks.value = siteLinksResponse.links;

  if (remoteSitesResponse) {
    sites.value = remoteSitesResponse.sites;
    sitesLoadedAt.value = remoteSitesResponse.cached_at;
  }

  rebuildRows();
}

async function loadLocalCertificates() {
  actions.loadingCertificates = true;

  try {
    const response = await fetchLocalCertificates();
    localCertificates.value = response.certificates;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "读取本地证书失败";
  } finally {
    actions.loadingCertificates = false;
  }
}

async function loadPageData() {
  loading.value = true;
  clearFeedback();

  try {
    settings.value = await fetchSettings();
    resetLocalSiteForm();
    await loadLocalCertificates();
    await refreshCollections("cached");
  } catch (e) {
    error.value = e instanceof Error ? e.message : "读取站点管理信息失败";
  } finally {
    loading.value = false;
  }
}

async function saveLocalSite() {
  actions.savingLocalSite = true;
  clearFeedback();

  try {
    const payload: LocalSiteDraft = {
      name: localSiteForm.name.trim(),
      primary_hostname: localSiteForm.primary_hostname.trim(),
      hostnames: localSiteForm.hostnames.map((item) => item.trim()).filter(Boolean),
      listen_ports: localSiteForm.listen_ports.map((item) => item.trim()).filter(Boolean),
      upstreams: localSiteForm.upstreams.map((item) => item.trim()).filter(Boolean),
      enabled: localSiteForm.enabled,
      tls_enabled: localSiteForm.tls_enabled,
      local_certificate_id: localSiteForm.local_certificate_id,
      source: "manual",
      sync_mode: localSiteForm.sync_mode.trim() || "manual",
      notes: localSiteForm.notes.trim(),
      last_synced_at: currentLocalSite.value?.last_synced_at ?? null,
    };

    if (editingLocalSiteId.value === null) {
      const created = await createLocalSite(payload);
      successMessage.value = `本地站点 ${created.name} 已创建。重启服务后生效。`;
      editingLocalSiteId.value = created.id;
    } else {
      const response = await updateLocalSite(editingLocalSiteId.value, payload);
      successMessage.value = response.message;
    }

    await refreshCollections(sitesLoadedAt.value !== null ? "cached" : "none");

    if (editingLocalSiteId.value !== null) {
      const updatedSite =
        localSites.value.find((item) => item.id === editingLocalSiteId.value) ?? null;
      if (updatedSite) {
        populateLocalSiteForm(siteDraftFromItem(updatedSite), updatedSite.id);
      }
    }

    closeLocalSiteModal();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "保存本地站点失败";
  } finally {
    actions.savingLocalSite = false;
  }
}

async function removeCurrentLocalSite() {
  if (editingLocalSiteId.value === null) return;

  actions.deletingLocalSite = true;
  clearFeedback();

  try {
    const response = await deleteLocalSite(editingLocalSiteId.value);
    successMessage.value = response.message;
    resetLocalSiteForm();
    await refreshCollections(sitesLoadedAt.value !== null ? "cached" : "none");
    closeLocalSiteModal();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "删除本地站点失败";
  } finally {
    actions.deletingLocalSite = false;
  }
}

async function refreshPageData() {
  actions.refreshing = true;
  clearFeedback();

  try {
    await refreshCollections(sitesLoadedAt.value !== null ? "cached" : "none");
    successMessage.value = "页面数据已刷新。";
  } catch (e) {
    error.value = e instanceof Error ? e.message : "刷新页面数据失败";
  } finally {
    actions.refreshing = false;
  }
}

async function runConnectionTest() {
  if (!settings.value) return;

  actions.testing = true;
  clearFeedback();

  try {
    testResult.value = await testSafeLineConnection(settings.value.safeline);
    successMessage.value = "连通性测试已完成。";
  } catch (e) {
    error.value = e instanceof Error ? e.message : "雷池连通性测试失败";
    testResult.value = null;
  } finally {
    actions.testing = false;
  }
}

async function loadRemoteSites() {
  if (!settings.value) return;

  actions.loadingSites = true;
  clearFeedback();

  try {
    const response = await fetchSafeLineSites(settings.value.safeline);
    sites.value = response.sites;
    sitesLoadedAt.value = response.cached_at ?? Math.floor(Date.now() / 1000);
    rebuildRows();
    successMessage.value = `已读取 ${response.total} 个雷池站点。`;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "读取雷池站点失败";
  } finally {
    actions.loadingSites = false;
  }
}

async function syncRemoteSite(row: SiteRowDraft) {
  if (!row.safeline_site_id) return;

  rowActions[row.row_key] = "pull";
  clearFeedback();

  try {
    const response = await pullSafeLineSite(row.safeline_site_id);
    await refreshCollections("live");
    successMessage.value = response.message;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "单站点回流失败";
  } finally {
    delete rowActions[row.row_key];
  }
}

async function syncLocalSite(row: SiteRowDraft) {
  if (!row.local_site_id) return;

  rowActions[row.row_key] = "push";
  clearFeedback();

  try {
    const response = await pushSafeLineSite(row.local_site_id);
    await refreshCollections("live");
    successMessage.value = response.message;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "单站点推送失败";
  } finally {
    delete rowActions[row.row_key];
  }
}

function rowActionPending(row: SiteRowDraft, action: "pull" | "push") {
  return rowActions[row.row_key] === action;
}

function rowBusy(row: SiteRowDraft) {
  return Boolean(rowActions[row.row_key]);
}

function remoteActionLabel(row: SiteRowDraft) {
  return row.local_present ? "从雷池更新" : "导入到本地";
}

function localActionLabel(row: SiteRowDraft) {
  if (row.row_kind === "missing_remote") return "重新创建到雷池";
  return row.remote_present && row.link_id ? "推送到雷池" : "创建到雷池";
}

function rowSyncText(row: SiteRowDraft) {
  if (row.link_last_error) return row.link_last_error;
  if (row.link_last_synced_at) return `最近同步：${formatTimestamp(row.link_last_synced_at)}`;
  if (row.remote_present && sitesLoadedAt.value) {
    return `远端读取：${formatTimestamp(sitesLoadedAt.value)}`;
  }
  if (row.local_updated_at) {
    return `本地更新：${formatTimestamp(row.local_updated_at)}`;
  }
  return "尚未执行单站点同步";
}

onMounted(loadPageData);
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <RouterLink
        to="/admin/safeline"
        class="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white shadow-sm transition hover:bg-blue-600/90"
      >
        <Link2 :size="12" />
        编辑映射
      </RouterLink>
    </template>

    <div class="min-w-0 space-y-4">
      <section class="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
        <div class="flex flex-col gap-3 2xl:flex-row 2xl:items-center 2xl:justify-between">
          <div class="flex flex-wrap gap-2">
            <button
              @click="refreshPageData"
              :disabled="actions.refreshing"
              class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <RefreshCw :size="14" :class="{ 'animate-spin': actions.refreshing }" />
              {{ actions.refreshing ? "刷新中..." : "刷新" }}
            </button>
            <button
              @click="runConnectionTest"
              :disabled="actions.testing || !hasSavedConfig"
              class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <PlugZap :size="14" :class="{ 'animate-pulse': actions.testing }" />
              {{ actions.testing ? "测试中..." : "测试连接" }}
            </button>
            <button
              @click="loadRemoteSites"
              :disabled="actions.loadingSites || !hasSavedConfig"
              class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <ServerCog :size="14" :class="{ 'animate-spin': actions.loadingSites }" />
              {{ actions.loadingSites ? "读取中..." : "读取远端" }}
            </button>
            <RouterLink
              to="/admin/settings"
              class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
            >
              <Settings2 :size="14" />
              系统设置
            </RouterLink>
          </div>

          <div class="flex flex-wrap gap-2">
            <StatusBadge
              :text="primaryDraft ? `主站点 ${primaryDraft.local_alias}` : '未设置主站点'"
              :type="primaryDraft ? 'info' : 'muted'"
              compact
            />
            <StatusBadge
              :text="sitesLoadedAt ? `远端已读取 ${formatNumber(sites.length)} 条` : '远端站点未读取'"
              :type="sitesLoadedAt ? 'success' : 'muted'"
              compact
            />
          </div>
        </div>

        <div class="mt-4 flex flex-nowrap items-end gap-3 overflow-x-auto">
          <label class="min-w-[18rem] flex-1 space-y-1.5">
            <span class="text-xs text-slate-500">搜索</span>
            <div class="relative">
              <Search
                class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                :size="14"
              />
              <input
                v-model="filters.keyword"
                type="text"
                placeholder="别名 / 本地域名 / 雷池域名 / 站点 ID / 备注"
                class="w-full rounded-lg border border-slate-200 bg-white px-9 py-2.5 text-sm outline-none transition focus:border-blue-500"
              />
            </div>
          </label>

          <label class="w-[11rem] shrink-0 space-y-1.5">
            <span class="text-xs text-slate-500">对账视图</span>
            <select
              v-model="filters.scope"
              class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
            >
              <option value="all">全部站点</option>
              <option value="mapped">只看已映射</option>
              <option value="unmapped">只看待建映射</option>
              <option value="orphaned">只看孤儿映射</option>
              <option value="local_only">只看仅本地</option>
              <option value="missing_remote">只看远端缺失</option>
            </select>
          </label>

          <label class="w-[11rem] shrink-0 space-y-1.5">
            <span class="text-xs text-slate-500">映射状态</span>
            <select
              v-model="filters.state"
              class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
            >
              <option value="all">全部状态</option>
              <option value="enabled">只看启用映射</option>
              <option value="disabled">只看停用映射</option>
              <option value="primary">只看主站点</option>
            </select>
          </label>
        </div>

        <div class="mt-3 flex flex-wrap gap-2">
          <StatusBadge
            :text="`当前列表 ${formatNumber(filteredRows.length)} 条`"
            type="info"
            compact
          />
          <StatusBadge
            :text="`已映射 ${formatNumber(totalMapped)} 条`"
            type="success"
            compact
          />
          <StatusBadge
            :text="`待建映射 ${formatNumber(totalUnmapped)} 条`"
            type="muted"
            compact
          />
          <StatusBadge
            :text="`孤儿映射 ${formatNumber(totalOrphaned)} 条`"
            type="warning"
            compact
          />
          <StatusBadge
            :text="`仅本地 ${formatNumber(totalLocalOnly)} 条`"
            type="info"
            compact
          />
          <StatusBadge
            :text="`远端缺失 ${formatNumber(totalMissingRemote)} 条`"
            type="warning"
            compact
          />
          <StatusBadge
            :text="`本地站点 ${formatNumber(totalLocalSites)} 条`"
            type="muted"
            compact
          />
          <StatusBadge
            :text="
              totalSyncErrors
                ? `链路 ${formatNumber(totalLinkedSites)} 条，错误 ${formatNumber(totalSyncErrors)} 条`
                : `链路 ${formatNumber(totalLinkedSites)} 条`
            "
            :type="totalSyncErrors ? 'warning' : 'muted'"
            compact
          />
        </div>

        <div
          class="mt-3 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600"
        >
          这个页面现在聚焦站点对账与同步操作。本地别名、主站点和映射启停请到
          <RouterLink to="/admin/safeline" class="font-medium text-blue-700 hover:underline">
            雷池联动
          </RouterLink>
          页面维护。
        </div>

        <div
          v-if="!hasSavedConfig"
          class="mt-3 rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600"
        >
          还没有保存雷池地址或鉴权参数，当前只能查看本地站点和本地映射。
        </div>

        <div
          v-if="testResult"
          class="mt-3 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600"
        >
          <div class="flex flex-wrap items-center gap-2">
            <StatusBadge
              :text="
                testResult.status === 'ok'
                  ? '连接测试通过'
                  : testResult.status === 'warning'
                    ? '连接测试需确认'
                    : '连接测试失败'
              "
              :type="
                testResult.status === 'ok'
                  ? 'success'
                  : testResult.status === 'warning'
                    ? 'warning'
                    : 'error'
              "
              compact
            />
            <span>{{ testResult.message }}</span>
          </div>
        </div>
      </section>

      <div
        v-if="error"
        class="rounded-xl border border-red-500/25 bg-red-500/8 px-4 py-3 text-sm text-red-600 shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

      <div
        v-if="successMessage"
        class="rounded-xl border border-emerald-300/60 bg-emerald-50 px-4 py-3 text-sm text-emerald-800 shadow-[0_14px_30px_rgba(16,185,129,0.08)]"
      >
        {{ successMessage }}
      </div>

      <div
        v-if="loading"
        class="rounded-xl border border-white/80 bg-white/75 px-4 py-6 text-center text-sm text-slate-500 shadow-sm"
      >
        正在读取站点管理数据...
      </div>

      <template v-else>
        <section class="rounded-2xl border border-slate-200 bg-white shadow-sm">
          <div class="flex flex-col gap-4 border-b border-slate-200 px-4 py-4 xl:flex-row xl:items-end xl:justify-between">
            <div>
              <p class="text-sm font-semibold text-stone-900">站点对账列表</p>
              <p class="mt-1 text-xs text-slate-500">
                按“本地站点、雷池站点、映射、同步链路”四类数据合并展示，方便排查缺链路、孤儿映射和双端配置漂移。
              </p>
            </div>
            <div class="flex flex-wrap items-center gap-3">
              <button
                @click="openCreateLocalSiteModal"
                class="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-2 text-xs font-medium text-white shadow-sm transition hover:bg-blue-600/90"
              >
                <Plus :size="14" />
                新建本地站点
              </button>
              <p class="text-xs text-slate-500">
                {{
                  sitesLoadedAt
                    ? `最近一次远端读取：${formatTimestamp(sitesLoadedAt)}`
                    : "还没有读取远端站点。"
                }}
              </p>
            </div>
          </div>

          <div
            v-if="filteredRows.length === 0"
            class="px-4 py-8 text-center text-sm text-slate-500"
          >
            当前筛选条件下没有可展示的站点。可以先读取远端站点，或者调整搜索与筛选条件。
          </div>

          <div v-else class="overflow-x-auto">
            <table class="w-full min-w-[1420px] text-left text-sm text-slate-700">
              <thead class="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th class="px-4 py-3 font-medium">站点标识</th>
                  <th class="px-4 py-3 font-medium">本地配置</th>
                  <th class="px-4 py-3 font-medium">雷池配置</th>
                  <th class="px-4 py-3 font-medium">同步状态</th>
                  <th class="px-4 py-3 font-medium">操作</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-200">
                <tr
                  v-for="row in filteredRows"
                  :key="row.row_key"
                  class="items-center transition hover:bg-slate-50/50"
                >
                  <td class="px-4 py-2">
                    <div class="space-y-1.5">
                      <div class="flex flex-wrap items-center gap-1.5">
                        <p
                          class="max-w-[220px] truncate font-medium text-stone-900"
                          :title="
                            row.local_alias ||
                            row.local_primary_hostname ||
                            row.safeline_site_domain ||
                            row.local_site_name
                          "
                        >
                          {{
                            row.local_alias ||
                            row.local_primary_hostname ||
                            row.safeline_site_domain ||
                            row.local_site_name ||
                            "未命名"
                          }}
                        </p>
                        <StatusBadge
                          v-if="row.saved"
                          text="已映射"
                          type="success"
                          compact
                        />
                        <StatusBadge
                          v-else-if="row.remote_present"
                          text="待建映射"
                          type="muted"
                          compact
                        />
                        <StatusBadge
                          v-if="row.is_primary"
                          text="主站点"
                          type="info"
                          compact
                        />
                        <StatusBadge
                          v-if="row.orphaned"
                          text="历史映射"
                          type="warning"
                          compact
                        />
                      </div>
                      <p class="text-xs text-slate-500">
                        {{
                          row.local_primary_hostname ||
                          row.safeline_site_domain ||
                          row.local_site_name ||
                          "暂无主机标识"
                        }}
                      </p>
                      <div class="flex flex-wrap gap-2 text-xs text-slate-400">
                        <span v-if="row.local_site_id" class="font-mono">
                          LOCAL:{{ row.local_site_id }}
                        </span>
                        <span v-if="row.safeline_site_id" class="font-mono">
                          SAFE:{{ row.safeline_site_id }}
                        </span>
                      </div>
                    </div>
                  </td>

                  <td class="px-4 py-2">
                    <div v-if="row.local_present" class="space-y-1.5">
                      <div class="flex flex-wrap items-center gap-1.5">
                        <span class="font-medium text-stone-900">{{ row.local_site_name }}</span>
                        <span class="font-mono text-[10px] text-slate-400">ID:{{ row.local_site_id }}</span>
                        <StatusBadge
                          :text="row.local_enabled ? '本地启用' : '本地停用'"
                          :type="row.local_enabled ? 'success' : 'warning'"
                          compact
                        />
                        <StatusBadge
                          :text="row.local_sync_mode ? `模式 ${syncModeLabel(row.local_sync_mode)}` : '模式未设置'"
                          type="muted"
                          compact
                        />
                        <StatusBadge
                          :text="row.local_upstreams.length ? '已配上游' : '未配上游'"
                          :type="row.local_upstreams.length ? 'info' : 'warning'"
                          compact
                        />
                      </div>
                      <div class="grid gap-1 text-xs text-slate-500">
                        <p class="truncate" :title="row.local_primary_hostname">
                          主域名：{{ row.local_primary_hostname || "未设置" }}
                        </p>
                        <p class="truncate" :title="row.local_hostnames.join(' / ')">
                          Hostnames：{{
                            row.local_hostnames.length
                              ? row.local_hostnames.join(" / ")
                              : "未设置"
                          }}
                        </p>
                        <p>
                          监听端口：{{
                            row.local_listen_ports.length
                              ? row.local_listen_ports.join(" / ")
                              : "未设置"
                          }}
                        </p>
                        <p class="truncate" :title="row.local_upstreams.join(' / ')">
                          Upstream：{{
                            row.local_upstreams.length
                              ? row.local_upstreams.join(" / ")
                              : "未设置"
                          }}
                        </p>
                      </div>
                    </div>
                    <p v-else class="text-xs text-slate-400 italic">未落本地站点</p>
                  </td>

                  <td class="px-4 py-2">
                    <div v-if="row.remote_present" class="space-y-1.5">
                      <div class="flex flex-wrap items-center gap-1.5">
                        <span class="font-medium text-stone-900">{{ row.safeline_site_name || "未命名" }}</span>
                        <span class="font-mono text-[10px] text-slate-400">ID:{{ row.safeline_site_id }}</span>
                        <StatusBadge
                          :text="remoteStatusText(row.status)"
                          :type="remoteStatusType(row.status)"
                          compact
                        />
                        <StatusBadge
                          :text="
                            row.remote_enabled === null
                              ? '未返回启停'
                              : row.remote_enabled
                                ? '远端启用'
                                : '远端停用'
                          "
                          :type="
                            row.remote_enabled === null
                              ? 'muted'
                              : row.remote_enabled
                                ? 'success'
                                : 'warning'
                          "
                          compact
                        />
                        <StatusBadge
                          :text="row.remote_ssl_enabled ? 'TLS' : '明文'"
                          :type="row.remote_ssl_enabled ? 'info' : 'muted'"
                          compact
                        />
                      </div>
                      <div class="grid gap-1 text-xs text-slate-500">
                        <p class="truncate" :title="row.safeline_site_domain">
                          域名：{{ row.safeline_site_domain || "未提供" }}
                        </p>
                        <p class="truncate" :title="row.server_names.join(' / ')">
                          Server Names：{{
                            row.server_names.length
                              ? row.server_names.join(" / ")
                              : "未提供"
                          }}
                        </p>
                        <p>
                          HTTP/HTTPS 端口：{{
                            row.remote_ports.length ? row.remote_ports.join(" / ") : "-"
                          }}
                          <span class="text-slate-300"> / </span>
                          {{
                            row.remote_ssl_ports.length
                              ? row.remote_ssl_ports.join(" / ")
                              : "-"
                          }}
                        </p>
                        <p class="truncate" :title="row.remote_upstreams.join(' / ')">
                          Upstream：{{
                            row.remote_upstreams.length
                              ? row.remote_upstreams.join(" / ")
                              : "未提供"
                          }}
                        </p>
                      </div>
                    </div>
                    <div v-else class="space-y-1">
                      <p class="text-xs text-slate-400 italic">雷池未见</p>
                      <span v-if="row.safeline_site_id" class="font-mono text-[10px] text-slate-400">ID:{{ row.safeline_site_id }}</span>
                    </div>
                  </td>

                  <td class="px-4 py-2">
                    <div class="space-y-2">
                      <div class="flex flex-wrap items-center gap-1.5">
                        <StatusBadge
                          :text="mappingStateText(row)"
                          :type="mappingStateType(row)"
                          compact
                        />
                        <StatusBadge
                          v-if="row.safeline_site_id"
                          :text="row.enabled ? '映射启用' : '映射停用'"
                          :type="row.enabled ? 'success' : 'warning'"
                          compact
                        />
                        <StatusBadge
                          :text="`同步 ${syncModeLabel(row.local_sync_mode)}`"
                          type="info"
                          compact
                        />
                      </div>
                      <div
                        v-if="row.link_last_error"
                        class="rounded-md border border-red-200 bg-red-50 px-2.5 py-2 text-xs text-red-700"
                      >
                        {{ row.link_last_error }}
                      </div>
                      <div v-else class="text-xs text-slate-500">
                        {{ rowSyncText(row) }}
                      </div>
                      <p
                        v-if="row.notes || row.local_notes"
                        class="text-xs text-slate-400"
                        :title="row.notes || row.local_notes"
                      >
                        备注：{{ row.notes || row.local_notes }}
                      </p>
                    </div>
                  </td>

                  <td class="px-4 py-2">
                    <div class="flex flex-wrap items-center gap-2">
                      <button
                        @click="editLocalSite(row)"
                        class="inline-flex h-8 items-center gap-1.5 rounded border border-slate-200 bg-white px-2.5 text-xs text-stone-700 transition hover:border-blue-400 hover:text-blue-700"
                      >
                        <PencilLine :size="14" />
                        <span>{{ row.local_present ? "编辑本地" : "新建本地" }}</span>
                      </button>

                      <button
                        v-if="row.remote_present"
                        @click="syncRemoteSite(row)"
                        :disabled="rowBusy(row) || !hasSavedConfig"
                        class="inline-flex h-8 items-center gap-1.5 rounded border border-emerald-200 bg-emerald-50 px-2.5 text-xs text-emerald-800 transition hover:border-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        <RefreshCw
                          :size="14"
                          :class="{ 'animate-spin': rowActionPending(row, 'pull') }"
                        />
                        <span>{{ remoteActionLabel(row) }}</span>
                      </button>

                      <button
                        v-if="row.local_present"
                        @click="syncLocalSite(row)"
                        :disabled="rowBusy(row) || !hasSavedConfig"
                        class="inline-flex h-8 items-center gap-1.5 rounded border border-amber-200 bg-amber-50 px-2.5 text-xs text-amber-900 transition hover:border-amber-400 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        <RefreshCw
                          :size="14"
                          :class="{ 'animate-spin': rowActionPending(row, 'push') }"
                        />
                        <span>{{ localActionLabel(row) }}</span>
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </template>
    </div>

    <div
      v-if="isLocalSiteModalOpen"
      class="fixed inset-0 z-[100] flex items-center justify-center p-4 md:p-6"
    >
      <div
        class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm"
        @click="closeLocalSiteModal"
      ></div>
      <div
        class="relative max-h-[calc(100vh-2rem)] w-full max-w-6xl overflow-y-auto rounded-[28px] border border-slate-200 bg-white shadow-[0_24px_80px_rgba(60,40,20,0.24)] md:max-h-[calc(100vh-3rem)]"
      >
        <div class="border-b border-slate-200 px-4 py-4 md:px-6">
          <div class="flex flex-col gap-3 xl:flex-row xl:items-end xl:justify-between">
            <div>
              <p class="text-sm font-semibold text-stone-900">{{ editorTitle }}</p>
              <p class="mt-1 text-xs text-slate-500">
                在这里直接维护本地运行站点。保存后会写入数据库，重启服务后生效。
              </p>
            </div>
            <div class="flex flex-wrap items-center gap-2">
              <StatusBadge
                :text="actions.loadingCertificates ? '证书读取中' : `可选证书 ${formatNumber(localCertificates.length)} 张`"
                :type="actions.loadingCertificates ? 'muted' : 'info'"
                compact
              />
              <StatusBadge
                :text="`本地站点 ${formatNumber(localSites.length)} 条`"
                type="muted"
                compact
              />
              <button
                @click="closeLocalSiteModal"
                class="flex h-10 w-10 items-center justify-center rounded-full border border-slate-200 bg-white/75 text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
              >
                <X :size="18" />
              </button>
            </div>
          </div>
        </div>

        <div class="grid gap-4 px-4 py-4 md:px-6 md:py-6 xl:grid-cols-[minmax(0,1.1fr)_minmax(22rem,0.9fr)]">
          <div class="space-y-4">
            <div class="grid gap-4 md:grid-cols-2">
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">站点名称</span>
                <input
                  v-model="localSiteForm.name"
                  type="text"
                  placeholder="例如 Portal"
                  class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">主域名</span>
                <input
                  v-model="localSiteForm.primary_hostname"
                  type="text"
                  placeholder="例如 portal.example.com"
                  class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
              <label class="space-y-1.5 md:col-span-2">
                <span class="text-xs text-slate-500">Hostnames</span>
                <input
                  v-model="hostnamesText"
                  type="text"
                  placeholder="多个域名用逗号分隔"
                  class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">监听端口</span>
                <input
                  v-model="listenPortsText"
                  type="text"
                  placeholder="例如 660"
                  class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">证书</span>
                <select
                  v-model="localSiteForm.local_certificate_id"
                  class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                >
                  <option :value="null">未设置</option>
                  <option
                    v-for="certificate in localCertificates"
                    :key="certificate.id"
                    :value="certificate.id"
                  >
                    #{{ certificate.id }} · {{ certificate.name }}
                  </option>
                </select>
              </label>
              <label class="space-y-1.5 md:col-span-2">
                <span class="text-xs text-slate-500">上游地址</span>
                <input
                  v-model="upstreamsText"
                  type="text"
                  placeholder="多个地址用逗号分隔，例如 127.0.0.1:880"
                  class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
                <span class="block text-xs text-slate-400">
                  当前运行时会优先使用第一个有效上游地址。
                </span>
              </label>
              <label class="space-y-1.5 md:col-span-2">
                <span class="text-xs text-slate-500">备注</span>
                <textarea
                  v-model="localSiteForm.notes"
                  rows="3"
                  class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
            </div>

            <div class="grid gap-3 md:grid-cols-3">
              <label
                class="flex items-start gap-2.5 rounded-lg border border-slate-200 bg-slate-50 p-3"
              >
                <input
                  v-model="localSiteForm.enabled"
                  type="checkbox"
                  class="mt-0.5 accent-blue-600"
                />
                <span>
                  <span class="block text-sm font-medium text-stone-900">启用站点</span>
                  <span class="mt-0.5 block text-xs text-slate-500">关闭后不会参与运行时匹配。</span>
                </span>
              </label>
              <label
                class="flex items-start gap-2.5 rounded-lg border border-slate-200 bg-slate-50 p-3"
              >
                <input
                  v-model="localSiteForm.tls_enabled"
                  type="checkbox"
                  class="mt-0.5 accent-blue-600"
                />
                <span>
                  <span class="block text-sm font-medium text-stone-900">启用 TLS 站点证书</span>
                  <span class="mt-0.5 block text-xs text-slate-500">启用后会参与 SNI 证书匹配。</span>
                </span>
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">同步模式</span>
                <select
                  v-model="localSiteForm.sync_mode"
                  class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
                >
                  <option value="manual">手动</option>
                  <option value="pull_only">仅回流</option>
                  <option value="push_only">仅推送</option>
                  <option value="bidirectional">双向同步</option>
                </select>
              </label>
            </div>

            <div class="flex flex-wrap items-center gap-2">
              <button
                @click="saveLocalSite"
                :disabled="actions.savingLocalSite"
                class="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-2 text-xs font-medium text-white shadow-sm transition hover:bg-blue-600/90 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <PencilLine :size="14" />
                {{ actions.savingLocalSite ? "保存中..." : editingLocalSiteId === null ? "创建本地站点" : "保存本地站点" }}
              </button>
              <button
                @click="resetLocalSiteForm"
                class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
              >
                <RotateCcw :size="14" />
                重置表单
              </button>
              <button
                v-if="editingLocalSiteId !== null"
                @click="removeCurrentLocalSite"
                :disabled="actions.deletingLocalSite"
                class="inline-flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs font-medium text-red-700 transition hover:border-red-400 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Trash2 :size="14" />
                {{ actions.deletingLocalSite ? "删除中..." : "删除本地站点" }}
              </button>
            </div>
          </div>

          <div class="space-y-3 rounded-xl border border-slate-200 bg-slate-50 p-4">
            <div>
              <p class="text-sm font-medium text-stone-900">编辑提示</p>
              <p class="mt-1 text-xs leading-5 text-slate-500">
                你可以直接从右侧对账列表点“编辑本地”带入，也可以手动新建。对同一个域名，建议统一走系统设置里的 HTTPS 入口端口。
              </p>
            </div>
            <div class="grid gap-2 text-xs text-slate-500">
              <p>监听端口：建议填统一入口端口，例如 `660`。</p>
              <p>证书：TLS 站点建议绑定真实证书；`IP:660` 回包用系统设置里的默认证书。</p>
              <p>上游地址：支持 `127.0.0.1:880` 或 `http://127.0.0.1:880`。</p>
              <p>保存后写入数据库，当前服务需要重启才会加载新的监听与站点路由。</p>
            </div>
            <div
              v-if="currentLocalSite"
              class="rounded-lg border border-slate-200 bg-white px-3 py-3 text-xs text-slate-500"
            >
              <p class="font-medium text-stone-900">{{ currentLocalSite.name }}</p>
              <p class="mt-1">最近更新：{{ formatTimestamp(currentLocalSite.updated_at) }}</p>
              <p class="mt-1">当前主域名：{{ currentLocalSite.primary_hostname }}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </AppLayout>
</template>
