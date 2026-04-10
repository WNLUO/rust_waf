<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import AppLayout from "../components/layout/AppLayout.vue";
import StatusBadge from "../components/ui/StatusBadge.vue";
import {
  fetchLocalSites,
  fetchSafeLineMappings,
  fetchSafeLineSites,
  fetchSiteSyncLinks,
  fetchSettings,
  pullSafeLineSite,
  pushSafeLineSite,
  testSafeLineConnection,
  updateSafeLineMappings,
} from "../lib/api";
import type {
  LocalSiteItem,
  SafeLineMappingItem,
  SafeLineSiteItem,
  SafeLineTestResponse,
  SettingsPayload,
  SiteSyncLinkItem,
} from "../lib/types";
import { useFormatters } from "../composables/useFormatters";
import {
  PlugZap,
  RefreshCw,
  Save,
  Search,
  ServerCog,
  Settings2,
  ShieldCheck,
} from "lucide-vue-next";

type ScopeFilter = "all" | "mapped" | "unmapped" | "orphaned" | "local_only";
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
const siteLinks = ref<SiteSyncLinkItem[]>([]);
const testResult = ref<SafeLineTestResponse | null>(null);
const siteRows = ref<SiteRowDraft[]>([]);
const sitesLoadedAt = ref<number | null>(null);

const actions = reactive({
  refreshing: false,
  testing: false,
  loadingSites: false,
  savingMappings: false,
});

const rowActions = reactive<Record<string, "pull" | "push" | undefined>>({});

const filters = reactive({
  keyword: "",
  scope: "all" as ScopeFilter,
  state: "all" as StateFilter,
});

function clearFeedback() {
  error.value = "";
  successMessage.value = "";
}

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

function selectPrimary(siteId: string) {
  for (const item of siteRows.value) {
    if (!item.safeline_site_id) continue;
    item.is_primary = item.safeline_site_id === siteId;
    if (item.is_primary) {
      item.enabled = true;
    }
  }
}

function clearPrimary() {
  for (const item of siteRows.value) {
    item.is_primary = false;
  }
}

function normalizeDraft(item: SiteRowDraft) {
  return {
    safeline_site_id: item.safeline_site_id.trim(),
    safeline_site_name: item.safeline_site_name.trim(),
    safeline_site_domain: item.safeline_site_domain.trim(),
    local_alias: item.local_alias.trim(),
    enabled: item.enabled,
    is_primary: item.is_primary,
    notes: item.notes.trim(),
  };
}

const hasSavedConfig = computed(() =>
  Boolean(settings.value?.safeline.base_url.trim()),
);

const hasPrimary = computed(() =>
  siteRows.value.some((item) => item.safeline_site_id && item.is_primary),
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

const draftPayload = computed(() =>
  siteRows.value
    .map(normalizeDraft)
    .filter((item) => item.safeline_site_id.length > 0),
);

const savedPayload = computed(() =>
  mappings.value.map((item) => ({
    safeline_site_id: item.safeline_site_id.trim(),
    safeline_site_name: item.safeline_site_name.trim(),
    safeline_site_domain: item.safeline_site_domain.trim(),
    local_alias: item.local_alias.trim(),
    enabled: item.enabled,
    is_primary: item.is_primary,
    notes: item.notes.trim(),
  })),
);

function serializeMappings(
  value: Array<{
    safeline_site_id: string;
    safeline_site_name: string;
    safeline_site_domain: string;
    local_alias: string;
    enabled: boolean;
    is_primary: boolean;
    notes: string;
  }>,
) {
  return JSON.stringify(
    [...value].sort((left, right) =>
      left.safeline_site_id.localeCompare(right.safeline_site_id, "zh-CN"),
    ),
  );
}

const hasDraftChanges = computed(
  () => serializeMappings(draftPayload.value) !== serializeMappings(savedPayload.value),
);

const validationError = computed(() => {
  const seenIds = new Set<string>();
  let primaryCount = 0;

  for (const item of draftPayload.value) {
    if (!item.safeline_site_id) {
      return "存在缺少雷池站点 ID 的记录，暂时无法保存。";
    }
    if (seenIds.has(item.safeline_site_id)) {
      return `雷池站点 ${item.safeline_site_id} 出现了重复映射，请先整理后再保存。`;
    }
    if (!item.local_alias) {
      return `站点 ${item.safeline_site_id} 的本地别名不能为空。`;
    }
    if (item.is_primary) {
      primaryCount += 1;
      if (!item.enabled) {
        return "主站点映射必须保持启用。";
      }
    }
    seenIds.add(item.safeline_site_id);
  }

  if (primaryCount > 1) {
    return "同一时间只能设置一个主站点。";
  }

  return "";
});

const canSave = computed(
  () =>
    !loading.value &&
    !actions.savingMappings &&
    !validationError.value &&
    hasDraftChanges.value,
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

async function refreshCollections(includeRemote: boolean) {
  const [mappingsResponse, localSitesResponse, siteLinksResponse, remoteSitesResponse] =
    await Promise.all([
      fetchSafeLineMappings(),
      fetchLocalSites(),
      fetchSiteSyncLinks(),
      includeRemote && settings.value && hasSavedConfig.value
        ? fetchSafeLineSites(settings.value.safeline)
        : Promise.resolve(null),
    ]);

  mappings.value = mappingsResponse.mappings;
  localSites.value = localSitesResponse.sites;
  siteLinks.value = siteLinksResponse.links;

  if (remoteSitesResponse) {
    sites.value = remoteSitesResponse.sites;
    sitesLoadedAt.value = Math.floor(Date.now() / 1000);
  }

  rebuildRows();
}

async function loadPageData() {
  loading.value = true;
  clearFeedback();

  try {
    settings.value = await fetchSettings();
    await refreshCollections(false);
  } catch (e) {
    error.value = e instanceof Error ? e.message : "读取站点管理信息失败";
  } finally {
    loading.value = false;
  }
}

async function refreshPageData() {
  actions.refreshing = true;
  clearFeedback();

  try {
    await refreshCollections(sitesLoadedAt.value !== null);
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
    sitesLoadedAt.value = Math.floor(Date.now() / 1000);
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
    await refreshCollections(true);
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
    await refreshCollections(true);
    successMessage.value = response.message;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "单站点推送失败";
  } finally {
    delete rowActions[row.row_key];
  }
}

async function saveMappings() {
  if (validationError.value) {
    error.value = validationError.value;
    return;
  }

  actions.savingMappings = true;
  clearFeedback();

  try {
    await updateSafeLineMappings({
      mappings: draftPayload.value,
    });

    const mappingsResponse = await fetchSafeLineMappings();
    mappings.value = mappingsResponse.mappings;
    rebuildRows();
    successMessage.value = "站点映射已保存到后端数据库。";
  } catch (e) {
    error.value = e instanceof Error ? e.message : "保存站点映射失败";
  } finally {
    actions.savingMappings = false;
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
      <button
        @click="saveMappings"
        :disabled="!canSave"
        class="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white shadow-sm transition hover:bg-blue-600/90 disabled:cursor-not-allowed disabled:opacity-60"
      >
        <Save :size="12" />
        {{ actions.savingMappings ? "保存中..." : "保存映射" }}
      </button>
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
            <button
              v-if="hasPrimary"
              @click="clearPrimary"
              class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-amber-500/40 hover:text-amber-700"
            >
              清空主站点
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
              :text="hasDraftChanges ? '存在未保存改动' : '已与数据库同步'"
              :type="hasDraftChanges ? 'warning' : 'success'"
              compact
            />
            <StatusBadge
              :text="validationError || '校验通过'"
              :type="validationError ? 'error' : 'info'"
              compact
            />
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
            <span class="text-xs text-slate-500">纳管状态</span>
            <select
              v-model="filters.scope"
              class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
            >
              <option value="all">全部站点</option>
              <option value="mapped">只看已映射</option>
              <option value="unmapped">只看待纳管</option>
              <option value="orphaned">只看孤儿映射</option>
              <option value="local_only">只看仅本地</option>
            </select>
          </label>

          <label class="w-[11rem] shrink-0 space-y-1.5">
            <span class="text-xs text-slate-500">运行状态</span>
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
            :text="`待纳管 ${formatNumber(totalUnmapped)} 条`"
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
              <p class="text-sm font-semibold text-stone-900">站点列表</p>
              <p class="mt-1 text-xs leading-5 text-slate-500">
                一行代表一个站点视图。这里只做映射维护和单站点同步，不再提供批量回流或批量推送。
              </p>
            </div>
            <p class="text-xs text-slate-500">
              {{
                sitesLoadedAt
                  ? `最近一次远端读取：${formatTimestamp(sitesLoadedAt)}`
                  : "还没有读取远端站点。"
              }}
            </p>
          </div>

          <div
            v-if="filteredRows.length === 0"
            class="px-4 py-8 text-center text-sm text-slate-500"
          >
            当前筛选条件下没有可展示的站点。可以先读取远端站点，或者调整搜索与筛选条件。
          </div>

          <div v-else class="overflow-x-auto">
            <table class="w-full min-w-[1180px] text-left text-sm text-slate-700">
              <thead class="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th class="px-4 py-3 font-medium">名称 / 别名</th>
                  <th class="px-4 py-3 font-medium">本地站点</th>
                  <th class="px-4 py-3 font-medium">雷池站点</th>
                  <th class="px-4 py-3 font-medium">状态</th>
                  <th class="px-4 py-3 font-medium">备注</th>
                  <th class="px-4 py-3 font-medium">操作</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-200">
                <tr
                  v-for="row in filteredRows"
                  :key="row.row_key"
                  class="align-top"
                >
                  <td class="px-4 py-4">
                    <div v-if="row.safeline_site_id" class="space-y-2">
                      <input
                        v-model="row.local_alias"
                        type="text"
                        class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-stone-900 outline-none transition focus:border-blue-500"
                        placeholder="输入本地别名"
                      />
                      <p class="text-xs text-slate-500">
                        用于事件识别和主站点选择。
                      </p>
                    </div>
                    <div v-else class="space-y-1">
                      <p class="font-medium text-stone-900">
                        {{ row.local_site_name || "未命名本地站点" }}
                      </p>
                      <p class="text-xs text-slate-500">
                        仅本地站点，不能保存雷池映射。
                      </p>
                    </div>
                  </td>

                  <td class="px-4 py-4">
                    <div v-if="row.local_present" class="space-y-1.5">
                      <p class="font-medium text-stone-900">
                        {{ row.local_site_name }}
                      </p>
                      <p class="font-mono text-xs text-slate-500">
                        local={{ row.local_site_id }}
                      </p>
                      <p class="break-all text-xs text-slate-500">
                        {{ row.local_primary_hostname }}
                      </p>
                      <p
                        v-if="row.local_listen_ports.length"
                        class="text-xs text-slate-500"
                      >
                        端口：{{ row.local_listen_ports.join(" / ") }}
                      </p>
                    </div>
                    <p v-else class="text-xs text-slate-500">未落库到本地</p>
                  </td>

                  <td class="px-4 py-4">
                    <div v-if="row.remote_present" class="space-y-1.5">
                      <p class="font-medium text-stone-900">
                        {{ row.safeline_site_name || "未返回名称" }}
                      </p>
                      <p class="font-mono text-xs text-slate-500">
                        remote={{ row.safeline_site_id }}
                      </p>
                      <p class="break-all text-xs text-slate-500">
                        {{ row.safeline_site_domain || "未返回域名" }}
                      </p>
                      <p
                        v-if="row.server_names.length"
                        class="break-all text-xs text-slate-500"
                      >
                        Server Names：{{ row.server_names.join(" / ") }}
                      </p>
                    </div>
                    <div v-else class="space-y-1">
                      <p class="text-xs text-slate-500">当前未出现在雷池列表</p>
                      <p
                        v-if="row.safeline_site_id"
                        class="font-mono text-xs text-slate-500"
                      >
                        记录中的 remote={{ row.safeline_site_id }}
                      </p>
                    </div>
                  </td>

                  <td class="px-4 py-4">
                    <div class="flex flex-wrap gap-2">
                      <StatusBadge
                        :text="mappingStateText(row)"
                        :type="mappingStateType(row)"
                        compact
                      />
                      <StatusBadge
                        v-if="row.remote_present"
                        :text="remoteStatusText(row.status)"
                        :type="remoteStatusType(row.status)"
                        compact
                      />
                      <StatusBadge
                        v-else-if="row.local_present"
                        :text="row.local_enabled ? '本地启用' : '本地停用'"
                        :type="row.local_enabled ? 'success' : 'warning'"
                        compact
                      />
                      <StatusBadge
                        v-if="row.is_primary"
                        text="主站点"
                        type="info"
                        compact
                      />
                      <StatusBadge
                        v-if="row.safeline_site_id && !row.enabled"
                        text="映射已停用"
                        type="warning"
                        compact
                      />
                    </div>
                    <p
                      class="mt-2 max-w-[24rem] text-xs leading-5"
                      :class="row.link_last_error ? 'text-red-600' : 'text-slate-500'"
                    >
                      {{ rowSyncText(row) }}
                    </p>
                  </td>

                  <td class="px-4 py-4">
                    <textarea
                      v-if="row.safeline_site_id"
                      v-model="row.notes"
                      rows="3"
                      class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                      placeholder="例如：核心业务、灰度入口、海外站点等"
                    />
                    <p
                      v-else
                      class="whitespace-pre-wrap text-sm leading-6 text-slate-600"
                    >
                      {{ row.local_notes || "无本地备注" }}
                    </p>
                  </td>

                  <td class="px-4 py-4">
                    <div class="flex min-w-[220px] flex-col gap-2">
                      <button
                        v-if="row.remote_present"
                        @click="syncRemoteSite(row)"
                        :disabled="rowBusy(row) || !hasSavedConfig"
                        class="inline-flex items-center justify-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs font-medium text-emerald-800 transition hover:border-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        <RefreshCw
                          :size="14"
                          :class="{ 'animate-spin': rowActionPending(row, 'pull') }"
                        />
                        {{
                          rowActionPending(row, "pull")
                            ? "处理中..."
                            : remoteActionLabel(row)
                        }}
                      </button>

                      <button
                        v-if="row.local_present"
                        @click="syncLocalSite(row)"
                        :disabled="rowBusy(row) || !hasSavedConfig"
                        class="inline-flex items-center justify-center gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs font-medium text-amber-900 transition hover:border-amber-400 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        <RefreshCw
                          :size="14"
                          :class="{ 'animate-spin': rowActionPending(row, 'push') }"
                        />
                        {{
                          rowActionPending(row, "push")
                            ? "处理中..."
                            : localActionLabel(row)
                        }}
                      </button>

                      <button
                        v-if="row.safeline_site_id"
                        @click="selectPrimary(row.safeline_site_id)"
                        class="inline-flex items-center justify-center gap-2 rounded-lg border px-3 py-2 text-xs font-medium transition"
                        :class="
                          row.is_primary
                            ? 'border-blue-500/30 bg-blue-50 text-blue-700'
                            : 'border-slate-200 bg-white text-stone-700 hover:border-blue-500/40 hover:text-blue-700'
                        "
                      >
                        <ShieldCheck :size="14" />
                        {{ row.is_primary ? "当前主站点" : "设为主站点" }}
                      </button>

                      <label
                        v-if="row.safeline_site_id"
                        class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs text-stone-700"
                      >
                        <input
                          v-model="row.enabled"
                          type="checkbox"
                          class="accent-blue-600"
                        />
                        启用映射
                      </label>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </template>
    </div>
  </AppLayout>
</template>
