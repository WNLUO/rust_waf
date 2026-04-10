<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import AppLayout from "../components/layout/AppLayout.vue";
import StatusBadge from "../components/ui/StatusBadge.vue";
import {
  fetchSafeLineMappings,
  fetchSafeLineSites,
  fetchSettings,
  testSafeLineConnection,
  updateSafeLineMappings,
} from "../lib/api";
import type {
  SafeLineMappingItem,
  SafeLineSiteItem,
  SafeLineTestResponse,
  SettingsPayload,
} from "../lib/types";
import { useFormatters } from "../composables/useFormatters";
import {
  AppWindow,
  Link2,
  PlugZap,
  RefreshCw,
  Save,
  Search,
  ServerCog,
  Settings2,
  ShieldCheck,
} from "lucide-vue-next";

interface SiteMappingDraft {
  safeline_site_id: string;
  safeline_site_name: string;
  safeline_site_domain: string;
  remote_enabled: boolean | null;
  server_names: string[];
  ports: string[];
  ssl_ports: string[];
  upstreams: string[];
  ssl_enabled: boolean;
  cert_id: number | null;
  cert_type: number | null;
  cert_filename: string | null;
  key_filename: string | null;
  health_check: boolean | null;
  local_alias: string;
  enabled: boolean;
  is_primary: boolean;
  notes: string;
  updated_at: number | null;
  orphaned: boolean;
  saved: boolean;
  status: string;
}

type ScopeFilter = "all" | "mapped" | "unmapped" | "orphaned";
type StateFilter = "all" | "enabled" | "disabled" | "primary";

const { formatNumber, formatTimestamp } = useFormatters();

const loading = ref(true);
const error = ref("");
const successMessage = ref("");
const settings = ref<SettingsPayload | null>(null);
const mappings = ref<SafeLineMappingItem[]>([]);
const sites = ref<SafeLineSiteItem[]>([]);
const testResult = ref<SafeLineTestResponse | null>(null);
const mappingDrafts = ref<SiteMappingDraft[]>([]);
const sitesLoadedAt = ref<number | null>(null);

const actions = reactive({
  refreshing: false,
  testing: false,
  loadingSites: false,
  savingMappings: false,
});

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
  if (!status.trim()) return "状态未知";
  if (isSiteOnline(status)) return `远端在线 · ${status}`;
  if (isSiteOffline(status)) return `远端停用 · ${status}`;
  return `远端状态 · ${status}`;
}

function mergeMappingDrafts(
  siteList: SafeLineSiteItem[],
  mappingList: SafeLineMappingItem[],
) {
  const nextDrafts: SiteMappingDraft[] = siteList.map((site) => {
    const existing = mappingList.find(
      (item) => item.safeline_site_id === site.id,
    );

    return {
      safeline_site_id: site.id,
      safeline_site_name: site.name,
      safeline_site_domain: site.domain,
      remote_enabled: site.enabled,
      server_names: site.server_names,
      ports: site.ports,
      ssl_ports: site.ssl_ports,
      upstreams: site.upstreams,
      ssl_enabled: site.ssl_enabled,
      cert_id: site.cert_id,
      cert_type: site.cert_type,
      cert_filename: site.cert_filename,
      key_filename: site.key_filename,
      health_check: site.health_check,
      local_alias: existing?.local_alias ?? site.name ?? site.domain ?? "",
      enabled: existing?.enabled ?? true,
      is_primary: existing?.is_primary ?? false,
      notes: existing?.notes ?? "",
      updated_at: existing?.updated_at ?? null,
      orphaned: false,
      saved: Boolean(existing),
      status: site.status,
    };
  });

  const existingIds = new Set(nextDrafts.map((item) => item.safeline_site_id));
  for (const item of mappingList) {
    if (existingIds.has(item.safeline_site_id)) continue;
    nextDrafts.push({
      safeline_site_id: item.safeline_site_id,
      safeline_site_name: item.safeline_site_name,
      safeline_site_domain: item.safeline_site_domain,
      remote_enabled: null,
      server_names: [],
      ports: [],
      ssl_ports: [],
      upstreams: [],
      ssl_enabled: false,
      cert_id: null,
      cert_type: null,
      cert_filename: null,
      key_filename: null,
      health_check: null,
      local_alias: item.local_alias,
      enabled: item.enabled,
      is_primary: item.is_primary,
      notes: item.notes,
      updated_at: item.updated_at ?? null,
      orphaned: true,
      saved: true,
      status: "",
    });
  }

  mappingDrafts.value = nextDrafts;
}

function mappingStateText(item: SiteMappingDraft) {
  if (item.orphaned) return "孤儿映射";
  if (item.saved) return "已映射";
  return "待纳管";
}

function mappingStateType(item: SiteMappingDraft) {
  if (item.orphaned) return "warning";
  if (item.saved) return "success";
  return "muted";
}

function selectPrimary(siteId: string) {
  for (const item of mappingDrafts.value) {
    item.is_primary = item.safeline_site_id === siteId;
    if (item.is_primary) {
      item.enabled = true;
    }
  }
}

function clearPrimary() {
  for (const item of mappingDrafts.value) {
    item.is_primary = false;
  }
}

function normalizeDraft(item: SiteMappingDraft) {
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

const authMode = computed(() => {
  if (settings.value?.safeline.api_token.trim()) return "API Token";
  if (
    settings.value?.safeline.username.trim() &&
    settings.value?.safeline.password.trim()
  ) {
    return "账号密码";
  }
  return "未配置鉴权";
});

const hasPrimary = computed(() =>
  mappingDrafts.value.some((item) => item.is_primary),
);

const totalMapped = computed(
  () => mappingDrafts.value.filter((item) => item.saved).length,
);

const totalUnmapped = computed(
  () =>
    mappingDrafts.value.filter((item) => !item.saved && !item.orphaned).length,
);

const totalOrphaned = computed(
  () => mappingDrafts.value.filter((item) => item.orphaned).length,
);

const totalEnabled = computed(
  () => mappingDrafts.value.filter((item) => item.enabled).length,
);

const totalSslSites = computed(
  () => mappingDrafts.value.filter((item) => item.ssl_enabled).length,
);

const primaryDraft = computed(
  () => mappingDrafts.value.find((item) => item.is_primary) ?? null,
);

const draftPayload = computed(() =>
  mappingDrafts.value
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

const filteredDrafts = computed(() => {
  const keyword = filters.keyword.trim().toLowerCase();

  return [...mappingDrafts.value]
    .filter((item) => {
      if (filters.scope === "mapped" && !item.saved) return false;
      if (
        filters.scope === "unmapped" &&
        (item.saved || item.orphaned)
      ) {
        return false;
      }
      if (filters.scope === "orphaned" && !item.orphaned) return false;

      if (filters.state === "enabled" && !item.enabled) return false;
      if (filters.state === "disabled" && item.enabled) return false;
      if (filters.state === "primary" && !item.is_primary) return false;

      if (!keyword) return true;

      return [
        item.local_alias,
        item.safeline_site_name,
        item.safeline_site_domain,
        item.safeline_site_id,
        item.ports.join(" "),
        item.server_names.join(" "),
        item.upstreams.join(" "),
        item.cert_filename ?? "",
        item.key_filename ?? "",
        item.notes,
      ]
        .join(" ")
        .toLowerCase()
        .includes(keyword);
    })
    .sort((left, right) => {
      if (left.is_primary !== right.is_primary) return left.is_primary ? -1 : 1;
      if (left.saved !== right.saved) return left.saved ? -1 : 1;
      if (left.enabled !== right.enabled) return left.enabled ? -1 : 1;
      if (left.orphaned !== right.orphaned) return left.orphaned ? 1 : -1;
      return left.local_alias.localeCompare(right.local_alias, "zh-CN");
    });
});

async function loadPageData() {
  loading.value = true;
  clearFeedback();

  try {
    const [settingsResponse, mappingsResponse] = await Promise.all([
      fetchSettings(),
      fetchSafeLineMappings(),
    ]);

    settings.value = settingsResponse;
    mappings.value = mappingsResponse.mappings;
    mergeMappingDrafts(sites.value, mappings.value);
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
    await loadPageData();
    successMessage.value = "页面数据已刷新。";
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
    mergeMappingDrafts(sites.value, mappings.value);
    successMessage.value = `已读取 ${response.total} 个雷池站点。`;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "读取雷池站点失败";
  } finally {
    actions.loadingSites = false;
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
    mergeMappingDrafts(sites.value, mappings.value);
    successMessage.value = "站点映射已保存到后端数据库。";
  } catch (e) {
    error.value = e instanceof Error ? e.message : "保存站点映射失败";
  } finally {
    actions.savingMappings = false;
  }
}

function listPreview(values: string[], fallback = "未配置") {
  return values.length ? values.join(" / ") : fallback;
}

function sslStateText(site: SiteMappingDraft) {
  if (!site.ssl_enabled) return "未绑定 HTTPS";
  if (site.cert_id !== null) return `HTTPS 已启用 · 证书 #${site.cert_id}`;
  if (site.cert_filename) return `HTTPS 已启用 · ${site.cert_filename}`;
  return "HTTPS 已启用";
}

function sslStateType(site: SiteMappingDraft) {
  return site.ssl_enabled ? "success" : "muted";
}

function certBindingText(site: SiteMappingDraft) {
  if (site.cert_id !== null) {
    const type = site.cert_type !== null ? `类型 ${site.cert_type}` : "类型未知";
    return `证书 #${site.cert_id} · ${type}`;
  }
  if (site.cert_filename || site.key_filename) {
    return [site.cert_filename, site.key_filename].filter(Boolean).join(" / ");
  }
  return "未返回证书绑定";
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

    <div class="min-w-0 space-y-6">
      <section
        class="rounded-[28px] border border-white/80 bg-[linear-gradient(135deg,rgba(248,250,252,0.96),rgba(255,255,255,0.88))] p-5 shadow-[0_20px_45px_rgba(90,60,30,0.08)]"
      >
        <div class="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
          <div class="max-w-3xl">
            <div class="flex items-center gap-3">
              <div
                class="flex h-11 w-11 items-center justify-center rounded-2xl bg-blue-50 text-blue-700 shadow-sm"
              >
                <AppWindow :size="20" />
              </div>
              <div>
                <p class="text-xs tracking-[0.24em] text-blue-700">
                  SITE CONTROL
                </p>
                <h1 class="mt-1 text-2xl font-semibold tracking-tight text-stone-900">
                  站点管理
                </h1>
              </div>
            </div>

            <p class="mt-4 max-w-2xl text-sm leading-6 text-slate-600">
              这一页聚合了后端已保存的雷池接入配置、远端站点读取结果以及本地站点映射编辑。你可以在这里统一完成站点纳管、主站点选择和备注维护。
            </p>

            <div class="mt-4 flex flex-wrap gap-2.5">
              <button
                @click="refreshPageData"
                :disabled="actions.refreshing"
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/80 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <RefreshCw :size="14" :class="{ 'animate-spin': actions.refreshing }" />
                {{ actions.refreshing ? "刷新中..." : "刷新页面数据" }}
              </button>
              <button
                @click="runConnectionTest"
                :disabled="actions.testing || !hasSavedConfig"
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/80 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <PlugZap :size="14" :class="{ 'animate-pulse': actions.testing }" />
                {{ actions.testing ? "测试中..." : "测试雷池连接" }}
              </button>
              <button
                @click="loadRemoteSites"
                :disabled="actions.loadingSites || !hasSavedConfig"
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/80 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <ServerCog :size="14" :class="{ 'animate-spin': actions.loadingSites }" />
                {{ actions.loadingSites ? "读取中..." : "读取远端站点" }}
              </button>
              <RouterLink
                to="/admin/settings"
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/80 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
              >
                <Settings2 :size="14" />
                前往系统设置
              </RouterLink>
            </div>
          </div>

          <div
            class="grid min-w-0 gap-3 sm:grid-cols-2 xl:w-[28rem]"
          >
            <div class="rounded-2xl border border-slate-200 bg-white/80 p-4">
              <p class="text-xs text-slate-500">当前主站点</p>
              <p class="mt-2 text-sm font-semibold text-stone-900">
                {{ primaryDraft?.local_alias || "尚未设置" }}
              </p>
              <p class="mt-1 text-xs text-slate-500">
                {{
                  primaryDraft?.safeline_site_domain ||
                  primaryDraft?.safeline_site_name ||
                  "保存映射后将用于统一识别站点。"
                }}
              </p>
            </div>
            <div class="rounded-2xl border border-slate-200 bg-white/80 p-4">
              <p class="text-xs text-slate-500">页面状态</p>
              <div class="mt-2 flex flex-wrap gap-2">
                <StatusBadge
                  :text="hasDraftChanges ? '存在未保存改动' : '与数据库一致'"
                  :type="hasDraftChanges ? 'warning' : 'success'"
                  compact
                />
                <StatusBadge
                  :text="validationError || '校验通过'"
                  :type="validationError ? 'error' : 'info'"
                  compact
                />
              </div>
            </div>
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
        <section class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <article
            class="rounded-2xl border border-white/80 bg-white/80 p-4 shadow-[0_14px_30px_rgba(90,60,30,0.06)]"
          >
            <p class="text-xs text-slate-500">远端站点</p>
            <p class="mt-2 text-2xl font-semibold tracking-tight text-stone-900">
              {{ sites.length ? formatNumber(sites.length) : "未读取" }}
            </p>
            <p class="mt-1 text-xs text-slate-500">
              {{
                sitesLoadedAt
                  ? `最近读取：${formatTimestamp(sitesLoadedAt)}`
                  : "使用“读取远端站点”从雷池加载最新站点。"
              }}
            </p>
          </article>

          <article
            class="rounded-2xl border border-white/80 bg-white/80 p-4 shadow-[0_14px_30px_rgba(90,60,30,0.06)]"
          >
            <p class="text-xs text-slate-500">已保存映射</p>
            <p class="mt-2 text-2xl font-semibold tracking-tight text-stone-900">
              {{ formatNumber(totalMapped) }}
            </p>
            <p class="mt-1 text-xs text-slate-500">
              含 {{ formatNumber(totalEnabled) }} 个启用映射，{{ hasPrimary ? "已" : "未" }}设置主站点。
            </p>
          </article>

          <article
            class="rounded-2xl border border-white/80 bg-white/80 p-4 shadow-[0_14px_30px_rgba(90,60,30,0.06)]"
          >
            <p class="text-xs text-slate-500">待纳管站点</p>
            <p class="mt-2 text-2xl font-semibold tracking-tight text-stone-900">
              {{ formatNumber(totalUnmapped) }}
            </p>
            <p class="mt-1 text-xs text-slate-500">
              这些站点已从远端读取，但尚未保存到本地映射表。
            </p>
          </article>

          <article
            class="rounded-2xl border border-white/80 bg-white/80 p-4 shadow-[0_14px_30px_rgba(90,60,30,0.06)]"
          >
            <p class="text-xs text-slate-500">孤儿映射</p>
            <p class="mt-2 text-2xl font-semibold tracking-tight text-stone-900">
              {{ formatNumber(totalOrphaned) }}
            </p>
            <p class="mt-1 text-xs text-slate-500">
              数据库里还在，但本次远端列表未返回对应站点。
            </p>
          </article>
        </section>

        <section class="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
          <div
            class="rounded-2xl border border-white/80 bg-white/80 p-5 shadow-[0_14px_30px_rgba(90,60,30,0.06)]"
          >
            <div class="flex items-center justify-between gap-3">
              <div>
                <p class="text-sm font-semibold text-stone-900">接入配置概览</p>
                <p class="mt-1 text-xs leading-5 text-slate-500">
                  这里展示的是后端数据库当前保存的雷池接入参数。
                </p>
              </div>
              <StatusBadge
                :text="settings?.safeline.enabled ? '集成已启用' : '集成未启用'"
                :type="settings?.safeline.enabled ? 'success' : 'warning'"
                compact
              />
            </div>

            <div class="mt-4 grid gap-3 md:grid-cols-2">
              <div class="rounded-2xl bg-slate-50 p-4">
                <p class="text-xs text-slate-500">雷池地址</p>
                <p class="mt-2 break-all text-sm font-medium text-stone-900">
                  {{ settings?.safeline.base_url || "未配置" }}
                </p>
              </div>
              <div class="rounded-2xl bg-slate-50 p-4">
                <p class="text-xs text-slate-500">鉴权方式</p>
                <p class="mt-2 text-sm font-medium text-stone-900">
                  {{ authMode }}
                </p>
              </div>
              <div class="rounded-2xl bg-slate-50 p-4">
                <p class="text-xs text-slate-500">站点列表路径</p>
                <p class="mt-2 break-all font-mono text-xs text-stone-900">
                  {{ settings?.safeline.site_list_path || "未配置" }}
                </p>
              </div>
              <div class="rounded-2xl bg-slate-50 p-4">
                <p class="text-xs text-slate-500">自动同步周期</p>
                <p class="mt-2 text-sm font-medium text-stone-900">
                  {{
                    settings?.safeline.auto_sync_interval_secs
                      ? `${formatNumber(settings.safeline.auto_sync_interval_secs)} 秒`
                      : "未配置"
                  }}
                </p>
              </div>
            </div>

            <div
              v-if="!hasSavedConfig"
              class="mt-4 rounded-2xl border border-dashed border-slate-200 bg-white px-4 py-3 text-sm leading-6 text-slate-500"
            >
              还没有保存雷池地址或鉴权参数，当前只能查看已存在的本地映射。先去系统设置完成接入，再回来读取远端站点。
            </div>
          </div>

          <div
            class="rounded-2xl border border-white/80 bg-white/80 p-5 shadow-[0_14px_30px_rgba(90,60,30,0.06)]"
          >
            <div class="flex items-center justify-between gap-3">
              <div>
                <p class="text-sm font-semibold text-stone-900">连接自检</p>
                <p class="mt-1 text-xs leading-5 text-slate-500">
                  检查文档入口和鉴权探测是否能正常访问。
                </p>
              </div>
              <ShieldCheck class="text-blue-700" :size="18" />
            </div>

            <div
              v-if="testResult"
              class="mt-4 rounded-2xl border border-slate-200 bg-slate-50 p-4"
            >
              <div class="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p class="text-sm font-medium text-stone-900">
                    最近一次测试结果
                  </p>
                  <p class="mt-1 text-xs leading-5 text-slate-500">
                    {{ testResult.message }}
                  </p>
                </div>
                <StatusBadge
                  :text="
                    testResult.status === 'ok'
                      ? '通过'
                      : testResult.status === 'warning'
                        ? '需确认'
                        : '失败'
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
              </div>

              <div class="mt-4 grid gap-3 md:grid-cols-2">
                <div class="rounded-2xl border border-slate-200 bg-white p-4">
                  <p class="text-xs text-slate-500">OpenAPI 文档</p>
                  <p class="mt-1 text-sm font-medium text-stone-900">
                    {{ testResult.openapi_doc_reachable ? "可访问" : "不可访问" }}
                    <span
                      v-if="testResult.openapi_doc_status !== null"
                      class="text-slate-500"
                    >
                      （HTTP {{ testResult.openapi_doc_status }}）
                    </span>
                  </p>
                </div>
                <div class="rounded-2xl border border-slate-200 bg-white p-4">
                  <p class="text-xs text-slate-500">鉴权探测</p>
                  <p class="mt-1 text-sm font-medium text-stone-900">
                    {{ testResult.authenticated ? "已通过" : "未通过" }}
                    <span
                      v-if="testResult.auth_probe_status !== null"
                      class="text-slate-500"
                    >
                      （HTTP {{ testResult.auth_probe_status }}）
                    </span>
                  </p>
                </div>
              </div>
            </div>
            <div
              v-else
              class="mt-4 rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-4 py-5 text-sm text-slate-500"
            >
              还没有执行连接测试。读取远端站点前，建议先跑一次自检。
            </div>

            <div class="mt-4 flex flex-wrap gap-2.5">
              <RouterLink
                to="/admin/safeline"
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
              >
                <Link2 :size="14" />
                打开雷池联动页
              </RouterLink>
              <button
                v-if="hasPrimary"
                @click="clearPrimary"
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-1.5 text-xs text-stone-700 transition hover:border-amber-500/40 hover:text-amber-700"
              >
                清空主站点
              </button>
            </div>
          </div>
        </section>

        <section
          class="rounded-2xl border border-white/80 bg-white/80 p-5 shadow-[0_14px_30px_rgba(90,60,30,0.06)]"
        >
          <div class="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
            <div>
              <p class="text-sm font-semibold text-stone-900">站点清单</p>
              <p class="mt-1 text-xs leading-5 text-slate-500">
                默认优先展示主站点、已保存映射和启用中的站点。直接编辑别名、启用状态和备注后保存即可写入后端。
              </p>
            </div>

            <div class="grid gap-3 md:grid-cols-3 xl:min-w-[42rem]">
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">搜索</span>
                <div class="relative">
                  <Search
                    class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                    :size="14"
                  />
                  <input
                    v-model="filters.keyword"
                    type="text"
                    placeholder="别名 / 域名 / 站点 ID / 备注"
                    class="w-full rounded-[16px] border border-slate-200 bg-white px-9 py-2.5 text-sm outline-none transition focus:border-blue-500"
                  />
                </div>
              </label>

              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">纳管状态</span>
                <select
                  v-model="filters.scope"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                >
                  <option value="all">全部站点</option>
                  <option value="mapped">只看已映射</option>
                  <option value="unmapped">只看待纳管</option>
                  <option value="orphaned">只看孤儿映射</option>
                </select>
              </label>

              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">运行状态</span>
                <select
                  v-model="filters.state"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                >
                  <option value="all">全部状态</option>
                  <option value="enabled">只看启用映射</option>
                  <option value="disabled">只看停用映射</option>
                  <option value="primary">只看主站点</option>
                </select>
              </label>
            </div>
          </div>

          <div class="mt-4 flex flex-wrap gap-2">
            <StatusBadge
              :text="`当前列表 ${formatNumber(filteredDrafts.length)} 条`"
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
          </div>

          <div
            v-if="filteredDrafts.length === 0"
            class="mt-4 rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-4 py-8 text-center text-sm text-slate-500"
          >
            当前筛选条件下没有可展示的站点。可以先读取远端站点，或者调整搜索与筛选条件。
          </div>

          <div v-else class="mt-4 grid gap-4">
            <article
              v-for="site in filteredDrafts"
              :key="site.safeline_site_id"
              class="rounded-[24px] border border-slate-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(248,250,252,0.96))] p-4 shadow-[0_10px_28px_rgba(90,60,30,0.05)]"
            >
              <div class="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                <div class="min-w-0 flex-1">
                  <label class="block text-xs text-slate-500">本地别名</label>
                  <input
                    v-model="site.local_alias"
                    type="text"
                    class="mt-1.5 w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm font-medium text-stone-900 outline-none transition focus:border-blue-500"
                    placeholder="给站点一个便于运营识别的名称"
                  />

                  <div class="mt-3 flex flex-wrap gap-2">
                    <StatusBadge
                      :text="mappingStateText(site)"
                      :type="mappingStateType(site)"
                      compact
                    />
                    <StatusBadge
                      :text="remoteStatusText(site.status)"
                      :type="remoteStatusType(site.status)"
                      compact
                    />
                    <StatusBadge
                      v-if="site.is_primary"
                      text="主站点"
                      type="info"
                      compact
                    />
                    <StatusBadge
                      v-if="!site.enabled"
                      text="映射已停用"
                      type="warning"
                      compact
                    />
                  </div>
                </div>

                <div class="flex shrink-0 flex-wrap gap-2">
                  <button
                    @click="selectPrimary(site.safeline_site_id)"
                    class="inline-flex items-center gap-2 rounded-full border px-4 py-1.5 text-xs font-medium transition"
                    :class="
                      site.is_primary
                        ? 'border-blue-500/30 bg-blue-50 text-blue-700'
                        : 'border-slate-200 bg-white text-stone-700 hover:border-blue-500/40 hover:text-blue-700'
                    "
                  >
                    <ShieldCheck :size="14" />
                    {{ site.is_primary ? "当前主站点" : "设为主站点" }}
                  </button>
                </div>
              </div>

              <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                <div class="rounded-2xl bg-slate-50 p-3.5">
                  <p class="text-xs text-slate-500">雷池站点名</p>
                  <p class="mt-1 break-all text-sm text-stone-900">
                    {{ site.safeline_site_name || "未返回名称" }}
                  </p>
                </div>
                <div class="rounded-2xl bg-slate-50 p-3.5">
                  <p class="text-xs text-slate-500">域名 / Host</p>
                  <p class="mt-1 break-all text-sm text-stone-900">
                    {{ site.safeline_site_domain || "未返回域名" }}
                  </p>
                </div>
                <div class="rounded-2xl bg-slate-50 p-3.5">
                  <p class="text-xs text-slate-500">雷池站点 ID</p>
                  <p class="mt-1 break-all font-mono text-sm text-stone-900">
                    {{ site.safeline_site_id || "缺失" }}
                  </p>
                </div>
                <div class="rounded-2xl bg-slate-50 p-3.5">
                  <p class="text-xs text-slate-500">最近入库时间</p>
                  <p class="mt-1 text-sm text-stone-900">
                    {{ formatTimestamp(site.updated_at) }}
                  </p>
                </div>
              </div>

              <div class="mt-4 grid gap-3 xl:grid-cols-[220px_1fr]">
                <label
                  class="flex items-start gap-2.5 rounded-2xl border border-slate-200 bg-white px-3 py-3"
                >
                  <input
                    v-model="site.enabled"
                    type="checkbox"
                    class="mt-0.5 accent-blue-600"
                  />
                  <span>
                    <span class="block text-sm font-medium text-stone-900">
                      启用映射
                    </span>
                    <span class="mt-0.5 block text-xs leading-5 text-slate-500">
                      关闭后保留记录，但事件识别和默认映射将不再使用它。
                    </span>
                  </span>
                </label>

                <label class="space-y-1.5">
                  <span class="text-xs text-slate-500">备注</span>
                  <textarea
                    v-model="site.notes"
                    rows="3"
                    class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                    placeholder="例如：核心业务、灰度入口、海外站点等"
                  />
                </label>
              </div>

              <div
                v-if="site.orphaned"
                class="mt-4 rounded-2xl border border-amber-300/60 bg-amber-50 px-4 py-3 text-sm leading-6 text-amber-800"
              >
                这条映射目前只存在于本地数据库。说明远端接口本次没有返回对应站点，可能是站点已删除、接口路径不一致，或者当前账号无权限看到它。
              </div>
            </article>
          </div>
        </section>
      </template>
    </div>
  </AppLayout>
</template>
