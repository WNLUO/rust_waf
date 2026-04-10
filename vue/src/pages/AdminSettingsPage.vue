<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import AppLayout from "../components/layout/AppLayout.vue";
import {
  createLocalCertificate,
  deleteLocalCertificate,
  fetchSafeLineMappings,
  fetchSafeLineSites,
  fetchSettings,
  fetchLocalCertificates,
  testSafeLineConnection,
  updateSafeLineMappings,
  updateSettings,
} from "../lib/api";
import type {
  LocalCertificateDraft,
  LocalCertificateItem,
  SafeLineMappingItem,
  SafeLineSiteItem,
  SafeLineTestResponse,
  SettingsPayload,
} from "../lib/types";
import { PlugZap, Save, ServerCog, Settings } from "lucide-vue-next";

interface SystemSettingsForm extends SettingsPayload {}

const loading = ref(true);
const saving = ref(false);
const testing = ref(false);
const loadingSites = ref(false);
const savingMappings = ref(false);
const loadingCertificates = ref(false);
const savingCertificate = ref(false);
const deletingCertificateId = ref<number | null>(null);
const error = ref("");
const successMessage = ref("");
const testResult = ref<SafeLineTestResponse | null>(null);
const sites = ref<SafeLineSiteItem[]>([]);
const mappings = ref<SafeLineMappingItem[]>([]);
const localCertificates = ref<LocalCertificateItem[]>([]);
const sitesLoadedAt = ref<number | null>(null);

const systemSettings = reactive<SystemSettingsForm>({
  gateway_name: "玄枢防护网关",
  auto_refresh_seconds: 5,
  https_listen_addr: "",
  default_certificate_id: null,
  upstream_endpoint: "",
  api_endpoint: "127.0.0.1:3000",
  emergency_mode: false,
  sqlite_persistence: true,
  notify_by_sound: false,
  notification_level: "critical",
  retain_days: 30,
  notes: "",
  safeline: {
    enabled: false,
    auto_sync_events: false,
    auto_sync_blocked_ips_push: false,
    auto_sync_blocked_ips_pull: false,
    auto_sync_interval_secs: 300,
    base_url: "",
    api_token: "",
    username: "",
    password: "",
    verify_tls: false,
    openapi_doc_path: "/openapi_doc/",
    auth_probe_path: "/api/open/system/key",
    site_list_path: "/api/open/site",
    event_list_path: "/api/open/records",
    blocklist_sync_path: "/api/open/ipgroup",
    blocklist_delete_path: "/api/open/ipgroup",
    blocklist_ip_group_ids: [],
  },
});

const certificateForm = reactive<LocalCertificateDraft>({
  name: "",
  domains: [],
  issuer: "",
  valid_from: null,
  valid_to: null,
  source_type: "manual",
  provider_remote_id: null,
  trusted: false,
  expired: false,
  notes: "",
  last_synced_at: null,
  certificate_pem: "",
  private_key_pem: "",
});

const certificateDomainsText = computed({
  get: () => certificateForm.domains.join(", "),
  set: (value: string) => {
    certificateForm.domains = value
      .split(/[\n,]/)
      .map((item) => item.trim())
      .filter(Boolean);
  },
});

const blocklistIpGroupIdsText = computed({
  get: () => systemSettings.safeline.blocklist_ip_group_ids.join(", "),
  set: (value: string) => {
    systemSettings.safeline.blocklist_ip_group_ids = value
      .split(/[\n,]/)
      .map((item) => item.trim())
      .filter(Boolean);
  },
});

function toPlainSafeLineSettings() {
  return {
    enabled: systemSettings.safeline.enabled,
    auto_sync_events: systemSettings.safeline.auto_sync_events,
    auto_sync_blocked_ips_push:
      systemSettings.safeline.auto_sync_blocked_ips_push,
    auto_sync_blocked_ips_pull:
      systemSettings.safeline.auto_sync_blocked_ips_pull,
    auto_sync_interval_secs: systemSettings.safeline.auto_sync_interval_secs,
    base_url: systemSettings.safeline.base_url,
    api_token: systemSettings.safeline.api_token,
    username: systemSettings.safeline.username,
    password: systemSettings.safeline.password,
    verify_tls: systemSettings.safeline.verify_tls,
    openapi_doc_path: systemSettings.safeline.openapi_doc_path,
    auth_probe_path: systemSettings.safeline.auth_probe_path,
    site_list_path: systemSettings.safeline.site_list_path,
    event_list_path: systemSettings.safeline.event_list_path,
    blocklist_sync_path: systemSettings.safeline.blocklist_sync_path,
    blocklist_delete_path: systemSettings.safeline.blocklist_delete_path,
    blocklist_ip_group_ids: [...systemSettings.safeline.blocklist_ip_group_ids],
  };
}

function toPlainSettingsPayload(): SettingsPayload {
  return {
    gateway_name: systemSettings.gateway_name,
    auto_refresh_seconds: systemSettings.auto_refresh_seconds,
    https_listen_addr: systemSettings.https_listen_addr,
    default_certificate_id: systemSettings.default_certificate_id,
    upstream_endpoint: systemSettings.upstream_endpoint,
    api_endpoint: systemSettings.api_endpoint,
    emergency_mode: systemSettings.emergency_mode,
    sqlite_persistence: systemSettings.sqlite_persistence,
    notify_by_sound: systemSettings.notify_by_sound,
    notification_level: systemSettings.notification_level,
    retain_days: systemSettings.retain_days,
    notes: systemSettings.notes,
    safeline: toPlainSafeLineSettings(),
  };
}

async function loadCertificates() {
  loadingCertificates.value = true;

  try {
    const response = await fetchLocalCertificates();
    localCertificates.value = response.certificates;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "读取本地证书失败";
  } finally {
    loadingCertificates.value = false;
  }
}

async function loadSettings() {
  loading.value = true;
  error.value = "";

  try {
    const payload = await fetchSettings();
    Object.assign(systemSettings, payload);
  } catch (e) {
    error.value = e instanceof Error ? e.message : "系统设置加载失败";
  } finally {
    loading.value = false;
  }
}

async function loadMappings() {
  try {
    const response = await fetchSafeLineMappings();
    mappings.value = response.mappings;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "读取雷池站点映射失败";
  }
}

async function saveSettings() {
  saving.value = true;
  error.value = "";
  successMessage.value = "";

  try {
    systemSettings.auto_refresh_seconds = Number.isFinite(
      systemSettings.auto_refresh_seconds,
    )
      ? Math.min(Math.max(systemSettings.auto_refresh_seconds, 3), 60)
      : 5;
    systemSettings.retain_days = Number.isFinite(systemSettings.retain_days)
      ? Math.min(Math.max(systemSettings.retain_days, 1), 365)
      : 30;
    systemSettings.safeline.auto_sync_interval_secs = Number.isFinite(
      systemSettings.safeline.auto_sync_interval_secs,
    )
      ? Math.min(
          Math.max(systemSettings.safeline.auto_sync_interval_secs, 15),
          86400,
        )
      : 300;

    const response = await updateSettings(toPlainSettingsPayload());
    successMessage.value = response.message;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "系统设置保存失败";
  } finally {
    saving.value = false;
  }
}

async function runSafeLineTest() {
  testing.value = true;
  error.value = "";

  try {
    testResult.value = await testSafeLineConnection(toPlainSafeLineSettings());
  } catch (e) {
    error.value = e instanceof Error ? e.message : "雷池连通性测试失败";
    testResult.value = null;
  } finally {
    testing.value = false;
  }
}

async function loadSafeLineSites() {
  loadingSites.value = true;
  error.value = "";

  try {
    const response = await fetchSafeLineSites(toPlainSafeLineSettings());
    sites.value = response.sites;
    sitesLoadedAt.value = Math.floor(Date.now() / 1000);
  } catch (e) {
    error.value = e instanceof Error ? e.message : "读取雷池站点列表失败";
    sites.value = [];
  } finally {
    loadingSites.value = false;
  }
}

function siteMappingDraft(site: SafeLineSiteItem) {
  const existing = mappings.value.find(
    (item) => item.safeline_site_id === site.id,
  );
  return {
    safeline_site_id: site.id,
    safeline_site_name: site.name,
    safeline_site_domain: site.domain,
    local_alias: existing?.local_alias ?? site.name ?? site.domain ?? "",
    enabled: existing?.enabled ?? true,
    is_primary: existing?.is_primary ?? false,
    notes: existing?.notes ?? "",
    updated_at: existing?.updated_at ?? null,
  };
}

const mappingDrafts = computed(() => sites.value.map(siteMappingDraft));

function formatTimestamp(timestamp: number | null) {
  if (!timestamp) return "暂无";
  return new Date(timestamp * 1000).toLocaleString("zh-CN", { hour12: false });
}

async function saveMappings() {
  savingMappings.value = true;
  error.value = "";
  successMessage.value = "";

  try {
    const payload = {
      mappings: mappingDrafts.value.map((item) => ({
        safeline_site_id: item.safeline_site_id,
        safeline_site_name: item.safeline_site_name,
        safeline_site_domain: item.safeline_site_domain,
        local_alias: item.local_alias,
        enabled: item.enabled,
        is_primary: item.is_primary,
        notes: item.notes,
      })),
    };
    const response = await updateSafeLineMappings(payload);
    successMessage.value = response.message;
    await loadMappings();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "保存雷池站点映射失败";
  } finally {
    savingMappings.value = false;
  }
}

async function uploadCertificate() {
  savingCertificate.value = true;
  error.value = "";
  successMessage.value = "";

  try {
    const payload: LocalCertificateDraft = {
      ...certificateForm,
      name: certificateForm.name.trim(),
      domains: certificateForm.domains.map((item) => item.trim()).filter(Boolean),
      issuer: certificateForm.issuer.trim(),
      notes: certificateForm.notes.trim(),
      certificate_pem: certificateForm.certificate_pem?.trim() ?? "",
      private_key_pem: certificateForm.private_key_pem?.trim() ?? "",
    };

    await createLocalCertificate(payload);
    certificateForm.name = "";
    certificateForm.domains = [];
    certificateForm.issuer = "";
    certificateForm.notes = "";
    certificateForm.certificate_pem = "";
    certificateForm.private_key_pem = "";

    await loadCertificates();
    successMessage.value = "证书已上传，可在下方设为默认证书。";
  } catch (e) {
    error.value = e instanceof Error ? e.message : "上传本地证书失败";
  } finally {
    savingCertificate.value = false;
  }
}

async function removeCertificate(id: number) {
  deletingCertificateId.value = id;
  error.value = "";
  successMessage.value = "";

  try {
    const response = await deleteLocalCertificate(id);
    if (systemSettings.default_certificate_id === id) {
      systemSettings.default_certificate_id = null;
    }
    await loadCertificates();
    successMessage.value = response.message;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "删除本地证书失败";
  } finally {
    deletingCertificateId.value = null;
  }
}

onMounted(async () => {
  await loadSettings();
  await loadCertificates();
  await loadMappings();
});
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        @click="saveSettings"
        :disabled="saving || loading"
        class="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white shadow-sm transition hover:bg-blue-600/90 disabled:cursor-not-allowed disabled:opacity-60"
      >
        <Save :size="12" />
        {{ saving ? "保存中..." : "保存设置" }}
      </button>
    </template>

    <div class="space-y-4">
      <div
        v-if="loading"
        class="rounded-lg border border-slate-200 bg-white/75 px-4 py-3 text-sm text-slate-500 shadow-[0_10px_25px_rgba(90,60,30,0.05)]"
      >
        正在从数据库加载设置...
      </div>

      <div
        v-if="error"
        class="rounded-lg border border-red-500/25 bg-red-500/8 px-4 py-3 text-sm text-red-600 shadow-[0_10px_25px_rgba(166,30,77,0.07)]"
      >
        {{ error }}
      </div>

      <div
        v-if="successMessage"
        class="rounded-lg border border-emerald-300/60 bg-emerald-50 px-4 py-3 text-sm text-emerald-800 shadow-[0_10px_25px_rgba(16,185,129,0.07)]"
      >
        {{ successMessage }}
      </div>

      <div class="space-y-4">
        <div
          class="rounded-xl border border-white/80 bg-white/80 p-5 shadow-[0_14px_30px_rgba(90,60,30,0.06)]"
        >
          <div class="flex items-center gap-3">
            <div
              class="flex h-10 w-10 items-center justify-center rounded-xl bg-slate-50 text-blue-700"
            >
              <Settings :size="20" />
            </div>
            <div>
              <p class="text-xs tracking-wide text-blue-700">控制台参数</p>
              <h3 class="mt-0.5 text-lg font-semibold text-stone-900">
                基础运行配置
              </h3>
            </div>
          </div>

          <div class="mt-3 grid gap-4 md:grid-cols-3">
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">网关名称</span>
              <input
                v-model="systemSettings.gateway_name"
                type="text"
                class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
              />
            </label>
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">自动刷新频率（秒）</span>
              <input
                v-model.number="systemSettings.auto_refresh_seconds"
                type="number"
                min="3"
                max="60"
                class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
              />
            </label>
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">统一 HTTPS 入口</span>
              <input
                v-model="systemSettings.https_listen_addr"
                type="text"
                placeholder="例如 0.0.0.0:660"
                class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
              />
            </label>
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">控制面 API 地址</span>
              <input
                v-model="systemSettings.api_endpoint"
                type="text"
                class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
              />
            </label>
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">事件保留天数</span>
              <input
                v-model.number="systemSettings.retain_days"
                type="number"
                min="1"
                max="365"
                class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
              />
            </label>
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">通知级别</span>
              <select
                v-model="systemSettings.notification_level"
                class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
              >
                <option value="critical">仅高风险事件</option>
                <option value="blocked_only">仅拦截事件</option>
                <option value="all">全部事件</option>
              </select>
            </label>
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">默认证书</span>
              <select
                v-model="systemSettings.default_certificate_id"
                class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
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
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">默认回源地址</span>
              <input
                v-model="systemSettings.upstream_endpoint"
                type="text"
                placeholder="未命中站点时使用，可留空"
                class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
              />
            </label>
          </div>

          <div class="mt-4 grid gap-3 md:grid-cols-3">
            <label
              class="flex items-start gap-2.5 rounded-lg border border-slate-200 bg-slate-50 p-3"
            >
              <input
                v-model="systemSettings.emergency_mode"
                type="checkbox"
                class="mt-0.5 accent-blue-600"
              />
              <span>
                <span class="block text-sm font-medium text-stone-900"
                  >紧急模式</span
                >
                <span class="mt-0.5 block text-xs leading-5 text-slate-500"
                  >面向突发攻击时的高敏感运行状态。</span
                >
              </span>
            </label>
            <label
              class="flex items-start gap-2.5 rounded-lg border border-slate-200 bg-slate-50 p-3"
            >
              <input
                v-model="systemSettings.sqlite_persistence"
                type="checkbox"
                class="mt-0.5 accent-blue-600"
              />
              <span>
                <span class="block text-sm font-medium text-stone-900"
                  >启用持久化</span
                >
                <span class="mt-0.5 block text-xs leading-5 text-slate-500"
                  >保存到后端 SQLite 配置与事件库。</span
                >
              </span>
            </label>
            <label
              class="flex items-start gap-2.5 rounded-lg border border-slate-200 bg-slate-50 p-3"
            >
              <input
                v-model="systemSettings.notify_by_sound"
                type="checkbox"
                class="mt-0.5 accent-blue-600"
              />
              <span>
                <span class="block text-sm font-medium text-stone-900"
                  >声音提醒</span
                >
                <span class="mt-0.5 block text-xs leading-5 text-slate-500"
                  >在控制台打开期间对关键事件进行即时提示。</span
                >
              </span>
            </label>
          </div>
        </div>

        <div
          class="rounded-xl border border-white/80 bg-white/80 p-5 shadow-[0_14px_30px_rgba(90,60,30,0.06)]"
        >
          <div class="flex items-center gap-3">
            <div
              class="flex h-10 w-10 items-center justify-center rounded-xl bg-slate-50 text-blue-700"
            >
              <ServerCog :size="20" />
            </div>
            <div>
              <p class="text-xs tracking-wide text-blue-700">证书中心</p>
              <h3 class="mt-0.5 text-lg font-semibold text-stone-900">
                本地证书上传
              </h3>
            </div>
          </div>

          <div class="mt-3 space-y-4">
            <div class="grid gap-4 md:grid-cols-2">
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">证书名称</span>
                <input
                  v-model="certificateForm.name"
                  type="text"
                  placeholder="例如 default-fake-cert"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">域名列表</span>
                <input
                  v-model="certificateDomainsText"
                  type="text"
                  placeholder="多个域名用逗号分隔"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
              <label class="space-y-1.5 md:col-span-2">
                <span class="text-xs text-slate-500">备注</span>
                <input
                  v-model="certificateForm.notes"
                  type="text"
                  placeholder="例如：用于 IP 直连时返回的假证书"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
              <label class="space-y-1.5 md:col-span-2">
                <span class="text-xs text-slate-500">证书 PEM</span>
                <textarea
                  v-model="certificateForm.certificate_pem"
                  rows="8"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 font-mono text-xs outline-none transition focus:border-blue-500"
                />
              </label>
              <label class="space-y-1.5 md:col-span-2">
                <span class="text-xs text-slate-500">私钥 PEM</span>
                <textarea
                  v-model="certificateForm.private_key_pem"
                  rows="8"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 font-mono text-xs outline-none transition focus:border-blue-500"
                />
              </label>
            </div>

            <div class="flex flex-wrap items-center gap-2.5">
              <button
                @click="uploadCertificate"
                :disabled="savingCertificate"
                class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-white px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Save :size="12" />
                {{ savingCertificate ? "上传中..." : "上传证书" }}
              </button>
              <span class="text-xs leading-5 text-slate-500">
                上传后可在“默认证书”里指定用于 `IP:端口` 或未知 SNI 的回包证书。
              </span>
            </div>

            <div class="rounded-lg border border-slate-200 bg-slate-50 p-4">
              <div class="flex items-center justify-between gap-3">
                <div>
                  <p class="text-sm font-medium text-stone-900">当前证书</p>
                  <p class="mt-1 text-xs leading-5 text-slate-500">
                    {{
                      loadingCertificates
                        ? "正在读取本地证书..."
                        : `共 ${localCertificates.length} 张，可用于站点证书和默认证书。`
                    }}
                  </p>
                </div>
              </div>

              <div v-if="localCertificates.length" class="mt-3 grid gap-3">
                <div
                  v-for="certificate in localCertificates"
                  :key="certificate.id"
                  class="rounded-[16px] border border-slate-200 bg-white px-4 py-3"
                >
                  <div class="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p class="text-sm font-medium text-stone-900">
                        #{{ certificate.id }} · {{ certificate.name }}
                      </p>
                      <p class="mt-1 text-xs text-slate-500">
                        {{
                          certificate.domains.length
                            ? certificate.domains.join(" / ")
                            : "未填写域名"
                        }}
                      </p>
                    </div>
                    <div class="flex flex-wrap gap-2">
                      <span
                        v-if="systemSettings.default_certificate_id === certificate.id"
                        class="inline-flex items-center rounded-full bg-blue-50 px-2.5 py-1 text-xs font-medium text-blue-700"
                      >
                        当前默认
                      </span>
                      <button
                        @click="systemSettings.default_certificate_id = certificate.id"
                        class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                      >
                        设为默认
                      </button>
                      <button
                        @click="removeCertificate(certificate.id)"
                        :disabled="deletingCertificateId === certificate.id"
                        class="inline-flex items-center gap-1 rounded-lg border border-red-500/20 px-2.5 py-1 text-xs font-medium text-red-600 transition hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        {{
                          deletingCertificateId === certificate.id
                            ? "删除中..."
                            : "删除"
                        }}
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              <div
                v-else-if="!loadingCertificates"
                class="mt-3 rounded-[16px] border border-dashed border-slate-200 bg-white px-4 py-6 text-sm text-slate-500"
              >
                还没有上传本地证书。
              </div>
            </div>
          </div>
        </div>

        <div
          class="rounded-xl border border-white/80 bg-white/80 p-5 shadow-[0_14px_30px_rgba(90,60,30,0.06)]"
        >
          <div class="flex items-center gap-3">
            <div
              class="flex h-10 w-10 items-center justify-center rounded-xl bg-slate-50 text-blue-700"
            >
              <PlugZap :size="20" />
            </div>
            <div>
              <p class="text-xs tracking-wide text-blue-700">雷池接入</p>
              <h3 class="mt-0.5 text-lg font-semibold text-stone-900">
                OpenAPI 基础配置
              </h3>
            </div>
          </div>

          <div class="mt-3 space-y-4">
            <label
              class="flex items-start gap-2.5 rounded-lg border border-slate-200 bg-slate-50 p-3"
            >
              <input
                v-model="systemSettings.safeline.enabled"
                type="checkbox"
                class="mt-0.5 accent-blue-600"
              />
              <span>
                <span class="block text-sm font-medium text-stone-900"
                  >启用雷池集成</span
                >
                <span class="mt-0.5 block text-xs leading-5 text-slate-500"
                  >保存后写入 SQLite，供后续日志同步和策略联动复用。</span
                >
              </span>
            </label>

            <div class="rounded-lg border border-slate-200 bg-slate-50 p-4">
              <div class="flex flex-col gap-1">
                <p class="text-sm font-medium text-stone-900">自动联动</p>
                <p class="text-xs leading-5 text-slate-500">
                  由服务端后台周期执行，不依赖页面停留。手动按钮仍可继续用于立即触发。
                </p>
              </div>

              <div class="mt-4 grid gap-3 md:grid-cols-3">
                <label
                  class="flex items-start gap-2.5 rounded-[16px] border border-slate-200 bg-white px-3 py-3"
                >
                  <input
                    v-model="systemSettings.safeline.auto_sync_events"
                    type="checkbox"
                    class="mt-0.5 accent-blue-600"
                  />
                  <span>
                    <span class="block text-sm font-medium text-stone-900"
                      >自动同步事件</span
                    >
                    <span class="mt-0.5 block text-xs leading-5 text-slate-500"
                      >定时拉取雷池攻击日志并写入本地事件库。</span
                    >
                  </span>
                </label>
                <label
                  class="flex items-start gap-2.5 rounded-[16px] border border-slate-200 bg-white px-3 py-3"
                >
                  <input
                    v-model="systemSettings.safeline.auto_sync_blocked_ips_push"
                    type="checkbox"
                    class="mt-0.5 accent-blue-600"
                  />
                  <span>
                    <span class="block text-sm font-medium text-stone-900"
                      >自动推送封禁</span
                    >
                    <span class="mt-0.5 block text-xs leading-5 text-slate-500"
                      >把本地仍生效的封禁周期性同步到雷池。</span
                    >
                  </span>
                </label>
                <label
                  class="flex items-start gap-2.5 rounded-[16px] border border-slate-200 bg-white px-3 py-3"
                >
                  <input
                    v-model="systemSettings.safeline.auto_sync_blocked_ips_pull"
                    type="checkbox"
                    class="mt-0.5 accent-blue-600"
                  />
                  <span>
                    <span class="block text-sm font-medium text-stone-900"
                      >自动回流封禁</span
                    >
                    <span class="mt-0.5 block text-xs leading-5 text-slate-500"
                      >定时把雷池远端封禁拉回本地，保持控制台名单同步。</span
                    >
                  </span>
                </label>
              </div>

              <label class="mt-4 block space-y-1.5">
                <span class="text-xs text-slate-500">自动联动间隔（秒）</span>
                <input
                  v-model.number="
                    systemSettings.safeline.auto_sync_interval_secs
                  "
                  type="number"
                  min="15"
                  max="86400"
                  step="15"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
                <span class="block text-xs leading-5 text-slate-500"
                  >建议从 60 到 300
                  秒开始。保存后后台任务会自动读取新配置，无需页面保持打开。</span
                >
              </label>
            </div>

            <div class="grid gap-4 md:grid-cols-2">
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">雷池地址</span>
                <input
                  v-model="systemSettings.safeline.base_url"
                  type="text"
                  placeholder="https://127.0.0.1:9443"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>

              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">API Token</span>
                <input
                  v-model="systemSettings.safeline.api_token"
                  type="password"
                  placeholder="API-TOKEN"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
            </div>

            <div class="grid gap-4 md:grid-cols-2">
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">雷池账号</span>
                <input
                  v-model="systemSettings.safeline.username"
                  type="text"
                  placeholder="用户名"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">雷池密码</span>
                <input
                  v-model="systemSettings.safeline.password"
                  type="password"
                  placeholder="密码"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
            </div>

            <div class="grid gap-4 md:grid-cols-3">
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">OpenAPI 文档路径</span>
                <input
                  v-model="systemSettings.safeline.openapi_doc_path"
                  type="text"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">鉴权探测路径</span>
                <input
                  v-model="systemSettings.safeline.auth_probe_path"
                  type="text"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">站点列表路径</span>
                <input
                  v-model="systemSettings.safeline.site_list_path"
                  type="text"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">事件列表路径</span>
                <input
                  v-model="systemSettings.safeline.event_list_path"
                  type="text"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">封禁同步路径</span>
                <input
                  v-model="systemSettings.safeline.blocklist_sync_path"
                  type="text"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">远端解封路径</span>
                <input
                  v-model="systemSettings.safeline.blocklist_delete_path"
                  type="text"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
              </label>
              <label class="space-y-1.5 md:col-span-3">
                <span class="text-xs text-slate-500">封禁目标 IP 组 ID</span>
                <input
                  v-model="blocklistIpGroupIdsText"
                  type="text"
                  placeholder="多个 ID 用逗号分隔，例如 12, 18"
                  class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                />
                <span class="block text-xs leading-5 text-slate-500"
                  >当封禁路径使用新版 `/api/open/ipgroup`
                  接口时，推送封禁和远端解封会基于这里填写的 IP 组 ID 执行
                  append/remove。</span
                >
              </label>
            </div>

            <label
              class="flex items-start gap-2.5 rounded-lg border border-slate-200 bg-slate-50 p-3"
            >
              <input
                v-model="systemSettings.safeline.verify_tls"
                type="checkbox"
                class="mt-0.5 accent-blue-600"
              />
              <span>
                <span class="block text-sm font-medium text-stone-900"
                  >校验证书</span
                >
                <span class="mt-0.5 block text-xs leading-5 text-slate-500"
                  >开启后会严格校验雷池 HTTPS
                  证书；自签名环境建议先关闭测试。</span
                >
              </span>
            </label>

            <div class="flex flex-wrap items-center gap-2.5">
              <button
                @click="runSafeLineTest"
                :disabled="testing || loading"
                class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-slate-50 px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <PlugZap :size="12" />
                {{ testing ? "测试中..." : "测试雷池连接" }}
              </button>
              <button
                @click="loadSafeLineSites"
                :disabled="loadingSites || loading"
                class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-white px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <ServerCog :size="12" />
                {{ loadingSites ? "读取中..." : "读取站点列表" }}
              </button>
              <button
                @click="saveMappings"
                :disabled="savingMappings || sites.length === 0"
                class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-white px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Save :size="12" />
                {{ savingMappings ? "保存中..." : "保存站点映射" }}
              </button>
              <p class="text-xs leading-5 text-slate-500">
                当前测试不会改动雷池配置，只会做连通性和鉴权探测。
              </p>
            </div>

            <div
              v-if="testResult"
              class="rounded-lg border border-slate-200 bg-slate-50 p-4"
            >
              <div class="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p class="text-sm font-medium text-stone-900">
                    连通性测试结果
                  </p>
                  <p class="mt-1 text-xs leading-5 text-slate-500">
                    {{ testResult.message }}
                  </p>
                </div>
                <span
                  class="inline-flex rounded-full px-2.5 py-1 text-xs font-medium"
                  :class="
                    testResult.status === 'ok'
                      ? 'bg-emerald-100 text-emerald-700'
                      : testResult.status === 'warning'
                        ? 'bg-amber-100 text-amber-700'
                        : 'bg-rose-100 text-rose-700'
                  "
                >
                  {{
                    testResult.status === "ok"
                      ? "通过"
                      : testResult.status === "warning"
                        ? "需确认"
                        : "失败"
                  }}
                </span>
              </div>

              <div class="mt-3 grid gap-3 md:grid-cols-2">
                <div
                  class="rounded-[16px] border border-slate-200 bg-white px-3.5 py-3"
                >
                  <p class="text-xs text-slate-500">OpenAPI 文档</p>
                  <p class="mt-1 text-sm font-medium text-stone-900">
                    {{
                      testResult.openapi_doc_reachable ? "可访问" : "不可访问"
                    }}
                    <span
                      v-if="testResult.openapi_doc_status !== null"
                      class="text-slate-500"
                    >
                      （HTTP {{ testResult.openapi_doc_status }}）
                    </span>
                  </p>
                </div>
                <div
                  class="rounded-[16px] border border-slate-200 bg-white px-3.5 py-3"
                >
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
              v-if="sitesLoadedAt !== null"
              class="rounded-lg border border-slate-200 bg-slate-50 p-4"
            >
              <div class="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p class="text-sm font-medium text-stone-900">
                    站点列表读取结果
                  </p>
                  <p class="mt-1 text-xs leading-5 text-slate-500">
                    最近读取时间：{{ formatTimestamp(sitesLoadedAt) }}，共
                    {{ sites.length }} 个站点。
                  </p>
                </div>
              </div>

              <div v-if="sites.length" class="mt-3 grid gap-3">
                <div
                  v-for="site in sites"
                  :key="site.id || `${site.name}-${site.domain}`"
                  class="rounded-[16px] border border-slate-200 bg-white px-4 py-3"
                >
                  <div
                    class="flex flex-wrap items-center justify-between gap-3"
                  >
                    <div>
                      <p class="text-sm font-medium text-stone-900">
                        {{ site.name || "未命名站点" }}
                      </p>
                      <p class="mt-1 font-mono text-xs text-slate-500">
                        {{ site.domain || "未提供域名" }}
                      </p>
                    </div>
                    <div class="text-right text-xs text-slate-500">
                      <p>ID：{{ site.id || "未提供" }}</p>
                      <p class="mt-1">状态：{{ site.status || "unknown" }}</p>
                    </div>
                  </div>
                </div>
              </div>

              <div
                v-else
                class="mt-3 rounded-[16px] border border-dashed border-slate-200 bg-white px-4 py-6 text-sm text-slate-500"
              >
                接口调用已完成，但当前没有可显示的站点。
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </AppLayout>
</template>
