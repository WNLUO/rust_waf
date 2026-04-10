<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import AppLayout from '../components/layout/AppLayout.vue'
import { useFormatters } from '../composables/useFormatters'
import {
  fetchSafeLineMappings,
  fetchSafeLineSites,
  fetchSafeLineSyncState,
  fetchSettings,
  syncSafeLineEvents,
  testSafeLineConnection,
  updateSafeLineMappings,
  updateSettings,
} from '../lib/api'
import type {
  SafeLineMappingItem,
  SafeLineSyncStateResponse,
  SafeLineSiteItem,
  SafeLineTestResponse,
  SettingsPayload,
} from '../lib/types'
import { BellRing, PlugZap, Save, ServerCog, Settings, ShieldCheck } from 'lucide-vue-next'

interface SystemSettingsForm extends SettingsPayload {}

const { formatTimestamp } = useFormatters()
const settingsSavedAt = ref<number | null>(null)
const loading = ref(true)
const saving = ref(false)
const testing = ref(false)
const loadingSites = ref(false)
const savingMappings = ref(false)
const syncingEvents = ref(false)
const error = ref('')
const successMessage = ref('')
const testResult = ref<SafeLineTestResponse | null>(null)
const sites = ref<SafeLineSiteItem[]>([])
const mappings = ref<SafeLineMappingItem[]>([])
const sitesLoadedAt = ref<number | null>(null)
const syncState = ref<SafeLineSyncStateResponse | null>(null)

const systemSettings = reactive<SystemSettingsForm>({
  gateway_name: '玄枢防护网关',
  auto_refresh_seconds: 5,
  upstream_endpoint: '',
  api_endpoint: '127.0.0.1:3000',
  emergency_mode: false,
  sqlite_persistence: true,
  notify_by_sound: false,
  notification_level: 'critical',
  retain_days: 30,
  notes: '',
  safeline: {
    enabled: false,
    base_url: '',
    api_token: '',
    verify_tls: false,
    openapi_doc_path: '/openapi_doc/',
    auth_probe_path: '/api/IPGroupAPI',
    site_list_path: '/api/WebsiteAPI',
    event_list_path: '/api/AttackLogAPI',
  },
})

const settingsSummary = computed(() => [
  {
    title: '自动刷新',
    value: `${systemSettings.auto_refresh_seconds} 秒`,
    desc: '控制总览数据的轮询频率。',
    icon: BellRing,
  },
  {
    title: '上游目标',
    value: systemSettings.upstream_endpoint || '未配置',
    desc: systemSettings.emergency_mode ? '当前处于紧急防护模式。' : '当前按常规转发策略运行。',
    icon: ServerCog,
  },
  {
    title:
      systemSettings.notification_level === 'all'
        ? '全部事件'
        : systemSettings.notification_level === 'blocked_only'
          ? '仅拦截事件'
          : '仅高风险事件',
    value: systemSettings.gateway_name,
    desc: systemSettings.notify_by_sound ? '声音提醒已启用。' : '声音提醒未启用。',
    icon: ShieldCheck,
  },
])

const testToneClass = computed(() => {
  if (!testResult.value) return 'border-cyber-border/70 bg-cyber-surface-strong text-stone-700'
  if (testResult.value.status === 'ok') return 'border-emerald-300/60 bg-emerald-50 text-emerald-800'
  if (testResult.value.status === 'error') return 'border-cyber-error/30 bg-cyber-error/8 text-cyber-error'
  return 'border-amber-300/60 bg-amber-50 text-amber-800'
})

async function loadSettings() {
  loading.value = true
  error.value = ''

  try {
    const payload = await fetchSettings()
    Object.assign(systemSettings, payload)
  } catch (e) {
    error.value = e instanceof Error ? e.message : '系统设置加载失败'
  } finally {
    loading.value = false
  }
}

async function loadMappings() {
  try {
    const response = await fetchSafeLineMappings()
    mappings.value = response.mappings
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取雷池站点映射失败'
  }
}

async function loadSyncState() {
  try {
    syncState.value = await fetchSafeLineSyncState()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取雷池同步状态失败'
  }
}

async function saveSettings() {
  saving.value = true
  error.value = ''
  successMessage.value = ''

  try {
    systemSettings.auto_refresh_seconds = Number.isFinite(systemSettings.auto_refresh_seconds)
      ? Math.min(Math.max(systemSettings.auto_refresh_seconds, 3), 60)
      : 5
    systemSettings.retain_days = Number.isFinite(systemSettings.retain_days)
      ? Math.min(Math.max(systemSettings.retain_days, 1), 365)
      : 30

    const response = await updateSettings(structuredClone(systemSettings))
    settingsSavedAt.value = Math.floor(Date.now() / 1000)
    successMessage.value = response.message
  } catch (e) {
    error.value = e instanceof Error ? e.message : '系统设置保存失败'
  } finally {
    saving.value = false
  }
}

async function runSafeLineTest() {
  testing.value = true
  error.value = ''

  try {
    testResult.value = await testSafeLineConnection(structuredClone(systemSettings.safeline))
  } catch (e) {
    error.value = e instanceof Error ? e.message : '雷池连通性测试失败'
    testResult.value = null
  } finally {
    testing.value = false
  }
}

async function loadSafeLineSites() {
  loadingSites.value = true
  error.value = ''

  try {
    const response = await fetchSafeLineSites(structuredClone(systemSettings.safeline))
    sites.value = response.sites
    sitesLoadedAt.value = Math.floor(Date.now() / 1000)
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取雷池站点列表失败'
    sites.value = []
  } finally {
    loadingSites.value = false
  }
}

function siteMappingDraft(site: SafeLineSiteItem) {
  const existing = mappings.value.find((item) => item.safeline_site_id === site.id)
  return {
    safeline_site_id: site.id,
    safeline_site_name: site.name,
    safeline_site_domain: site.domain,
    local_alias: existing?.local_alias ?? site.name ?? site.domain ?? '',
    enabled: existing?.enabled ?? true,
    is_primary: existing?.is_primary ?? false,
    notes: existing?.notes ?? '',
    updated_at: existing?.updated_at ?? null,
  }
}

const mappingDrafts = computed(() => sites.value.map(siteMappingDraft))

function setDraftAlias(siteId: string, value: string) {
  upsertMapping(siteId, { local_alias: value })
}

function setDraftEnabled(siteId: string, value: boolean) {
  upsertMapping(siteId, { enabled: value })
}

function setDraftPrimary(siteId: string, value: boolean) {
  if (value) {
    mappings.value = mappings.value.map((item) => ({
      ...item,
      is_primary: item.safeline_site_id === siteId,
    }))
  }
  upsertMapping(siteId, { is_primary: value })
}

function setDraftNotes(siteId: string, value: string) {
  upsertMapping(siteId, { notes: value })
}

function upsertMapping(
  siteId: string,
  patch: Partial<Pick<SafeLineMappingItem, 'local_alias' | 'enabled' | 'is_primary' | 'notes'>>,
) {
  const site = sites.value.find((item) => item.id === siteId)
  if (!site) return

  const index = mappings.value.findIndex((item) => item.safeline_site_id === siteId)
  if (index >= 0) {
    mappings.value[index] = {
      ...mappings.value[index],
      ...patch,
    }
    return
  }

  mappings.value.unshift({
    id: 0,
    safeline_site_id: site.id,
    safeline_site_name: site.name,
    safeline_site_domain: site.domain,
    local_alias: patch.local_alias ?? site.name ?? site.domain ?? '',
    enabled: patch.enabled ?? true,
    is_primary: patch.is_primary ?? false,
    notes: patch.notes ?? '',
    updated_at: 0,
  })
}

async function saveMappings() {
  savingMappings.value = true
  error.value = ''
  successMessage.value = ''

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
    }
    const response = await updateSafeLineMappings(payload)
    successMessage.value = response.message
    await loadMappings()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '保存雷池站点映射失败'
  } finally {
    savingMappings.value = false
  }
}

async function runEventSync() {
  syncingEvents.value = true
  error.value = ''
  successMessage.value = ''

  try {
    const response = await syncSafeLineEvents()
    successMessage.value = response.message
    await loadSyncState()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '同步雷池事件失败'
  } finally {
    syncingEvents.value = false
  }
}

onMounted(async () => {
  await loadSettings()
  await loadMappings()
  await loadSyncState()
})
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        @click="saveSettings"
        :disabled="saving || loading"
        class="inline-flex items-center gap-2 rounded-full bg-cyber-accent px-4 py-2 text-xs font-semibold text-white shadow-cyber transition hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-60"
      >
        <Save :size="14" />
        {{ saving ? '写入数据库中...' : '保存设置' }}
      </button>
    </template>

    <div class="space-y-6">
      <section class="rounded-[34px] border border-white/85 bg-[linear-gradient(140deg,rgba(255,250,244,0.92),rgba(244,239,231,0.96))] p-7 shadow-[0_26px_80px_rgba(90,60,30,0.10)]">
        <p class="text-sm tracking-[0.22em] text-cyber-accent-strong">系统设置</p>
        <h2 class="mt-3 font-display text-4xl font-semibold text-stone-900">数据库持久化与雷池对接</h2>
        <p class="mt-4 max-w-2xl text-sm leading-7 text-stone-700">
          当前页面会直接读取和写入后端 SQLite 配置。涉及监听、上游转发等运行时参数的改动，会在服务重启后生效。
        </p>
      </section>

      <div
        v-if="loading"
        class="rounded-[24px] border border-cyber-border/70 bg-white/75 px-5 py-4 text-sm text-cyber-muted shadow-[0_14px_30px_rgba(90,60,30,0.06)]"
      >
        正在从数据库加载设置...
      </div>

      <div
        v-if="error"
        class="rounded-[24px] border border-cyber-error/25 bg-cyber-error/8 px-5 py-4 text-sm text-cyber-error shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

      <div
        v-if="successMessage"
        class="rounded-[24px] border border-emerald-300/60 bg-emerald-50 px-5 py-4 text-sm text-emerald-800 shadow-[0_14px_30px_rgba(16,185,129,0.08)]"
      >
        {{ successMessage }}
      </div>

      <div class="grid gap-4 xl:grid-cols-3">
        <div
          v-for="item in settingsSummary"
          :key="item.title"
          class="rounded-[28px] border border-white/80 bg-white/76 p-5 shadow-[0_14px_38px_rgba(90,60,30,0.07)]"
        >
          <div class="flex h-12 w-12 items-center justify-center rounded-2xl bg-cyber-surface-strong text-cyber-accent-strong">
            <component :is="item.icon" :size="22" />
          </div>
          <p class="mt-4 text-xs tracking-[0.18em] text-cyber-muted">{{ item.title }}</p>
          <p class="mt-2 text-xl font-semibold text-stone-900">{{ item.value }}</p>
          <p class="mt-2 text-sm leading-6 text-stone-700">{{ item.desc }}</p>
        </div>
      </div>

      <div class="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <div class="space-y-6">
          <div class="rounded-[32px] border border-white/80 bg-white/80 p-6 shadow-[0_18px_50px_rgba(90,60,30,0.08)]">
            <div class="flex items-center gap-3">
              <div class="flex h-12 w-12 items-center justify-center rounded-2xl bg-cyber-surface-strong text-cyber-accent-strong">
                <Settings :size="22" />
              </div>
              <div>
                <p class="text-sm tracking-[0.18em] text-cyber-accent-strong">控制台参数</p>
                <h3 class="mt-1 text-xl font-semibold text-stone-900">基础运行配置</h3>
              </div>
            </div>

            <div class="mt-6 grid gap-5 md:grid-cols-2">
              <label class="space-y-2">
                <span class="text-sm text-cyber-muted">网关名称</span>
                <input v-model="systemSettings.gateway_name" type="text" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" />
              </label>
              <label class="space-y-2">
                <span class="text-sm text-cyber-muted">自动刷新频率（秒）</span>
                <input v-model.number="systemSettings.auto_refresh_seconds" type="number" min="3" max="60" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" />
              </label>
              <label class="space-y-2">
                <span class="text-sm text-cyber-muted">上游服务地址</span>
                <input v-model="systemSettings.upstream_endpoint" type="text" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" />
              </label>
              <label class="space-y-2">
                <span class="text-sm text-cyber-muted">控制面 API 地址</span>
                <input v-model="systemSettings.api_endpoint" type="text" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" />
              </label>
              <label class="space-y-2">
                <span class="text-sm text-cyber-muted">事件保留天数</span>
                <input v-model.number="systemSettings.retain_days" type="number" min="1" max="365" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" />
              </label>
              <label class="space-y-2">
                <span class="text-sm text-cyber-muted">通知级别</span>
                <select v-model="systemSettings.notification_level" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent">
                  <option value="critical">仅高风险事件</option>
                  <option value="blocked_only">仅拦截事件</option>
                  <option value="all">全部事件</option>
                </select>
              </label>
            </div>

            <div class="mt-6 grid gap-4 md:grid-cols-3">
              <label class="flex items-start gap-3 rounded-[24px] border border-cyber-border/70 bg-cyber-surface-strong p-4">
                <input v-model="systemSettings.emergency_mode" type="checkbox" class="mt-1 accent-[var(--color-cyber-accent)]" />
                <span>
                  <span class="block text-sm font-medium text-stone-900">紧急模式</span>
                  <span class="mt-1 block text-sm leading-6 text-cyber-muted">面向突发攻击时的高敏感运行状态。</span>
                </span>
              </label>
              <label class="flex items-start gap-3 rounded-[24px] border border-cyber-border/70 bg-cyber-surface-strong p-4">
                <input v-model="systemSettings.sqlite_persistence" type="checkbox" class="mt-1 accent-[var(--color-cyber-accent)]" />
                <span>
                  <span class="block text-sm font-medium text-stone-900">启用持久化</span>
                  <span class="mt-1 block text-sm leading-6 text-cyber-muted">保存到后端 SQLite 配置与事件库。</span>
                </span>
              </label>
              <label class="flex items-start gap-3 rounded-[24px] border border-cyber-border/70 bg-cyber-surface-strong p-4">
                <input v-model="systemSettings.notify_by_sound" type="checkbox" class="mt-1 accent-[var(--color-cyber-accent)]" />
                <span>
                  <span class="block text-sm font-medium text-stone-900">声音提醒</span>
                  <span class="mt-1 block text-sm leading-6 text-cyber-muted">在控制台打开期间对关键事件进行即时提示。</span>
                </span>
              </label>
            </div>
          </div>

          <div class="rounded-[32px] border border-white/80 bg-[linear-gradient(160deg,rgba(247,239,225,0.92),rgba(255,255,255,0.84))] p-6 shadow-[0_18px_50px_rgba(90,60,30,0.08)]">
            <p class="text-sm tracking-[0.18em] text-cyber-accent-strong">值守备注</p>
            <textarea
              v-model="systemSettings.notes"
              rows="8"
              class="mt-4 w-full rounded-[24px] border border-cyber-border bg-white px-4 py-4 outline-none transition focus:border-cyber-accent"
            ></textarea>
            <p class="mt-3 text-xs leading-6 text-cyber-muted">
              {{ settingsSavedAt ? `最近写入数据库：${formatTimestamp(settingsSavedAt)}` : '尚未写入数据库' }}
            </p>
          </div>
        </div>

        <div class="space-y-6">
          <div class="rounded-[32px] border border-white/80 bg-white/80 p-6 shadow-[0_18px_50px_rgba(90,60,30,0.08)]">
            <div class="flex items-center gap-3">
              <div class="flex h-12 w-12 items-center justify-center rounded-2xl bg-cyber-surface-strong text-cyber-accent-strong">
                <PlugZap :size="22" />
              </div>
              <div>
                <p class="text-sm tracking-[0.18em] text-cyber-accent-strong">雷池接入</p>
                <h3 class="mt-1 text-xl font-semibold text-stone-900">OpenAPI 基础配置</h3>
              </div>
            </div>

            <div class="mt-6 space-y-5">
              <label class="flex items-start gap-3 rounded-[24px] border border-cyber-border/70 bg-cyber-surface-strong p-4">
                <input v-model="systemSettings.safeline.enabled" type="checkbox" class="mt-1 accent-[var(--color-cyber-accent)]" />
                <span>
                  <span class="block text-sm font-medium text-stone-900">启用雷池集成</span>
                  <span class="mt-1 block text-sm leading-6 text-cyber-muted">保存后写入 SQLite，供后续日志同步和策略联动复用。</span>
                </span>
              </label>

              <label class="space-y-2">
                <span class="text-sm text-cyber-muted">雷池地址</span>
                <input v-model="systemSettings.safeline.base_url" type="text" placeholder="https://127.0.0.1:9443" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" />
              </label>

              <label class="space-y-2">
                <span class="text-sm text-cyber-muted">API Token</span>
                <input v-model="systemSettings.safeline.api_token" type="password" placeholder="API-TOKEN" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" />
              </label>

              <div class="grid gap-5 md:grid-cols-2">
                <label class="space-y-2">
                  <span class="text-sm text-cyber-muted">OpenAPI 文档路径</span>
                  <input v-model="systemSettings.safeline.openapi_doc_path" type="text" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" />
                </label>
                <label class="space-y-2">
                  <span class="text-sm text-cyber-muted">鉴权探测路径</span>
                  <input v-model="systemSettings.safeline.auth_probe_path" type="text" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" />
                </label>
                <label class="space-y-2 md:col-span-2">
                  <span class="text-sm text-cyber-muted">站点列表路径</span>
                  <input v-model="systemSettings.safeline.site_list_path" type="text" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" />
                </label>
                <label class="space-y-2 md:col-span-2">
                  <span class="text-sm text-cyber-muted">事件列表路径</span>
                  <input v-model="systemSettings.safeline.event_list_path" type="text" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" />
                </label>
              </div>

              <label class="flex items-start gap-3 rounded-[24px] border border-cyber-border/70 bg-cyber-surface-strong p-4">
                <input v-model="systemSettings.safeline.verify_tls" type="checkbox" class="mt-1 accent-[var(--color-cyber-accent)]" />
                <span>
                  <span class="block text-sm font-medium text-stone-900">校验证书</span>
                  <span class="mt-1 block text-sm leading-6 text-cyber-muted">开启后会严格校验雷池 HTTPS 证书；自签名环境建议先关闭测试。</span>
                </span>
              </label>

              <div class="flex items-center gap-3">
                <button
                  @click="runSafeLineTest"
                  :disabled="testing || loading"
                  class="inline-flex items-center gap-2 rounded-full border border-cyber-accent/25 bg-cyber-surface-strong px-4 py-2 text-xs font-semibold text-cyber-accent-strong transition hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <PlugZap :size="14" />
                  {{ testing ? '测试中...' : '测试雷池连接' }}
                </button>
                <button
                  @click="loadSafeLineSites"
                  :disabled="loadingSites || loading"
                  class="inline-flex items-center gap-2 rounded-full border border-cyber-accent/25 bg-white px-4 py-2 text-xs font-semibold text-cyber-accent-strong transition hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <ServerCog :size="14" />
                  {{ loadingSites ? '读取中...' : '读取站点列表' }}
                </button>
                <button
                  @click="saveMappings"
                  :disabled="savingMappings || sites.length === 0"
                  class="inline-flex items-center gap-2 rounded-full border border-cyber-accent/25 bg-white px-4 py-2 text-xs font-semibold text-cyber-accent-strong transition hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <Save :size="14" />
                  {{ savingMappings ? '保存中...' : '保存站点映射' }}
                </button>
                <button
                  @click="runEventSync"
                  :disabled="syncingEvents"
                  class="inline-flex items-center gap-2 rounded-full border border-cyber-accent/25 bg-white px-4 py-2 text-xs font-semibold text-cyber-accent-strong transition hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <BellRing :size="14" />
                  {{ syncingEvents ? '同步中...' : '立即同步雷池事件' }}
                </button>
                <p class="text-xs leading-6 text-cyber-muted">当前测试不会改动雷池配置，只会做连通性和鉴权探测。</p>
              </div>
            </div>
          </div>

          <div
            class="rounded-[32px] border p-6 shadow-[0_18px_50px_rgba(90,60,30,0.08)]"
            :class="testToneClass"
          >
            <p class="text-sm tracking-[0.18em]">连通性反馈</p>
            <h3 class="mt-2 text-xl font-semibold">雷池探测结果</h3>
            <p class="mt-4 text-sm leading-7">
              {{
                testResult
                  ? testResult.message
                  : '保存前可以先做一次连接测试。当前默认先验证 OpenAPI 文档入口，再尝试带 API-TOKEN 访问一个只读探测路径。'
              }}
            </p>
            <div v-if="testResult" class="mt-4 grid gap-3 text-sm md:grid-cols-2">
              <p>文档入口：{{ testResult.openapi_doc_reachable ? '可访问' : '不可访问' }}</p>
              <p>文档状态码：{{ testResult.openapi_doc_status ?? '-' }}</p>
              <p>鉴权结果：{{ testResult.authenticated ? '通过' : '未确认' }}</p>
              <p>探测状态码：{{ testResult.auth_probe_status ?? '-' }}</p>
            </div>
          </div>

          <div class="rounded-[32px] border border-white/80 bg-white/80 p-6 shadow-[0_18px_50px_rgba(90,60,30,0.08)]">
            <p class="text-sm tracking-[0.18em] text-cyber-accent-strong">同步状态</p>
            <h3 class="mt-2 text-xl font-semibold text-stone-900">雷池事件同步游标</h3>
            <p class="mt-4 text-sm leading-7 text-stone-700">
              {{
                syncState
                  ? `最近一次同步新增 ${syncState.last_imported_count} 条，跳过 ${syncState.last_skipped_count} 条重复事件。`
                  : '尚未建立雷池事件同步状态。第一次同步后，这里会显示最近一次同步的游标和计数。'
              }}
            </p>
            <div v-if="syncState" class="mt-4 grid gap-3 text-sm md:grid-cols-2">
              <p>资源：{{ syncState.resource }}</p>
              <p>最近成功时间：{{ syncState.last_success_at ? formatTimestamp(syncState.last_success_at) : '-' }}</p>
              <p>最近游标：{{ syncState.last_cursor ?? '-' }}</p>
              <p>状态更新时间：{{ formatTimestamp(syncState.updated_at) }}</p>
            </div>
          </div>

          <div class="rounded-[32px] border border-white/80 bg-white/80 p-6 shadow-[0_18px_50px_rgba(90,60,30,0.08)]">
            <p class="text-sm tracking-[0.18em] text-cyber-accent-strong">站点发现</p>
            <h3 class="mt-2 text-xl font-semibold text-stone-900">雷池站点列表预览</h3>
            <p class="mt-4 text-sm leading-7 text-stone-700">
              {{ sites.length > 0 ? `当前识别到 ${sites.length} 个站点。` : '可以直接用当前表单里的雷池地址、Token 和站点列表路径做一次即时读取。' }}
            </p>
            <p class="mt-2 text-xs leading-6 text-cyber-muted">
              {{ sitesLoadedAt ? `最近读取：${formatTimestamp(sitesLoadedAt)}` : '尚未读取站点列表' }}
            </p>

            <div v-if="sites.length > 0" class="mt-5 space-y-3">
              <div
                v-for="site in sites"
                :key="`${site.id}-${site.domain}`"
                class="rounded-[24px] border border-cyber-border/70 bg-cyber-surface-strong p-4"
              >
                <div class="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p class="text-sm font-semibold text-stone-900">{{ site.name || '未命名站点' }}</p>
                    <p class="mt-1 text-xs text-cyber-muted">{{ site.domain || '未识别域名' }}</p>
                  </div>
                  <div class="text-right">
                    <p class="text-xs tracking-[0.14em] text-cyber-muted">状态</p>
                    <p class="mt-1 text-sm font-medium text-cyber-accent-strong">{{ site.status || 'unknown' }}</p>
                  </div>
                </div>
                <p class="mt-3 text-xs text-cyber-muted">ID：{{ site.id || '未识别' }}</p>
                <div class="mt-4 grid gap-4 md:grid-cols-2">
                  <label class="space-y-2">
                    <span class="text-xs text-cyber-muted">本地别名</span>
                    <input
                      :value="siteMappingDraft(site).local_alias"
                      @input="setDraftAlias(site.id, ($event.target as HTMLInputElement).value)"
                      type="text"
                      class="w-full rounded-[18px] border border-cyber-border bg-white px-3 py-2 text-sm outline-none transition focus:border-cyber-accent"
                    />
                  </label>
                  <label class="space-y-2">
                    <span class="text-xs text-cyber-muted">备注</span>
                    <input
                      :value="siteMappingDraft(site).notes"
                      @input="setDraftNotes(site.id, ($event.target as HTMLInputElement).value)"
                      type="text"
                      class="w-full rounded-[18px] border border-cyber-border bg-white px-3 py-2 text-sm outline-none transition focus:border-cyber-accent"
                    />
                  </label>
                </div>
                <div class="mt-4 flex flex-wrap gap-4 text-sm text-stone-700">
                  <label class="inline-flex items-center gap-2">
                    <input
                      :checked="siteMappingDraft(site).enabled"
                      @change="setDraftEnabled(site.id, ($event.target as HTMLInputElement).checked)"
                      type="checkbox"
                      class="accent-[var(--color-cyber-accent)]"
                    />
                    启用映射
                  </label>
                  <label class="inline-flex items-center gap-2">
                    <input
                      :checked="siteMappingDraft(site).is_primary"
                      @change="setDraftPrimary(site.id, ($event.target as HTMLInputElement).checked)"
                      type="checkbox"
                      class="accent-[var(--color-cyber-accent)]"
                    />
                    设为主站点
                  </label>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </AppLayout>
</template>
