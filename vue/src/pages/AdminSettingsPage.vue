<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import AppLayout from '../components/layout/AppLayout.vue'
import {
  fetchSafeLineMappings,
  fetchSafeLineSites,
  fetchSettings,
  testSafeLineConnection,
  updateSafeLineMappings,
  updateSettings,
} from '../lib/api'
import type {
  SafeLineMappingItem,
  SafeLineSiteItem,
  SafeLineTestResponse,
  SettingsPayload,
} from '../lib/types'
import { PlugZap, Save, ServerCog, Settings } from 'lucide-vue-next'

interface SystemSettingsForm extends SettingsPayload {}

const loading = ref(true)
const saving = ref(false)
const testing = ref(false)
const loadingSites = ref(false)
const savingMappings = ref(false)
const error = ref('')
const successMessage = ref('')
const testResult = ref<SafeLineTestResponse | null>(null)
const sites = ref<SafeLineSiteItem[]>([])
const mappings = ref<SafeLineMappingItem[]>([])
const sitesLoadedAt = ref<number | null>(null)

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
    auth_probe_path: '/api/open/system/key',
    site_list_path: '/api/open/site',
    event_list_path: '/api/open/records',
    blocklist_sync_path: '/api/open/ipgroup',
    blocklist_delete_path: '/api/open/ipgroup',
  },
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

onMounted(async () => {
  await loadSettings()
  await loadMappings()
})
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        @click="saveSettings"
        :disabled="saving || loading"
        class="inline-flex items-center gap-2 rounded-lg bg-cyber-accent px-3 py-1.5 text-xs font-medium text-white shadow-sm transition hover:bg-cyber-accent/90 disabled:cursor-not-allowed disabled:opacity-60"
      >
        <Save :size="12" />
        {{ saving ? '保存中...' : '保存设置' }}
      </button>
    </template>

    <div class="space-y-4">
      <div
        v-if="loading"
        class="rounded-[20px] border border-cyber-border/70 bg-white/75 px-4 py-3 text-sm text-cyber-muted shadow-[0_10px_25px_rgba(90,60,30,0.05)]"
      >
        正在从数据库加载设置...
      </div>

      <div
        v-if="error"
        class="rounded-[20px] border border-cyber-error/25 bg-cyber-error/8 px-4 py-3 text-sm text-cyber-error shadow-[0_10px_25px_rgba(166,30,77,0.07)]"
      >
        {{ error }}
      </div>

      <div
        v-if="successMessage"
        class="rounded-[20px] border border-emerald-300/60 bg-emerald-50 px-4 py-3 text-sm text-emerald-800 shadow-[0_10px_25px_rgba(16,185,129,0.07)]"
      >
        {{ successMessage }}
      </div>

      <div class="space-y-4 max-w-5xl mx-auto">
          <div class="rounded-[24px] border border-white/80 bg-white/80 p-5 shadow-[0_14px_30px_rgba(90,60,30,0.06)]">
            <div class="flex items-center gap-3">
              <div class="flex h-10 w-10 items-center justify-center rounded-xl bg-cyber-surface-strong text-cyber-accent-strong">
                <Settings :size="20" />
              </div>
              <div>
                <p class="text-xs tracking-[0.18em] text-cyber-accent-strong">控制台参数</p>
                <h3 class="mt-0.5 text-lg font-semibold text-stone-900">基础运行配置</h3>
              </div>
            </div>

            <div class="mt-5 grid gap-4 md:grid-cols-2">
              <label class="space-y-1.5">
                <span class="text-xs text-cyber-muted">网关名称</span>
                <input v-model="systemSettings.gateway_name" type="text" class="w-full rounded-[16px] border border-cyber-border bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-cyber-accent" />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-cyber-muted">自动刷新频率（秒）</span>
                <input v-model.number="systemSettings.auto_refresh_seconds" type="number" min="3" max="60" class="w-full rounded-[16px] border border-cyber-border bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-cyber-accent" />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-cyber-muted">上游服务地址</span>
                <input v-model="systemSettings.upstream_endpoint" type="text" class="w-full rounded-[16px] border border-cyber-border bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-cyber-accent" />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-cyber-muted">控制面 API 地址</span>
                <input v-model="systemSettings.api_endpoint" type="text" class="w-full rounded-[16px] border border-cyber-border bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-cyber-accent" />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-cyber-muted">事件保留天数</span>
                <input v-model.number="systemSettings.retain_days" type="number" min="1" max="365" class="w-full rounded-[16px] border border-cyber-border bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-cyber-accent" />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-cyber-muted">通知级别</span>
                <select v-model="systemSettings.notification_level" class="w-full rounded-[16px] border border-cyber-border bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-cyber-accent">
                  <option value="critical">仅高风险事件</option>
                  <option value="blocked_only">仅拦截事件</option>
                  <option value="all">全部事件</option>
                </select>
              </label>
            </div>

            <div class="mt-4 grid gap-3 md:grid-cols-3">
              <label class="flex items-start gap-2.5 rounded-[20px] border border-cyber-border/70 bg-cyber-surface-strong p-3">
                <input v-model="systemSettings.emergency_mode" type="checkbox" class="mt-0.5 accent-[var(--color-cyber-accent)]" />
                <span>
                  <span class="block text-sm font-medium text-stone-900">紧急模式</span>
                  <span class="mt-0.5 block text-xs leading-5 text-cyber-muted">面向突发攻击时的高敏感运行状态。</span>
                </span>
              </label>
              <label class="flex items-start gap-2.5 rounded-[20px] border border-cyber-border/70 bg-cyber-surface-strong p-3">
                <input v-model="systemSettings.sqlite_persistence" type="checkbox" class="mt-0.5 accent-[var(--color-cyber-accent)]" />
                <span>
                  <span class="block text-sm font-medium text-stone-900">启用持久化</span>
                  <span class="mt-0.5 block text-xs leading-5 text-cyber-muted">保存到后端 SQLite 配置与事件库。</span>
                </span>
              </label>
              <label class="flex items-start gap-2.5 rounded-[20px] border border-cyber-border/70 bg-cyber-surface-strong p-3">
                <input v-model="systemSettings.notify_by_sound" type="checkbox" class="mt-0.5 accent-[var(--color-cyber-accent)]" />
                <span>
                  <span class="block text-sm font-medium text-stone-900">声音提醒</span>
                  <span class="mt-0.5 block text-xs leading-5 text-cyber-muted">在控制台打开期间对关键事件进行即时提示。</span>
                </span>
              </label>
            </div>
          </div>

          <div class="rounded-[24px] border border-white/80 bg-white/80 p-5 shadow-[0_14px_30px_rgba(90,60,30,0.06)]">
            <div class="flex items-center gap-3">
              <div class="flex h-10 w-10 items-center justify-center rounded-xl bg-cyber-surface-strong text-cyber-accent-strong">
                <PlugZap :size="20" />
              </div>
              <div>
                <p class="text-xs tracking-[0.18em] text-cyber-accent-strong">雷池接入</p>
                <h3 class="mt-0.5 text-lg font-semibold text-stone-900">OpenAPI 基础配置</h3>
              </div>
            </div>

            <div class="mt-5 space-y-4">
              <label class="flex items-start gap-2.5 rounded-[20px] border border-cyber-border/70 bg-cyber-surface-strong p-3">
                <input v-model="systemSettings.safeline.enabled" type="checkbox" class="mt-0.5 accent-[var(--color-cyber-accent)]" />
                <span>
                  <span class="block text-sm font-medium text-stone-900">启用雷池集成</span>
                  <span class="mt-0.5 block text-xs leading-5 text-cyber-muted">保存后写入 SQLite，供后续日志同步和策略联动复用。</span>
                </span>
              </label>

              <label class="space-y-1.5">
                <span class="text-xs text-cyber-muted">雷池地址</span>
                <input v-model="systemSettings.safeline.base_url" type="text" placeholder="https://127.0.0.1:9443" class="w-full rounded-[16px] border border-cyber-border bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-cyber-accent" />
              </label>

              <label class="space-y-1.5">
                <span class="text-xs text-cyber-muted">API Token</span>
                <input v-model="systemSettings.safeline.api_token" type="password" placeholder="API-TOKEN" class="w-full rounded-[16px] border border-cyber-border bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-cyber-accent" />
              </label>

              <div class="grid gap-4 md:grid-cols-2">
                <label class="space-y-1.5">
                  <span class="text-xs text-cyber-muted">OpenAPI 文档路径</span>
                  <input v-model="systemSettings.safeline.openapi_doc_path" type="text" class="w-full rounded-[16px] border border-cyber-border bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-cyber-accent" />
                </label>
                <label class="space-y-1.5">
                  <span class="text-xs text-cyber-muted">鉴权探测路径</span>
                  <input v-model="systemSettings.safeline.auth_probe_path" type="text" class="w-full rounded-[16px] border border-cyber-border bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-cyber-accent" />
                </label>
                <label class="space-y-1.5 md:col-span-2">
                  <span class="text-xs text-cyber-muted">站点列表路径</span>
                  <input v-model="systemSettings.safeline.site_list_path" type="text" class="w-full rounded-[16px] border border-cyber-border bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-cyber-accent" />
                </label>
                <label class="space-y-1.5 md:col-span-2">
                  <span class="text-xs text-cyber-muted">事件列表路径</span>
                  <input v-model="systemSettings.safeline.event_list_path" type="text" class="w-full rounded-[16px] border border-cyber-border bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-cyber-accent" />
                </label>
                <label class="space-y-1.5 md:col-span-2">
                  <span class="text-xs text-cyber-muted">封禁同步路径</span>
                  <input v-model="systemSettings.safeline.blocklist_sync_path" type="text" class="w-full rounded-[16px] border border-cyber-border bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-cyber-accent" />
                </label>
                <label class="space-y-1.5 md:col-span-2">
                  <span class="text-xs text-cyber-muted">远端解封路径</span>
                  <input v-model="systemSettings.safeline.blocklist_delete_path" type="text" class="w-full rounded-[16px] border border-cyber-border bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-cyber-accent" />
                </label>
              </div>

              <label class="flex items-start gap-2.5 rounded-[20px] border border-cyber-border/70 bg-cyber-surface-strong p-3">
                <input v-model="systemSettings.safeline.verify_tls" type="checkbox" class="mt-0.5 accent-[var(--color-cyber-accent)]" />
                <span>
                  <span class="block text-sm font-medium text-stone-900">校验证书</span>
                  <span class="mt-0.5 block text-xs leading-5 text-cyber-muted">开启后会严格校验雷池 HTTPS 证书；自签名环境建议先关闭测试。</span>
                </span>
              </label>

              <div class="flex flex-wrap items-center gap-2.5">
                <button
                  @click="runSafeLineTest"
                  :disabled="testing || loading"
                  class="inline-flex items-center gap-1.5 rounded-lg border border-cyber-accent/25 bg-cyber-surface-strong px-3 py-1.5 text-xs font-medium text-cyber-accent-strong transition hover:bg-cyber-surface-strong/80 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <PlugZap :size="12" />
                  {{ testing ? '测试中...' : '测试雷池连接' }}
                </button>
                <button
                  @click="loadSafeLineSites"
                  :disabled="loadingSites || loading"
                  class="inline-flex items-center gap-1.5 rounded-lg border border-cyber-accent/25 bg-white px-3 py-1.5 text-xs font-medium text-cyber-accent-strong transition hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <ServerCog :size="12" />
                  {{ loadingSites ? '读取中...' : '读取站点列表' }}
                </button>
                <button
                  @click="saveMappings"
                  :disabled="savingMappings || sites.length === 0"
                  class="inline-flex items-center gap-1.5 rounded-lg border border-cyber-accent/25 bg-white px-3 py-1.5 text-xs font-medium text-cyber-accent-strong transition hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <Save :size="12" />
                  {{ savingMappings ? '保存中...' : '保存站点映射' }}
                </button>
                <p class="text-xs leading-5 text-cyber-muted">当前测试不会改动雷池配置，只会做连通性和鉴权探测。</p>
              </div>
            </div>
          </div>
      </div>
    </div>
  </AppLayout>
</template>
