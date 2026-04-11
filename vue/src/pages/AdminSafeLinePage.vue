<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import AppLayout from '../components/layout/AppLayout.vue'
import StatusBadge from '../components/ui/StatusBadge.vue'
import {
  fetchSafeLineMappings,
  fetchSafeLineSites,
  fetchSafeLineSyncState,
  fetchSettings,
  pullSafeLineBlockedIps,
  syncSafeLineBlockedIps,
  syncSafeLineEvents,
  testSafeLineConnection,
  updateSafeLineMappings,
} from '../lib/api'
import type {
  SafeLineMappingItem,
  SafeLineSiteItem,
  SafeLineSyncOverviewResponse,
  SafeLineSyncStateResponse,
  SafeLineTestResponse,
  SettingsPayload,
} from '../lib/types'
import { useFormatters } from '../composables/useFormatters'
import {
  Download,
  PlugZap,
  RefreshCw,
  Save,
  ServerCog,
  ShieldCheck,
  Upload,
} from 'lucide-vue-next'

interface SafeLineMappingDraft {
  safeline_site_id: string
  safeline_site_name: string
  safeline_site_domain: string
  local_alias: string
  enabled: boolean
  is_primary: boolean
  notes: string
  updated_at: number | null
  orphaned: boolean
}

const { formatTimestamp } = useFormatters()

const loading = ref(true)
const error = ref('')
const successMessage = ref('')
const settings = ref<SettingsPayload | null>(null)
const mappings = ref<SafeLineMappingItem[]>([])
const sites = ref<SafeLineSiteItem[]>([])
const syncState = ref<SafeLineSyncOverviewResponse | null>(null)
const testResult = ref<SafeLineTestResponse | null>(null)
const mappingDrafts = ref<SafeLineMappingDraft[]>([])

const actions = reactive({
  refreshing: false,
  testing: false,
  loadingSites: false,
  syncingEvents: false,
  pushingBlocked: false,
  pullingBlocked: false,
  savingMappings: false,
})

function mergeMappingDrafts(
  siteList: SafeLineSiteItem[],
  mappingList: SafeLineMappingItem[],
) {
  const nextDrafts: SafeLineMappingDraft[] = siteList.map((site) => {
    const existing = mappingList.find(
      (item) => item.safeline_site_id === site.id,
    )
    return {
      safeline_site_id: site.id,
      safeline_site_name: site.name,
      safeline_site_domain: site.domain,
      local_alias: existing?.local_alias ?? site.name ?? site.domain ?? '',
      enabled: existing?.enabled ?? true,
      is_primary: existing?.is_primary ?? false,
      notes: existing?.notes ?? '',
      updated_at: existing?.updated_at ?? null,
      orphaned: false,
    }
  })

  const existingIds = new Set(nextDrafts.map((item) => item.safeline_site_id))
  for (const item of mappingList) {
    if (existingIds.has(item.safeline_site_id)) continue
    nextDrafts.push({
      safeline_site_id: item.safeline_site_id,
      safeline_site_name: item.safeline_site_name,
      safeline_site_domain: item.safeline_site_domain,
      local_alias: item.local_alias,
      enabled: item.enabled,
      is_primary: item.is_primary,
      notes: item.notes,
      updated_at: item.updated_at ?? null,
      orphaned: true,
    })
  }

  mappingDrafts.value = nextDrafts
}

const syncCards = computed(() => [
  {
    key: 'events',
    title: '事件同步',
    description: '把雷池攻击日志落到本地事件库，供事件页统一检索。',
    data: syncState.value?.events ?? null,
  },
  {
    key: 'blocked_ips_pull',
    title: '封禁回流',
    description: '把雷池远端封禁拉回本地名单，便于统一查看与解封。',
    data: syncState.value?.blocked_ips_pull ?? null,
  },
  {
    key: 'blocked_ips_push',
    title: '本地推送',
    description: '把本地封禁推到雷池，联动边界拦截策略。',
    data: syncState.value?.blocked_ips_push ?? null,
  },
  {
    key: 'blocked_ips_delete',
    title: '远端解封',
    description: '记录从本地触发雷池解封时的最近执行结果。',
    data: syncState.value?.blocked_ips_delete ?? null,
  },
])

const hasSavedConfig = computed(() =>
  Boolean(settings.value?.safeline.base_url.trim()),
)

const authMode = computed(() => {
  if (settings.value?.safeline.api_token.trim()) return 'API Token'
  if (
    settings.value?.safeline.username.trim() &&
    settings.value?.safeline.password.trim()
  ) {
    return '账号密码'
  }
  return '未配置鉴权'
})

const sortedDrafts = computed(() =>
  [...mappingDrafts.value].sort((left, right) => {
    if (left.is_primary !== right.is_primary) return left.is_primary ? -1 : 1
    if (left.enabled !== right.enabled) return left.enabled ? -1 : 1
    if (left.orphaned !== right.orphaned) return left.orphaned ? 1 : -1
    return left.local_alias.localeCompare(right.local_alias, 'zh-CN')
  }),
)

function clearFeedback() {
  error.value = ''
  successMessage.value = ''
}

function syncStatusType(item: SafeLineSyncStateResponse | null) {
  if (!item) return 'muted'
  if (item.last_success_at) return 'success'
  return 'warning'
}

function syncStatusText(item: SafeLineSyncStateResponse | null) {
  if (!item) return '未执行'
  if (item.last_success_at) return '最近成功'
  return '已记录'
}

function selectPrimary(siteId: string) {
  for (const item of mappingDrafts.value) {
    item.is_primary = item.safeline_site_id === siteId
  }
}

function clearPrimary() {
  for (const item of mappingDrafts.value) {
    item.is_primary = false
  }
}

async function loadPageData() {
  loading.value = true
  clearFeedback()

  try {
    const [settingsResponse, mappingsResponse, syncResponse] =
      await Promise.all([
        fetchSettings(),
        fetchSafeLineMappings(),
        fetchSafeLineSyncState(),
      ])

    settings.value = settingsResponse
    mappings.value = mappingsResponse.mappings
    syncState.value = syncResponse
    mergeMappingDrafts(sites.value, mappings.value)
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取雷池联动信息失败'
  } finally {
    loading.value = false
  }
}

async function refreshSyncState() {
  actions.refreshing = true
  clearFeedback()

  try {
    syncState.value = await fetchSafeLineSyncState()
    successMessage.value = '联动状态已刷新。'
  } catch (e) {
    error.value = e instanceof Error ? e.message : '刷新联动状态失败'
  } finally {
    actions.refreshing = false
  }
}

async function runConnectionTest() {
  if (!settings.value) return

  actions.testing = true
  clearFeedback()

  try {
    testResult.value = await testSafeLineConnection(settings.value.safeline)
    successMessage.value = '连通性测试已完成。'
  } catch (e) {
    error.value = e instanceof Error ? e.message : '雷池连通性测试失败'
    testResult.value = null
  } finally {
    actions.testing = false
  }
}

async function loadRemoteSites() {
  if (!settings.value) return

  actions.loadingSites = true
  clearFeedback()

  try {
    const response = await fetchSafeLineSites(settings.value.safeline)
    sites.value = response.sites
    mergeMappingDrafts(sites.value, mappings.value)
    successMessage.value = `已读取 ${response.total} 个雷池站点。`
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取雷池站点失败'
  } finally {
    actions.loadingSites = false
  }
}

async function saveMappings() {
  actions.savingMappings = true
  clearFeedback()

  try {
    await updateSafeLineMappings({
      mappings: mappingDrafts.value.map((item) => ({
        safeline_site_id: item.safeline_site_id,
        safeline_site_name: item.safeline_site_name,
        safeline_site_domain: item.safeline_site_domain,
        local_alias: item.local_alias.trim(),
        enabled: item.enabled,
        is_primary: item.is_primary,
        notes: item.notes.trim(),
      })),
    })

    const mappingsResponse = await fetchSafeLineMappings()
    mappings.value = mappingsResponse.mappings
    mergeMappingDrafts(sites.value, mappings.value)
    successMessage.value = '站点映射已保存。'
  } catch (e) {
    error.value = e instanceof Error ? e.message : '保存站点映射失败'
  } finally {
    actions.savingMappings = false
  }
}

async function runEventSync() {
  actions.syncingEvents = true
  clearFeedback()

  try {
    const response = await syncSafeLineEvents()
    successMessage.value = response.message
    syncState.value = await fetchSafeLineSyncState()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '同步雷池事件失败'
  } finally {
    actions.syncingEvents = false
  }
}

async function runBlockedPush() {
  actions.pushingBlocked = true
  clearFeedback()

  try {
    const response = await syncSafeLineBlockedIps()
    successMessage.value = response.message
    syncState.value = await fetchSafeLineSyncState()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '推送本地封禁失败'
  } finally {
    actions.pushingBlocked = false
  }
}

async function runBlockedPull() {
  actions.pullingBlocked = true
  clearFeedback()

  try {
    const response = await pullSafeLineBlockedIps()
    successMessage.value = response.message
    syncState.value = await fetchSafeLineSyncState()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '拉取雷池封禁失败'
  } finally {
    actions.pullingBlocked = false
  }
}

onMounted(loadPageData)
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
        :disabled="actions.refreshing || loading"
        @click="refreshSyncState"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': actions.refreshing }" />
        刷新联动状态
      </button>
    </template>

    <div class="space-y-6">
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
        正在加载雷池联动面板...
      </div>

      <template v-else>
        <section class="grid gap-4 xl:grid-cols-[1fr_1.1fr] xl:items-start">
          <div
            class="rounded-xl border border-white/80 bg-white/78 p-4 shadow-[0_14px_40px_rgba(90,60,30,0.07)]"
          >
            <div class="flex items-center justify-between gap-3">
              <div>
                <p class="text-sm font-semibold text-stone-900">接入概况</p>
                <p class="mt-1 text-xs leading-5 text-slate-500">
                  当前展示的是已保存到后端数据库的雷池配置。
                </p>
              </div>
              <StatusBadge
                :text="settings?.safeline.enabled ? '已启用' : '未启用'"
                :type="settings?.safeline.enabled ? 'success' : 'warning'"
                compact
              />
            </div>

            <div class="mt-4 grid gap-3 md:grid-cols-2">
              <div class="rounded-lg bg-slate-50 p-4">
                <p class="text-xs text-slate-500">雷池地址</p>
                <p class="mt-2 break-all text-sm font-medium text-stone-900">
                  {{ settings?.safeline.base_url || '未配置' }}
                </p>
              </div>
              <div class="rounded-lg bg-slate-50 p-4">
                <p class="text-xs text-slate-500">鉴权方式</p>
                <p class="mt-2 text-sm font-medium text-stone-900">
                  {{ authMode }}
                </p>
              </div>
              <div class="rounded-lg bg-slate-50 p-4">
                <p class="text-xs text-slate-500">站点列表路径</p>
                <p class="mt-2 break-all font-mono text-xs text-stone-900">
                  {{ settings?.safeline.site_list_path || '未配置' }}
                </p>
              </div>
              <div class="rounded-lg bg-slate-50 p-4">
                <p class="text-xs text-slate-500">事件列表路径</p>
                <p class="mt-2 break-all font-mono text-xs text-stone-900">
                  {{ settings?.safeline.event_list_path || '未配置' }}
                </p>
              </div>
            </div>

            <div
              v-if="!hasSavedConfig"
              class="mt-4 rounded-lg border border-dashed border-slate-200 bg-white px-4 py-3 text-sm text-slate-500"
            >
              还没有保存雷池地址。请先到系统设置填写连接参数并保存，再回来执行联调。
            </div>

            <div class="mt-4 flex flex-wrap gap-2.5">
              <button
                :disabled="actions.testing || !hasSavedConfig"
                class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-slate-50 px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
                @click="runConnectionTest"
              >
                <PlugZap :size="12" />
                {{ actions.testing ? '测试中...' : '测试连接' }}
              </button>
              <button
                :disabled="actions.loadingSites || !hasSavedConfig"
                class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-white px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-60"
                @click="loadRemoteSites"
              >
                <ServerCog :size="12" />
                {{ actions.loadingSites ? '读取中...' : '读取远端站点' }}
              </button>
            </div>

            <div
              v-if="testResult"
              class="mt-4 rounded-lg border border-slate-200 bg-slate-50 p-4"
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

              <div class="mt-3 grid gap-3 md:grid-cols-2">
                <div
                  class="rounded-[16px] border border-slate-200 bg-white px-3.5 py-3"
                >
                  <p class="text-xs text-slate-500">OpenAPI 文档</p>
                  <p class="mt-1 text-sm font-medium text-stone-900">
                    {{
                      testResult.openapi_doc_reachable ? '可访问' : '不可访问'
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
                    {{ testResult.authenticated ? '已通过' : '未通过' }}
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
          </div>

          <div
            class="rounded-xl border border-white/80 bg-white/78 p-4 shadow-[0_14px_40px_rgba(90,60,30,0.07)]"
          >
            <div class="flex items-center justify-between gap-3">
              <div>
                <p class="text-sm font-semibold text-stone-900">联动操作</p>
                <p class="mt-1 text-xs leading-5 text-slate-500">
                  这些按钮直接调用后端已实现的雷池同步接口。
                </p>
              </div>
              <ShieldCheck :size="18" class="text-blue-700" />
            </div>

            <div class="mt-4 grid gap-3 md:grid-cols-2">
              <button
                :disabled="actions.syncingEvents"
                class="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-left transition hover:border-blue-500/40 disabled:cursor-not-allowed disabled:opacity-60"
                @click="runEventSync"
              >
                <span>
                  <span class="block text-sm font-medium text-stone-900"
                    >同步雷池事件</span
                  >
                  <span class="mt-1 block text-xs text-slate-500"
                    >写入本地事件库并套用站点映射。</span
                  >
                </span>
                <RefreshCw
                  :size="16"
                  :class="{ 'animate-spin': actions.syncingEvents }"
                />
              </button>

              <button
                :disabled="actions.pullingBlocked"
                class="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-left transition hover:border-blue-500/40 disabled:cursor-not-allowed disabled:opacity-60"
                @click="runBlockedPull"
              >
                <span>
                  <span class="block text-sm font-medium text-stone-900"
                    >拉取雷池封禁</span
                  >
                  <span class="mt-1 block text-xs text-slate-500"
                    >把远端封禁同步到本地封禁名单。</span
                  >
                </span>
                <Download :size="16" />
              </button>

              <button
                :disabled="actions.pushingBlocked"
                class="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-left transition hover:border-blue-500/40 disabled:cursor-not-allowed disabled:opacity-60"
                @click="runBlockedPush"
              >
                <span>
                  <span class="block text-sm font-medium text-stone-900"
                    >推送本地封禁</span
                  >
                  <span class="mt-1 block text-xs text-slate-500"
                    >把本地封禁联动到雷池。</span
                  >
                </span>
                <Upload :size="16" />
              </button>

              <button
                :disabled="actions.refreshing"
                class="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-left transition hover:border-blue-500/40 disabled:cursor-not-allowed disabled:opacity-60"
                @click="refreshSyncState"
              >
                <span>
                  <span class="block text-sm font-medium text-stone-900"
                    >刷新执行状态</span
                  >
                  <span class="mt-1 block text-xs text-slate-500"
                    >查看最近一次成功时间和导入统计。</span
                  >
                </span>
                <RefreshCw
                  :size="16"
                  :class="{ 'animate-spin': actions.refreshing }"
                />
              </button>
            </div>

            <div class="mt-3 grid gap-3">
              <article
                v-for="item in syncCards"
                :key="item.key"
                class="rounded-lg border border-slate-200 bg-white/80 p-4"
              >
                <div class="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p class="text-sm font-medium text-stone-900">
                      {{ item.title }}
                    </p>
                    <p class="mt-1 text-xs leading-5 text-slate-500">
                      {{ item.description }}
                    </p>
                  </div>
                  <StatusBadge
                    :text="syncStatusText(item.data)"
                    :type="syncStatusType(item.data)"
                    compact
                  />
                </div>
                <div
                  class="mt-3 grid gap-2 text-xs text-slate-500 md:grid-cols-2"
                >
                  <p>
                    最近成功：{{ formatTimestamp(item.data?.last_success_at) }}
                  </p>
                  <p>最近更新：{{ formatTimestamp(item.data?.updated_at) }}</p>
                  <p>最近导入：{{ item.data?.last_imported_count ?? 0 }}</p>
                  <p>最近跳过：{{ item.data?.last_skipped_count ?? 0 }}</p>
                </div>
              </article>
            </div>
          </div>
        </section>

        <section
          class="rounded-xl border border-white/80 bg-white/78 p-4 shadow-[0_14px_40px_rgba(90,60,30,0.07)]"
        >
          <div
            class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
          >
            <div>
              <p class="text-sm font-semibold text-stone-900">站点映射管理</p>
              <p class="mt-1 text-xs leading-5 text-slate-500">
                读取远端站点后，可以在这里补本地别名、是否启用和主站点标识。未出现在本次远端读取中的历史映射会保留。
              </p>
            </div>
            <div class="flex flex-wrap gap-2">
              <button
                class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                @click="clearPrimary"
              >
                清空主站点
              </button>
              <button
                :disabled="actions.savingMappings || !mappingDrafts.length"
                class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-slate-50 px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
                @click="saveMappings"
              >
                <Save :size="12" />
                {{ actions.savingMappings ? '保存中...' : '保存映射' }}
              </button>
            </div>
          </div>

          <div
            v-if="!sortedDrafts.length"
            class="mt-4 rounded-lg border border-dashed border-slate-200 bg-white px-4 py-8 text-sm text-slate-500"
          >
            还没有可编辑的站点映射。先点击上方"读取远端站点"，或确认数据库里已经有历史映射。
          </div>

          <div v-else class="mt-4 grid gap-4">
            <article
              v-for="draft in sortedDrafts"
              :key="draft.safeline_site_id"
              class="rounded-xl border border-slate-200 bg-slate-50 p-4"
            >
              <div
                class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between"
              >
                <div class="space-y-2">
                  <div class="flex flex-wrap items-center gap-2">
                    <p class="text-sm font-medium text-stone-900">
                      {{ draft.safeline_site_name || '未命名站点' }}
                    </p>
                    <StatusBadge
                      v-if="draft.enabled"
                      text="启用映射"
                      type="success"
                      compact
                    />
                    <StatusBadge v-else text="停用映射" type="muted" compact />
                    <StatusBadge
                      v-if="draft.is_primary"
                      text="主站点"
                      type="info"
                      compact
                    />
                    <StatusBadge
                      v-if="draft.orphaned"
                      text="历史映射"
                      type="warning"
                      compact
                    />
                  </div>
                  <p class="font-mono text-xs text-slate-500">
                    站点 ID：{{ draft.safeline_site_id }}
                  </p>
                  <p class="font-mono text-xs text-slate-500">
                    域名：{{ draft.safeline_site_domain || '未提供域名' }}
                  </p>
                  <p class="text-xs text-slate-500">
                    上次更新：{{ formatTimestamp(draft.updated_at) }}
                  </p>
                </div>

                <div class="grid gap-3 lg:w-[520px] md:grid-cols-[1.2fr_1fr]">
                  <label class="space-y-1.5">
                    <span class="text-xs text-slate-500">本地别名</span>
                    <input
                      v-model="draft.local_alias"
                      type="text"
                      class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                    />
                  </label>
                  <label class="space-y-1.5">
                    <span class="text-xs text-slate-500">备注</span>
                    <input
                      v-model="draft.notes"
                      type="text"
                      class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
                    />
                  </label>
                  <label
                    class="flex items-center gap-2 rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
                  >
                    <input
                      v-model="draft.enabled"
                      type="checkbox"
                      class="accent-blue-600"
                    />
                    启用该映射
                  </label>
                  <label
                    class="flex items-center gap-2 rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
                  >
                    <input
                      type="radio"
                      name="safeline-primary"
                      :checked="draft.is_primary"
                      class="accent-blue-600"
                      @change="selectPrimary(draft.safeline_site_id)"
                    />
                    设为主站点
                  </label>
                </div>
              </div>
            </article>
          </div>
        </section>
      </template>
    </div>
  </AppLayout>
</template>
