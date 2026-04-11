<script setup lang="ts">
import { computed } from 'vue'
import { PlugZap, Save, ServerCog } from 'lucide-vue-next'
import type { SafeLineTestResponse, SafeLineSiteItem } from '../../lib/types'
import type { SystemSettingsForm } from '../../lib/adminSettings'

const props = defineProps<{
  formatTimestamp: (timestamp: number | null) => string
  loading: boolean
  loadingSites: boolean
  mappingDrafts: Array<{
    safeline_site_id: string
    safeline_site_name: string
    safeline_site_domain: string
    local_alias: string
    enabled: boolean
    is_primary: boolean
    notes: string
    updated_at: number | null
  }>
  savingMappings: boolean
  sites: SafeLineSiteItem[]
  sitesLoadedAt: number | null
  systemSettings: SystemSettingsForm
  testResult: SafeLineTestResponse | null
  testing: boolean
}>()

const emit = defineEmits<{
  loadSites: []
  saveMappings: []
  test: []
  'update:systemSettings': [value: SystemSettingsForm]
}>()

function updateSafeLine(patch: Partial<SystemSettingsForm['safeline']>) {
  emit('update:systemSettings', {
    ...props.systemSettings,
    safeline: {
      ...props.systemSettings.safeline,
      ...patch,
    },
  })
}

const baseUrl = computed({
  get: () => props.systemSettings.safeline.base_url,
  set: (value: string) => updateSafeLine({ base_url: value }),
})
const apiToken = computed({
  get: () => props.systemSettings.safeline.api_token,
  set: (value: string) => updateSafeLine({ api_token: value }),
})
const username = computed({
  get: () => props.systemSettings.safeline.username,
  set: (value: string) => updateSafeLine({ username: value }),
})
const password = computed({
  get: () => props.systemSettings.safeline.password,
  set: (value: string) => updateSafeLine({ password: value }),
})
const verifyTls = computed({
  get: () => props.systemSettings.safeline.verify_tls,
  set: (value: boolean) => updateSafeLine({ verify_tls: value }),
})
const autoSyncEvents = computed({
  get: () => props.systemSettings.safeline.auto_sync_events,
  set: (value: boolean) => updateSafeLine({ auto_sync_events: value }),
})
const autoSyncPush = computed({
  get: () => props.systemSettings.safeline.auto_sync_blocked_ips_push,
  set: (value: boolean) =>
    updateSafeLine({ auto_sync_blocked_ips_push: value }),
})
const autoSyncPull = computed({
  get: () => props.systemSettings.safeline.auto_sync_blocked_ips_pull,
  set: (value: boolean) =>
    updateSafeLine({ auto_sync_blocked_ips_pull: value }),
})
const autoSyncInterval = computed({
  get: () => props.systemSettings.safeline.auto_sync_interval_secs,
  set: (value: number) => updateSafeLine({ auto_sync_interval_secs: value }),
})
</script>

<template>
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
      <div class="grid gap-4 md:grid-cols-2">
        <label class="space-y-1.5">
          <span class="text-xs text-slate-500">雷池地址</span>
          <input
            v-model="baseUrl"
            type="text"
            placeholder="https://127.0.0.1:9443"
            class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
          />
        </label>
        <label class="space-y-1.5">
          <span class="text-xs text-slate-500">API Token</span>
          <input
            v-model="apiToken"
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
            v-model="username"
            type="text"
            placeholder="用户名"
            class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
          />
        </label>
        <label class="space-y-1.5">
          <span class="text-xs text-slate-500">雷池密码</span>
          <input
            v-model="password"
            type="password"
            placeholder="密码"
            class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
          />
        </label>
      </div>

      <div class="flex flex-wrap items-center justify-end gap-2.5">
        <label
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm text-stone-700"
        >
          <input v-model="verifyTls" type="checkbox" class="accent-blue-600" />
          <span>校验证书</span>
        </label>
        <label
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm text-stone-700"
        >
          <input
            v-model="autoSyncEvents"
            type="checkbox"
            class="accent-blue-600"
          />
          <span>同步事件</span>
        </label>
        <label
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm text-stone-700"
        >
          <input
            v-model="autoSyncPush"
            type="checkbox"
            class="accent-blue-600"
          />
          <span>推送封禁</span>
        </label>
        <label
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm text-stone-700"
        >
          <input
            v-model="autoSyncPull"
            type="checkbox"
            class="accent-blue-600"
          />
          <span>回流封禁</span>
        </label>
        <label
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm text-stone-700"
        >
          <span>自动</span>
          <input
            v-model.number="autoSyncInterval"
            type="number"
            min="15"
            max="86400"
            step="15"
            class="w-20 appearance-none border-0 bg-transparent p-0 text-center text-sm text-stone-900 outline-none"
          />
          <span>秒同步</span>
        </label>
      </div>

      <div class="flex flex-wrap items-center justify-end gap-2.5">
        <button
          :disabled="testing || loading"
          class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-slate-50 px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('test')"
        >
          <PlugZap :size="12" />
          {{ testing ? '测试中...' : '测试雷池连接' }}
        </button>
        <button
          :disabled="loadingSites || loading"
          class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-white px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('loadSites')"
        >
          <ServerCog :size="12" />
          {{ loadingSites ? '读取中...' : '读取站点列表' }}
        </button>
        <button
          :disabled="savingMappings || sites.length === 0"
          class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-white px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('saveMappings')"
        >
          <Save :size="12" />
          {{ savingMappings ? '保存中...' : '保存站点映射' }}
        </button>
      </div>

      <div
        v-if="testResult"
        class="rounded-lg border border-slate-200 bg-slate-50 p-4"
      >
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p class="text-sm font-medium text-stone-900">连通性测试结果</p>
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
              testResult.status === 'ok'
                ? '通过'
                : testResult.status === 'warning'
                  ? '需确认'
                  : '失败'
            }}
          </span>
        </div>

        <div class="mt-3 grid gap-3 md:grid-cols-2">
          <div
            class="rounded-[16px] border border-slate-200 bg-white px-3.5 py-3"
          >
            <p class="text-xs text-slate-500">OpenAPI 文档</p>
            <p class="mt-1 text-sm font-medium text-stone-900">
              {{ testResult.openapi_doc_reachable ? '可访问' : '不可访问' }}
              <span
                v-if="testResult.openapi_doc_status !== null"
                class="text-slate-500"
                >（HTTP {{ testResult.openapi_doc_status }}）</span
              >
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
                >（HTTP {{ testResult.auth_probe_status }}）</span
              >
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
            <p class="text-sm font-medium text-stone-900">站点列表读取结果</p>
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
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p class="text-sm font-medium text-stone-900">
                  {{ site.name || '未命名站点' }}
                </p>
                <p class="mt-1 font-mono text-xs text-slate-500">
                  {{ site.domain || '未提供域名' }}
                </p>
              </div>
              <div class="text-right text-xs text-slate-500">
                <p>ID：{{ site.id || '未提供' }}</p>
                <p class="mt-1">状态：{{ site.status || 'unknown' }}</p>
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
</template>
