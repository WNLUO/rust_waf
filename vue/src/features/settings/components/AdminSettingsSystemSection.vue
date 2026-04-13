<script setup lang="ts">
import { computed } from 'vue'
import { PlugZap, Save, ServerCog, Settings } from 'lucide-vue-next'
import type { LocalCertificateItem, SafeLineTestResponse } from '@/shared/types'
import type { SystemSettingsForm } from '@/features/settings/utils/adminSettings'
import type { GlobalEntryConfigPayload } from '@/shared/types'

const props = defineProps<{
  globalEntryForm: GlobalEntryConfigPayload
  loading: boolean
  loadingSites: boolean
  localCertificates: LocalCertificateItem[]
  savingDefaultCertificate: boolean
  savingMappings: boolean
  sites: Array<{ id: string }>
  systemSettings: SystemSettingsForm
  testResult: SafeLineTestResponse | null
  testing: boolean
}>()

const emit = defineEmits<{
  defaultCertificateChange: [event: Event]
  loadSites: []
  saveMappings: []
  test: []
  'update:globalEntryForm': [value: GlobalEntryConfigPayload]
  'update:systemSettings': [value: SystemSettingsForm]
}>()

function updateSystemSettings(patch: Partial<SystemSettingsForm>) {
  emit('update:systemSettings', {
    ...props.systemSettings,
    ...patch,
  })
}

function updateGlobalEntryForm(patch: Partial<GlobalEntryConfigPayload>) {
  emit('update:globalEntryForm', {
    ...props.globalEntryForm,
    ...patch,
  })
}

const apiEndpoint = computed({
  get: () => props.systemSettings.api_endpoint,
  set: (value: string) => updateSystemSettings({ api_endpoint: value }),
})
const dropUnmatchedRequests = computed({
  get: () => props.systemSettings.drop_unmatched_requests,
  set: (value: boolean) =>
    updateSystemSettings({ drop_unmatched_requests: value }),
})
const defaultCertificateId = computed({
  get: () => props.systemSettings.default_certificate_id,
  set: (value: number | null) =>
    updateSystemSettings({ default_certificate_id: value }),
})
const globalHttpPort = computed({
  get: () => props.globalEntryForm.http_port,
  set: (value: string) => updateGlobalEntryForm({ http_port: value }),
})
const globalHttpsPort = computed({
  get: () => props.globalEntryForm.https_port,
  set: (value: string) => updateGlobalEntryForm({ https_port: value }),
})
const safeLineBaseUrl = computed({
  get: () => props.systemSettings.safeline.base_url,
  set: (value: string) =>
    updateSystemSettings({
      safeline: {
        ...props.systemSettings.safeline,
        base_url: value,
      },
    }),
})
const safeLineApiToken = computed({
  get: () => props.systemSettings.safeline.api_token,
  set: (value: string) =>
    updateSystemSettings({
      safeline: {
        ...props.systemSettings.safeline,
        api_token: value,
      },
    }),
})
const safeLineUsername = computed({
  get: () => props.systemSettings.safeline.username,
  set: (value: string) =>
    updateSystemSettings({
      safeline: {
        ...props.systemSettings.safeline,
        username: value,
      },
    }),
})
const safeLinePassword = computed({
  get: () => props.systemSettings.safeline.password,
  set: (value: string) =>
    updateSystemSettings({
      safeline: {
        ...props.systemSettings.safeline,
        password: value,
      },
    }),
})
const safeLineVerifyTls = computed({
  get: () => props.systemSettings.safeline.verify_tls,
  set: (value: boolean) =>
    updateSystemSettings({
      safeline: {
        ...props.systemSettings.safeline,
        verify_tls: value,
      },
    }),
})
const safeLineAutoSyncEvents = computed({
  get: () => props.systemSettings.safeline.auto_sync_events,
  set: (value: boolean) =>
    updateSystemSettings({
      safeline: {
        ...props.systemSettings.safeline,
        auto_sync_events: value,
      },
    }),
})
const safeLineAutoSyncPush = computed({
  get: () => props.systemSettings.safeline.auto_sync_blocked_ips_push,
  set: (value: boolean) =>
    updateSystemSettings({
      safeline: {
        ...props.systemSettings.safeline,
        auto_sync_blocked_ips_push: value,
      },
    }),
})
const safeLineAutoSyncPull = computed({
  get: () => props.systemSettings.safeline.auto_sync_blocked_ips_pull,
  set: (value: boolean) =>
    updateSystemSettings({
      safeline: {
        ...props.systemSettings.safeline,
        auto_sync_blocked_ips_pull: value,
      },
    }),
})
const safeLineAutoSyncInterval = computed({
  get: () => props.systemSettings.safeline.auto_sync_interval_secs,
  set: (value: number) =>
    updateSystemSettings({
      safeline: {
        ...props.systemSettings.safeline,
        auto_sync_interval_secs: value,
      },
    }),
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
        <Settings :size="20" />
      </div>
      <div>
        <p class="text-xs tracking-wide text-blue-700">控制台参数</p>
        <h3 class="mt-0.5 text-lg font-semibold text-stone-900">
          基础运行配置
        </h3>
      </div>
    </div>

    <div class="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
      <label class="space-y-1">
        <span class="text-xs text-slate-500">统一 HTTP 入口端口</span>
        <input
          v-model="globalHttpPort"
          type="text"
          inputmode="numeric"
          placeholder="例如 8080"
          class="w-full rounded-[14px] border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs text-slate-500">统一 HTTPS 入口端口</span>
        <input
          v-model="globalHttpsPort"
          type="text"
          inputmode="numeric"
          placeholder="例如 660，可留空关闭 HTTPS 入口"
          class="w-full rounded-[14px] border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs text-slate-500">控制面 API 地址</span>
        <input
          v-model="apiEndpoint"
          type="text"
          class="w-full rounded-[14px] border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
        />
      </label>
      <label class="space-y-1">
        <span class="text-xs text-slate-500">默认证书</span>
        <select
          v-model="defaultCertificateId"
          :disabled="savingDefaultCertificate"
          class="w-full rounded-[14px] border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
          @change="emit('defaultCertificateChange', $event)"
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
    </div>

    <p class="mt-3 text-xs leading-5 text-slate-500">
      全局入口保存时会校验端口是否已被其他进程占用；如果端口可用，保存后 Rust 会立即接管监听。
    </p>

    <label
      class="mt-3 inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-sm text-stone-700"
    >
      <input
        v-model="dropUnmatchedRequests"
        type="checkbox"
        class="accent-blue-600"
      />
      <span>未命中站点时直接断开连接</span>
    </label>
    <p class="mt-2 text-xs leading-5 text-slate-500">
      开启后，不返回任何页面内容；关闭时，未命中站点会返回 404。
    </p>

    <div class="mt-5 rounded-[16px] border border-slate-200 bg-slate-50/70 p-4">
      <div class="flex items-center justify-between gap-3">
        <div>
          <p class="text-xs tracking-wide text-blue-700">雷池接入</p>
          <h4 class="mt-1 text-base font-semibold text-stone-900">
            OpenAPI 基础配置
          </h4>
        </div>
        <label
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-sm text-stone-700"
        >
          <input
            v-model="safeLineVerifyTls"
            type="checkbox"
            class="accent-blue-600"
          />
          <span>校验证书</span>
        </label>
      </div>

      <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <label class="space-y-1 md:col-span-2">
          <span class="text-xs text-slate-500">雷池地址</span>
          <input
            v-model="safeLineBaseUrl"
            type="text"
            placeholder="https://127.0.0.1:9443"
            class="w-full rounded-[14px] border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
          />
        </label>
        <label class="space-y-1 md:col-span-2">
          <span class="text-xs text-slate-500">API Token</span>
          <input
            v-model="safeLineApiToken"
            type="password"
            placeholder="API-TOKEN"
            class="w-full rounded-[14px] border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
          />
        </label>
        <label class="space-y-1 md:col-span-2">
          <span class="text-xs text-slate-500">雷池账号</span>
          <input
            v-model="safeLineUsername"
            type="text"
            placeholder="用户名"
            class="w-full rounded-[14px] border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
          />
        </label>
        <label class="space-y-1 md:col-span-2">
          <span class="text-xs text-slate-500">雷池密码</span>
          <input
            v-model="safeLinePassword"
            type="password"
            placeholder="密码"
            class="w-full rounded-[14px] border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-blue-500"
          />
        </label>
      </div>

      <div class="mt-4 flex flex-wrap items-center gap-2.5">
        <label
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-sm text-stone-700"
        >
          <input
            v-model="safeLineAutoSyncEvents"
            type="checkbox"
            class="accent-blue-600"
          />
          <span>同步事件</span>
        </label>
        <label
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-sm text-stone-700"
        >
          <input
            v-model="safeLineAutoSyncPush"
            type="checkbox"
            class="accent-blue-600"
          />
          <span>推送封禁</span>
        </label>
        <label
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-sm text-stone-700"
        >
          <input
            v-model="safeLineAutoSyncPull"
            type="checkbox"
            class="accent-blue-600"
          />
          <span>回流封禁</span>
        </label>
        <label
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-sm text-stone-700"
        >
          <span>自动</span>
          <input
            v-model.number="safeLineAutoSyncInterval"
            type="number"
            min="15"
            max="86400"
            step="15"
            class="w-20 appearance-none border-0 bg-transparent p-0 text-center text-sm text-stone-900 outline-none"
          />
          <span>秒同步</span>
        </label>
        <button
          :disabled="testing || loading"
          class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-white px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('test')"
        >
          <PlugZap :size="12" />
          {{ testing ? '测试中...' : '测试雷池连接' }}
        </button>
        <button
          :disabled="loadingSites || loading"
          class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-white px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('loadSites')"
        >
          <ServerCog :size="12" />
          {{ loadingSites ? '读取中...' : '读取站点列表' }}
        </button>
        <button
          :disabled="savingMappings || sites.length === 0"
          class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-white px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('saveMappings')"
        >
          <Save :size="12" />
          {{ savingMappings ? '保存中...' : '保存站点映射' }}
        </button>
      </div>

      <div
        v-if="testResult"
        class="mt-4 rounded-lg border border-slate-200 bg-white p-4"
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
            class="rounded-[16px] border border-slate-200 bg-slate-50 px-3.5 py-3"
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
            class="rounded-[16px] border border-slate-200 bg-slate-50 px-3.5 py-3"
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
    </div>

  </div>
</template>
