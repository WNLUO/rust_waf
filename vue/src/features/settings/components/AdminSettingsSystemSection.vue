<script setup lang="ts">
import { computed } from 'vue'
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

function truncateCertificateName(name: string, maxLength = 18) {
  if (name.length <= maxLength) return name
  return `${name.slice(0, maxLength)}...`
}
</script>

<template>
  <div class="space-y-4">
      <section class="rounded-2xl border border-slate-200/90 bg-white/90 p-4">
        <div>
          <p class="text-sm font-semibold text-stone-900">核心参数</p>
        </div>

        <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
          <label class="flex items-center gap-2.5 px-1 py-1.5">
            <span class="shrink-0 text-xs font-medium text-slate-500"
              >统一 HTTP 入口端口</span
            >
            <input
              v-model="globalHttpPort"
              type="text"
              inputmode="numeric"
              placeholder="例如 8080"
              class="w-full max-w-[5.5rem] rounded-xl border border-slate-200 bg-white px-3 py-2 text-center text-sm outline-none transition focus:border-blue-500"
            />
          </label>
          <label class="flex items-center gap-2.5 px-1 py-1.5">
            <span class="shrink-0 text-xs font-medium text-slate-500"
              >统一 HTTPS 入口端口</span
            >
            <input
              v-model="globalHttpsPort"
              type="text"
              inputmode="numeric"
              placeholder="例如 660，可留空关闭 HTTPS 入口"
              class="w-full max-w-[5.5rem] rounded-xl border border-slate-200 bg-white px-3 py-2 text-center text-sm outline-none transition focus:border-blue-500"
            />
          </label>
          <label class="flex items-center gap-2.5 px-1 py-1.5">
            <span class="shrink-0 text-xs font-medium text-slate-500"
              >控制面 API 地址</span
            >
            <input
              v-model="apiEndpoint"
              type="text"
              class="w-full max-w-[9rem] rounded-xl border border-slate-200 bg-white px-3 py-2 text-center text-sm outline-none transition focus:border-blue-500"
            />
          </label>
          <label class="flex items-center gap-2.5 px-1 py-1.5">
            <span class="shrink-0 text-xs font-medium text-slate-500"
              >默认证书</span
            >
            <select
              v-model="defaultCertificateId"
              :disabled="savingDefaultCertificate"
              class="w-full max-w-[11rem] rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-left outline-none transition focus:border-blue-500"
              @change="emit('defaultCertificateChange', $event)"
            >
              <option :value="null">未设置</option>
              <option
                v-for="certificate in localCertificates"
                :key="certificate.id"
                :value="certificate.id"
              >
                {{ truncateCertificateName(certificate.name) }}
              </option>
            </select>
          </label>
        </div>

        <div class="mt-4 border-t border-slate-100 pt-3">
          <div class="mb-3 flex flex-col gap-2 xl:flex-row xl:items-center xl:justify-between">
            <p class="text-sm font-semibold text-stone-900">雷池接入参数</p>
            <div class="flex flex-wrap items-center gap-4">
              <label class="inline-flex items-center gap-2 text-xs text-stone-700">
                <input
                  v-model="safeLineVerifyTls"
                  type="checkbox"
                  class="peer sr-only"
                />
                <span
                  class="relative h-5 w-9 rounded-full bg-slate-300 transition peer-checked:bg-blue-600 after:absolute after:left-0.5 after:top-0.5 after:h-4 after:w-4 after:rounded-full after:bg-white after:transition peer-checked:after:translate-x-4"
                ></span>
                <span>校验证书</span>
              </label>
              <div class="h-3 w-px bg-slate-200"></div>
              <label class="inline-flex items-center gap-2 text-xs text-stone-700">
                <input
                  v-model="safeLineAutoSyncEvents"
                  type="checkbox"
                  class="peer sr-only"
                />
                <span
                  class="relative h-5 w-9 rounded-full bg-slate-300 transition peer-checked:bg-blue-600 after:absolute after:left-0.5 after:top-0.5 after:h-4 after:w-4 after:rounded-full after:bg-white after:transition peer-checked:after:translate-x-4"
                ></span>
                <span>同步事件</span>
              </label>
              <label class="inline-flex items-center gap-2 text-xs text-stone-700">
                <input
                  v-model="safeLineAutoSyncPush"
                  type="checkbox"
                  class="peer sr-only"
                />
                <span
                  class="relative h-5 w-9 rounded-full bg-slate-300 transition peer-checked:bg-blue-600 after:absolute after:left-0.5 after:top-0.5 after:h-4 after:w-4 after:rounded-full after:bg-white after:transition peer-checked:after:translate-x-4"
                ></span>
                <span>推送封禁</span>
              </label>
              <label class="inline-flex items-center gap-2 text-xs text-stone-700">
                <input
                  v-model="safeLineAutoSyncPull"
                  type="checkbox"
                  class="peer sr-only"
                />
                <span
                  class="relative h-5 w-9 rounded-full bg-slate-300 transition peer-checked:bg-blue-600 after:absolute after:left-0.5 after:top-0.5 after:h-4 after:w-4 after:rounded-full after:bg-white after:transition peer-checked:after:translate-x-4"
                ></span>
                <span>回流封禁</span>
              </label>
              <label class="inline-flex items-center gap-1.5 text-xs text-stone-700">
                <span>自动</span>
                <input
                  v-model.number="safeLineAutoSyncInterval"
                  type="number"
                  min="15"
                  max="86400"
                  step="15"
                  class="no-spinner w-12 rounded border border-slate-200 bg-slate-50 px-1 py-0.5 text-center text-xs font-bold text-stone-900 outline-none focus:border-blue-500 focus:bg-white"
                />
                <span>s 同步</span>
              </label>
            </div>
          </div>

          <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <label class="flex items-center justify-start gap-2 text-sm text-stone-700">
              <span class="font-medium whitespace-nowrap">雷池地址</span>
              <input
                v-model="safeLineBaseUrl"
                type="text"
                placeholder="https://127.0.0.1:9443"
                class="w-full rounded border border-slate-200 bg-transparent px-2 py-1 text-sm outline-none transition focus:border-blue-500 text-left"
              />
            </label>
            <label class="flex items-center justify-start gap-2 text-sm text-stone-700">
              <span class="font-medium whitespace-nowrap">API Token</span>
              <input
                v-model="safeLineApiToken"
                type="password"
                placeholder="API-TOKEN"
                class="w-full rounded border border-slate-200 bg-transparent px-2 py-1 text-sm outline-none transition focus:border-blue-500 text-left"
              />
            </label>
            <label class="flex items-center justify-start gap-2 text-sm text-stone-700">
              <span class="font-medium whitespace-nowrap">雷池账号</span>
              <input
                v-model="safeLineUsername"
                type="text"
                placeholder="用户名"
                class="w-full rounded border border-slate-200 bg-transparent px-2 py-1 text-sm outline-none transition focus:border-blue-500 text-left"
              />
            </label>
            <label class="flex items-center justify-start gap-2 text-sm text-stone-700">
              <span class="font-medium whitespace-nowrap">雷池密码</span>
              <input
                v-model="safeLinePassword"
                type="password"
                placeholder="密码"
                class="w-full rounded border border-slate-200 bg-transparent px-2 py-1 text-sm outline-none transition focus:border-blue-500 text-left"
              />
            </label>

          </div>

          <!-- 测试结果横向扁平化 -->
          <div
            v-if="testResult"
            class="mt-4 flex flex-col gap-3 rounded-lg border border-slate-200 bg-slate-50/70 p-2.5 md:flex-row md:items-center"
          >
            <div class="flex items-center gap-2">
              <span
                class="inline-flex shrink-0 rounded-full px-2 py-0.5 text-[10px] font-bold"
                :class="
                  testResult.status === 'ok'
                    ? 'bg-emerald-100 text-emerald-700'
                    : testResult.status === 'warning'
                      ? 'bg-amber-100 text-amber-700'
                      : 'bg-rose-100 text-rose-700'
                "
              >
                {{ testResult.status === 'ok' ? '连通正常' : testResult.status === 'warning' ? '需确认' : '连通失败' }}
              </span>
            </div>
            <div class="hidden h-4 w-px bg-slate-200 md:block"></div>
            <p class="min-w-0 flex-1 truncate text-[11px] leading-4 text-slate-500" :title="testResult.message">
              {{ testResult.message }}
            </p>
            <div class="hidden h-4 w-px bg-slate-200 md:block"></div>
            <div class="flex shrink-0 flex-wrap items-center gap-3 whitespace-nowrap text-[11px] text-slate-500">
              <p>
                OpenAPI:
                <span class="font-medium text-stone-900">{{ testResult.openapi_doc_reachable ? '可访问' : '不可访问' }}</span>
                <span v-if="testResult.openapi_doc_status !== null" class="ml-0.5 text-slate-400">({{ testResult.openapi_doc_status }})</span>
              </p>
              <p>
                鉴权:
                <span class="font-medium text-stone-900">{{ testResult.authenticated ? '通过' : '未通过' }}</span>
                <span v-if="testResult.auth_probe_status !== null" class="ml-0.5 text-slate-400">({{ testResult.auth_probe_status }})</span>
              </p>
            </div>
          </div>
        </div>
      </section>
  </div>
</template>

<style scoped>
.no-spinner::-webkit-outer-spin-button,
.no-spinner::-webkit-inner-spin-button {
  -webkit-appearance: none;
  margin: 0;
}

.no-spinner {
  -moz-appearance: textfield;
}
</style>
