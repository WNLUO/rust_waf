<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { RefreshCw, Save } from 'lucide-vue-next'
import { fetchGlobalSettings, updateGlobalSettings } from '@/shared/api/settings'
import type { GlobalSettingsPayload } from '@/shared/types'
import { useFlashMessages } from '@/shared/composables/useNotifications'

function createDefaultSettings(): GlobalSettingsPayload {
  return {
    enable_http1_0: true,
    http2_enabled: true,
    http3_enabled: false,
    source_ip_strategy: 'connection',
    custom_source_ip_header: '',
    custom_source_ip_header_auth_enabled: false,
    custom_source_ip_header_auth_header: '',
    custom_source_ip_header_auth_secret: '',
    trusted_proxy_cidrs: [],
    http_to_https_redirect: true,
    enable_hsts: true,
    rewrite_host_enabled: true,
    rewrite_host_value: '$http_host',
    add_x_forwarded_headers: true,
    rewrite_x_forwarded_for: true,
    support_gzip: true,
    support_brotli: true,
    support_sse: true,
    enable_ntlm: true,
    fallback_self_signed_certificate: true,
    ssl_protocols: ['TLSv1.2', 'TLSv1.3'],
    ssl_ciphers: '',
    header_operations: [],
    ai_audit: {
      enabled: false,
      provider: 'local_rules',
      model: '',
      base_url: '',
      api_key: '',
      timeout_ms: 15000,
      fallback_to_rules: true,
    },
  }
}

const loading = ref(true)
const saving = ref(false)
const error = ref('')
const successMessage = ref('')
const settings = reactive<GlobalSettingsPayload>(createDefaultSettings())

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: '全局设置',
  successTitle: '全局设置',
  errorDuration: 5600,
  successDuration: 3200,
})

function assignSettings(payload: GlobalSettingsPayload) {
  Object.assign(settings, payload)
}

async function loadSettings() {
  loading.value = true
  error.value = ''
  try {
    assignSettings(await fetchGlobalSettings())
  } catch (err) {
    error.value = err instanceof Error ? err.message : '加载全局设置失败'
  } finally {
    loading.value = false
  }
}

function toggleSslProtocol(protocol: string, enabled: boolean) {
  const next = new Set(settings.ssl_protocols)
  if (enabled) {
    next.add(protocol)
  } else {
    next.delete(protocol)
  }
  settings.ssl_protocols = [...next]
}

async function saveSettings() {
  saving.value = true
  error.value = ''
  successMessage.value = ''
  try {
    const response = await updateGlobalSettings(settings)
    successMessage.value = response.message
    assignSettings(await fetchGlobalSettings())
  } catch (err) {
    error.value = err instanceof Error ? err.message : '保存全局设置失败'
  } finally {
    saving.value = false
  }
}

onMounted(loadSettings)
</script>

<template>
  <section
    class="space-y-3 rounded-2xl border border-white/80 bg-[linear-gradient(180deg,rgba(255,255,255,0.96),rgba(248,250,252,0.92))] p-4 shadow-[0_18px_48px_rgba(90,60,30,0.07)]"
  >
    <div
      class="flex flex-col gap-3 md:flex-row md:items-end md:justify-between"
    >
      <div>
        <p class="text-[10px] font-medium tracking-[0.24em] text-blue-700">
          GLOBAL
        </p>
        <h3 class="mt-0.5 text-lg font-semibold text-stone-900">
          协议、转发与边界行为
        </h3>
        <p class="mt-0.5 text-xs leading-5 text-slate-500">
          用更紧凑的方式组织源 IP 与 SSL 配置，减少视觉噪音。
        </p>
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <button
          :disabled="loading"
          class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
          @click="loadSettings"
        >
          <RefreshCw :size="12" :class="{ 'animate-spin': loading }" />
          刷新
        </button>
        <button
          :disabled="saving || loading"
          class="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white shadow-sm transition hover:bg-blue-600/90 disabled:opacity-60"
          @click="saveSettings"
        >
          <Save :size="12" />
          {{ saving ? '保存中...' : '保存全局设置' }}
        </button>
      </div>
    </div>

    <div
      v-if="loading"
      class="rounded-xl border border-slate-200 bg-white px-4 py-6 text-sm text-slate-500 shadow-sm"
    >
      正在加载全局设置...
    </div>

    <template v-else>
      <div class="grid gap-3 xl:grid-cols-[minmax(0,1.18fr)_minmax(0,0.92fr)]">
        <section class="rounded-xl border border-slate-200 bg-white p-3">
          <div>
            <p class="text-sm font-semibold text-stone-900">真实来源 IP 获取</p>
            <p class="mt-0.5 text-xs leading-4 text-slate-500">
              Header 模式下会直接以你配置的自定义 Header 识别用户真实 IP；你也可以额外开启认证 Header 校验，避免被伪造。
            </p>
          </div>

          <div class="mt-3 grid gap-3 lg:grid-cols-[15rem_minmax(0,1fr)]">
            <label class="space-y-1">
              <span class="text-xs font-medium text-slate-500">获取方式</span>
              <select
                v-model="settings.source_ip_strategy"
                class="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm outline-none transition focus:border-blue-500 focus:bg-white"
              >
                <option value="connection">从网络连接中获取</option>
                <option value="x_forwarded_for_first">
                  取 X-Forwarded-For 中上一一级代理的地址
                </option>
                <option value="x_forwarded_for_last">
                  取 X-Forwarded-For 中上一级代理的地址
                </option>
                <option value="x_forwarded_for_last_but_one">
                  取 X-Forwarded-For 中上上一级代理的地址
                </option>
                <option value="x_forwarded_for_last_but_two">
                  取 X-Forwarded-For 中上上上一级代理的地址
                </option>
                <option value="header">从真实来源 IP Header 中获取</option>
                <option value="proxy_protocol">从 PROXY Protocol 中获取</option>
              </select>
            </label>

            <div class="grid gap-3 md:grid-cols-2">
              <label class="space-y-1">
                <span class="text-xs font-medium text-slate-500">真实来源 IP Header</span>
                <input
                  v-model="settings.custom_source_ip_header"
                  class="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm outline-none transition focus:border-blue-500 focus:bg-white"
                  type="text"
                  placeholder="例如 x-cdn-real-ip"
                />
              </label>
              <label
                class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-700"
              >
                <input
                  v-model="settings.custom_source_ip_header_auth_enabled"
                  type="checkbox"
                  class="h-4 w-4 accent-blue-600"
                />
                开启 Header 认证校验
              </label>
            </div>

            <div
              v-if="settings.source_ip_strategy === 'header'"
              class="mt-3 grid gap-3 md:grid-cols-2"
            >
              <label class="space-y-1">
                <span class="text-xs font-medium text-slate-500">认证 Header 名称</span>
                <input
                  v-model="settings.custom_source_ip_header_auth_header"
                  class="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm outline-none transition focus:border-blue-500 focus:bg-white"
                  type="text"
                  placeholder="例如 x-cdn-auth"
                  :disabled="!settings.custom_source_ip_header_auth_enabled"
                />
              </label>
              <label class="space-y-1">
                <span class="text-xs font-medium text-slate-500">认证 Secret</span>
                <input
                  v-model="settings.custom_source_ip_header_auth_secret"
                  class="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm outline-none transition focus:border-blue-500 focus:bg-white"
                  type="password"
                  placeholder="开启认证后必填"
                  :disabled="!settings.custom_source_ip_header_auth_enabled"
                />
              </label>
            </div>
            <div
              v-if="settings.source_ip_strategy === 'header'"
              class="mt-3 rounded-xl border border-cyan-200 bg-cyan-50 px-3 py-2 text-xs leading-5 text-cyan-800"
            >
              关闭认证时，只要请求携带你配置的真实 IP Header，就会按 CDN 转发流量处理。
            </div>
          </div>
        </section>

        <div>
          <section class="rounded-xl border border-slate-200 bg-white p-3">
            <p class="text-sm font-semibold text-stone-900">SSL 合规配置</p>
            <div class="mt-3 flex flex-wrap gap-2">
              <label
                v-for="protocol in ['TLSv1.2', 'TLSv1.3']"
                :key="protocol"
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-xs"
              >
                <input
                  :checked="settings.ssl_protocols.includes(protocol)"
                  type="checkbox"
                  class="h-3.5 w-3.5 accent-blue-600"
                  @change="
                    toggleSslProtocol(
                      protocol,
                      ($event.target as HTMLInputElement).checked,
                    )
                  "
                />
                {{ protocol }}
              </label>
            </div>
            <label class="mt-3 block space-y-1">
              <span class="text-xs font-medium text-slate-500">SSL 加密套件</span>
              <input
                v-model="settings.ssl_ciphers"
                class="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm outline-none transition focus:border-blue-500 focus:bg-white"
                type="text"
                placeholder="留空则沿用默认"
              />
            </label>
          </section>

          <section class="mt-3 rounded-xl border border-slate-200 bg-white p-3">
            <p class="text-sm font-semibold text-stone-900">AI 审计 Provider</p>
            <p class="mt-0.5 text-xs leading-4 text-slate-500">
              这里配置审计报告的默认 provider。当前仍以内置 `local_rules` 为兜底，外部模型只做占位接入准备。
            </p>
            <div class="mt-3 grid gap-3 md:grid-cols-2">
              <label
                class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm"
              >
                <input
                  v-model="settings.ai_audit.enabled"
                  type="checkbox"
                  class="h-4 w-4 accent-blue-600"
                />
                启用 AI 审计 provider
              </label>
              <label class="space-y-1">
                <span class="text-xs font-medium text-slate-500">默认 provider</span>
                <select
                  v-model="settings.ai_audit.provider"
                  class="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm outline-none transition focus:border-blue-500 focus:bg-white"
                >
                  <option value="local_rules">local_rules</option>
                  <option value="stub_model">stub_model</option>
                  <option value="openai_compatible">openai_compatible</option>
                  <option value="xiaomi_mimo">xiaomi_mimo</option>
                </select>
              </label>
              <label class="space-y-1">
                <span class="text-xs font-medium text-slate-500">模型名称</span>
                <input
                  v-model="settings.ai_audit.model"
                  class="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm outline-none transition focus:border-blue-500 focus:bg-white"
                  type="text"
                  placeholder="例如 gpt-5.4-mini"
                />
              </label>
              <label class="space-y-1">
                <span class="text-xs font-medium text-slate-500">Base URL</span>
                <input
                  v-model="settings.ai_audit.base_url"
                  class="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm outline-none transition focus:border-blue-500 focus:bg-white"
                  type="text"
                  placeholder="例如 https://api.example.com/v1"
                />
              </label>
              <label class="space-y-1">
                <span class="text-xs font-medium text-slate-500">API Key</span>
                <input
                  v-model="settings.ai_audit.api_key"
                  class="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm outline-none transition focus:border-blue-500 focus:bg-white"
                  type="password"
                  placeholder="留空则只保留本地报告链路"
                />
              </label>
              <label class="space-y-1">
                <span class="text-xs font-medium text-slate-500">超时预算（毫秒）</span>
                <input
                  v-model.number="settings.ai_audit.timeout_ms"
                  class="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm outline-none transition focus:border-blue-500 focus:bg-white"
                  type="number"
                  min="1000"
                  step="500"
                />
              </label>
            </div>
            <label
              class="mt-3 flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm"
            >
              <input
                v-model="settings.ai_audit.fallback_to_rules"
                type="checkbox"
                class="h-4 w-4 accent-blue-600"
              />
              provider 失败时自动回退到 local_rules
            </label>
          </section>
        </div>
      </div>
    </template>
  </section>
</template>
