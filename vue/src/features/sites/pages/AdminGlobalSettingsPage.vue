<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { RefreshCw, Save } from 'lucide-vue-next'
import AppLayout from '@/app/layout/AppLayout.vue'
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
      event_sample_limit: 120,
      recent_event_limit: 12,
      include_raw_event_samples: false,
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

async function loadPage() {
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

onMounted(loadPage)
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <div class="flex items-center gap-2">
        <button
          :disabled="loading"
          class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
          @click="loadPage"
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
          {{ saving ? '保存中...' : '保存设置' }}
        </button>
      </div>
    </template>

    <div class="space-y-4">
      <div
        v-if="loading"
        class="rounded-xl border border-slate-200 bg-white px-4 py-6 text-sm text-slate-500 shadow-sm"
      >
        正在加载全局设置...
      </div>

      <template v-else>
        <section
          class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"
        >
          <p class="text-sm font-semibold text-stone-900">真实来源 IP 获取</p>
          <p class="mt-1 text-xs leading-5 text-slate-500">
            Header 模式下会直接以你配置的自定义 Header 识别用户真实 IP；如果开启认证，则还会额外校验认证 Header 与 Secret。
          </p>
          <div class="mt-4 grid gap-4 md:grid-cols-[16rem_minmax(0,1fr)]">
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">获取方式</span>
              <select
                v-model="settings.source_ip_strategy"
                class="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500"
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

            <div class="grid gap-4 md:grid-cols-2">
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">真实来源 IP Header</span>
                <input
                  v-model="settings.custom_source_ip_header"
                  class="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                  type="text"
                  placeholder="例如 x-cdn-real-ip"
                />
              </label>
              <label
                class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm"
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
              class="mt-4 grid gap-4 md:grid-cols-2"
            >
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">认证 Header 名称</span>
                <input
                  v-model="settings.custom_source_ip_header_auth_header"
                  class="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                  type="text"
                  placeholder="例如 x-cdn-auth"
                  :disabled="!settings.custom_source_ip_header_auth_enabled"
                />
              </label>
              <label class="space-y-1.5">
                <span class="text-xs text-slate-500">认证 Secret</span>
                <input
                  v-model="settings.custom_source_ip_header_auth_secret"
                  class="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                  type="password"
                  placeholder="开启认证后必填"
                  :disabled="!settings.custom_source_ip_header_auth_enabled"
                />
              </label>
            </div>
            <div
              v-if="settings.source_ip_strategy === 'header'"
              class="mt-4 rounded-lg border border-cyan-200 bg-cyan-50 px-3 py-2 text-xs leading-5 text-cyan-800"
            >
              关闭认证时，只要请求携带你配置的真实来源 IP Header，就会被按 CDN 转发流量处理。
            </div>
          </div>
        </section>

        <section
          class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"
        >
          <p class="text-sm font-semibold text-stone-900">协议兼容</p>
          <p class="mt-1 text-xs leading-5 text-slate-500">
            HTTP/3 依赖 QUIC、TLS 1.3 与可用证书配置；仅打开开关还需要服务端监听和证书链完整才能对外生效。
          </p>
          <div class="mt-4 grid gap-3 md:grid-cols-3">
            <label
              class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm"
            >
              <input
                v-model="settings.enable_http1_0"
                type="checkbox"
                class="h-4 w-4 accent-blue-600"
              />
              启用 HTTP/1.0
            </label>
            <label
              class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm"
            >
              <input
                v-model="settings.http2_enabled"
                type="checkbox"
                class="h-4 w-4 accent-blue-600"
              />
              启用 HTTP/2
            </label>
            <label
              class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm"
            >
              <input
                v-model="settings.http3_enabled"
                type="checkbox"
                class="h-4 w-4 accent-blue-600"
              />
              启用 HTTP/3
            </label>
          </div>
        </section>

        <section
          class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"
        >
          <p class="text-sm font-semibold text-stone-900">SSL 合规配置</p>
          <div class="mt-4 flex flex-wrap gap-3">
            <label
              v-for="protocol in ['TLSv1.2', 'TLSv1.3']"
              :key="protocol"
              class="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm"
            >
              <input
                :checked="settings.ssl_protocols.includes(protocol)"
                type="checkbox"
                class="h-4 w-4 accent-blue-600"
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
          <label class="mt-4 block space-y-1.5">
            <span class="text-xs text-slate-500">SSL 加密套件</span>
            <input
              v-model="settings.ssl_ciphers"
              class="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500"
              type="text"
              placeholder="留空则沿用默认"
            />
          </label>
        </section>

      </template>
    </div>
  </AppLayout>
</template>
