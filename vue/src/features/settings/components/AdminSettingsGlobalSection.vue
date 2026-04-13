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
    trusted_proxy_cidrs: [],
    http_to_https_redirect: true,
    enable_hsts: true,
    rewrite_host_enabled: true,
    rewrite_host_value: '',
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
  }
}

const loading = ref(true)
const saving = ref(false)
const error = ref('')
const successMessage = ref('')
const trustedProxyCidrsText = ref('')
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
  trustedProxyCidrsText.value = payload.trusted_proxy_cidrs.join('\n')
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
    const payload: GlobalSettingsPayload = {
      ...settings,
      trusted_proxy_cidrs: trustedProxyCidrsText.value
        .split('\n')
        .map((item) => item.trim())
        .filter(Boolean),
    }
    const response = await updateGlobalSettings(payload)
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
  <section class="space-y-4 rounded-xl border border-white/80 bg-white/78 p-4 shadow-[0_18px_48px_rgba(90,60,30,0.08)]">
    <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
      <div>
        <p class="text-sm tracking-wider text-blue-700">全局设置</p>
        <h3 class="mt-2 text-2xl font-semibold text-stone-900">协议、转发与边界行为</h3>
      </div>
      <div class="flex items-center gap-2">
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
      <section class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <p class="text-sm font-semibold text-stone-900">源 IP 获取方式</p>
        <div class="mt-4 grid gap-4 md:grid-cols-[16rem_minmax(0,1fr)]">
          <label class="space-y-1.5">
            <span class="text-xs text-slate-500">获取来源</span>
            <select
              v-model="settings.source_ip_strategy"
              class="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500"
            >
              <option value="connection">从网络连接中获取</option>
              <option value="x_forwarded_for_first">取 X-Forwarded-For 中上一一级代理的地址</option>
              <option value="x_forwarded_for_last">取 X-Forwarded-For 中上一级代理的地址</option>
              <option value="x_forwarded_for_last_but_one">取 X-Forwarded-For 中上上一级代理的地址</option>
              <option value="x_forwarded_for_last_but_two">取 X-Forwarded-For 中上上上一级代理的地址</option>
              <option value="header">从 HTTP Header 中获取</option>
              <option value="proxy_protocol">从 PROXY Protocol 中获取</option>
            </select>
          </label>

          <div class="grid gap-4 md:grid-cols-2">
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">自定义 Header</span>
              <input
                v-model="settings.custom_source_ip_header"
                class="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                type="text"
                placeholder="例如 x-real-ip"
              />
            </label>
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">可信代理 CIDR</span>
              <textarea
                v-model="trustedProxyCidrsText"
                class="min-h-[6.5rem] w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                placeholder="每行一个，如 10.0.0.0/8"
              />
            </label>
          </div>
        </div>
      </section>

      <section class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <p class="text-sm font-semibold text-stone-900">协议兼容</p>
        <p class="mt-1 text-xs leading-5 text-slate-500">
          HTTP/3 依赖 QUIC、TLS 1.3 与可用证书配置；端口自动跟随全局 HTTPS 入口。
        </p>
        <div class="mt-4 grid gap-3 md:grid-cols-3">
          <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
            <input v-model="settings.enable_http1_0" type="checkbox" class="h-4 w-4 accent-blue-600" />
            启用 HTTP/1.0
          </label>
          <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
            <input v-model="settings.http2_enabled" type="checkbox" class="h-4 w-4 accent-blue-600" />
            启用 HTTP/2
          </label>
          <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
            <input v-model="settings.http3_enabled" type="checkbox" class="h-4 w-4 accent-blue-600" />
            启用 HTTP/3
          </label>
        </div>
      </section>

      <section class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
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
              @change="toggleSslProtocol(protocol, ($event.target as HTMLInputElement).checked)"
            />
            {{ protocol }}
          </label>
        </div>
        <label class="mt-4 block space-y-1.5">
          <span class="text-xs text-slate-500">SSL Ciphers</span>
          <input
            v-model="settings.ssl_ciphers"
            class="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500"
            type="text"
            placeholder="留空则沿用默认"
          />
        </label>
      </section>

    </template>
  </section>
</template>
