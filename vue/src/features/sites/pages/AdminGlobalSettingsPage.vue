<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { Plus, RefreshCw, Save, Trash2 } from 'lucide-vue-next'
import AppLayout from '@/app/layout/AppLayout.vue'
import { fetchGlobalSettings, updateGlobalSettings } from '@/shared/api/settings'
import type { GlobalSettingsPayload, HeaderOperationItem } from '@/shared/types'
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

function addHeaderOperation() {
  settings.header_operations.push({
    scope: 'request',
    action: 'set',
    header: '',
    value: '',
  })
}

function removeHeaderOperation(index: number) {
  settings.header_operations.splice(index, 1)
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
      header_operations: settings.header_operations.map(
        (item): HeaderOperationItem => ({
          scope: item.scope,
          action: item.action,
          header: item.header.trim(),
          value: item.value.trim(),
        }),
      ),
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
          <p class="text-sm font-semibold text-stone-900">源 IP 获取方式</p>
          <div class="mt-4 grid gap-4 md:grid-cols-[16rem_minmax(0,1fr)]">
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">获取来源</span>
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
          <p class="text-sm font-semibold text-stone-900">其他高级配置</p>
          <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            <label
              class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm"
            >
              <input
                v-model="settings.http_to_https_redirect"
                type="checkbox"
                class="h-4 w-4 accent-blue-600"
              />
              HTTP 自动跳转到 HTTPS
            </label>
            <label
              class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm"
            >
              <input
                v-model="settings.enable_hsts"
                type="checkbox"
                class="h-4 w-4 accent-blue-600"
              />
              启用 HSTS
            </label>
            <label
              class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm"
            >
              <input
                v-model="settings.add_x_forwarded_headers"
                type="checkbox"
                class="h-4 w-4 accent-blue-600"
              />
              为上游服务器传递 X-Forwarded-Host / Proto
            </label>
            <label
              class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm"
            >
              <input
                v-model="settings.rewrite_x_forwarded_for"
                type="checkbox"
                class="h-4 w-4 accent-blue-600"
              />
              清空并重写 X-Forwarded-For
            </label>
            <label
              class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm"
            >
              <input
                v-model="settings.support_gzip"
                type="checkbox"
                class="h-4 w-4 accent-blue-600"
              />
              支持 Gzip 压缩
            </label>
            <label
              class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm"
            >
              <input
                v-model="settings.support_brotli"
                type="checkbox"
                class="h-4 w-4 accent-blue-600"
              />
              支持 Brotli 压缩
            </label>
            <label
              class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm"
            >
              <input
                v-model="settings.support_sse"
                type="checkbox"
                class="h-4 w-4 accent-blue-600"
              />
              支持 SSE 流式响应
            </label>
            <label
              class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm"
            >
              <input
                v-model="settings.enable_ntlm"
                type="checkbox"
                class="h-4 w-4 accent-blue-600"
              />
              启用 NTLM 认证
            </label>
            <label
              class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm"
            >
              <input
                v-model="settings.fallback_self_signed_certificate"
                type="checkbox"
                class="h-4 w-4 accent-blue-600"
              />
              应用不存在时返回自置证书
            </label>
          </div>

          <div class="mt-4 grid gap-4 md:grid-cols-[16rem_minmax(0,1fr)]">
            <label
              class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm"
            >
              <input
                v-model="settings.rewrite_host_enabled"
                type="checkbox"
                class="h-4 w-4 accent-blue-600"
              />
              代理时修改请求中的 Host 头
            </label>
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">Host 头</span>
              <input
                v-model="settings.rewrite_host_value"
                :disabled="!settings.rewrite_host_enabled"
                class="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500 disabled:bg-slate-50"
                type="text"
                placeholder="$http_host"
              />
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
            <span class="text-xs text-slate-500">SSL Ciphers</span>
            <input
              v-model="settings.ssl_ciphers"
              class="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500"
              type="text"
              placeholder="留空则沿用默认"
            />
          </label>
        </section>

        <section
          class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"
        >
          <div class="flex items-center justify-between gap-3">
            <p class="text-sm font-semibold text-stone-900">HTTP Header 操作</p>
            <button
              class="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
              @click="addHeaderOperation"
            >
              <Plus :size="12" />
              添加一项 Header 操作
            </button>
          </div>

          <div v-if="settings.header_operations.length" class="mt-4 space-y-3">
            <div
              v-for="(item, index) in settings.header_operations"
              :key="index"
              class="grid gap-3 rounded-xl border border-slate-200 bg-slate-50 p-3 md:grid-cols-[8rem_8rem_minmax(0,1fr)_minmax(0,1fr)_3rem]"
            >
              <select
                v-model="item.scope"
                class="rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500"
              >
                <option value="request">请求头</option>
                <option value="response">响应头</option>
              </select>
              <select
                v-model="item.action"
                class="rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500"
              >
                <option value="set">设置</option>
                <option value="add">新增</option>
                <option value="remove">移除</option>
              </select>
              <input
                v-model="item.header"
                class="rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                type="text"
                placeholder="Header 名称"
              />
              <input
                v-model="item.value"
                :disabled="item.action === 'remove'"
                class="rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500 disabled:bg-slate-100"
                type="text"
                placeholder="Header 值"
              />
              <button
                class="inline-flex items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-500 transition hover:text-rose-600"
                @click="removeHeaderOperation(index)"
              >
                <Trash2 :size="14" />
              </button>
            </div>
          </div>
          <p v-else class="mt-4 text-sm text-slate-500">
            还没有添加 Header 操作。
          </p>
        </section>
      </template>
    </div>
  </AppLayout>
</template>
