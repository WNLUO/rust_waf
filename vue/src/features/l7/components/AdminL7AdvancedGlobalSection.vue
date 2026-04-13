<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { Plus, RefreshCw, Save, Trash2 } from 'lucide-vue-next'
import { fetchGlobalSettings, updateGlobalSettings } from '@/shared/api/settings'
import type { GlobalSettingsPayload, HeaderOperationItem } from '@/shared/types'
import { useFlashMessages } from '@/shared/composables/useNotifications'

type AdvancedGlobalSettingsForm = Pick<
  GlobalSettingsPayload,
  | 'enable_http1_0'
  | 'source_ip_strategy'
  | 'custom_source_ip_header'
  | 'trusted_proxy_cidrs'
  | 'http_to_https_redirect'
  | 'enable_hsts'
  | 'add_x_forwarded_headers'
  | 'rewrite_x_forwarded_for'
  | 'support_gzip'
  | 'support_brotli'
  | 'support_sse'
  | 'enable_ntlm'
  | 'fallback_self_signed_certificate'
  | 'ssl_protocols'
  | 'ssl_ciphers'
  | 'rewrite_host_enabled'
  | 'rewrite_host_value'
  | 'header_operations'
>

function createDefaultAdvancedSettings(): AdvancedGlobalSettingsForm {
  return {
    enable_http1_0: true,
    source_ip_strategy: 'connection',
    custom_source_ip_header: '',
    trusted_proxy_cidrs: [],
    http_to_https_redirect: true,
    enable_hsts: true,
    add_x_forwarded_headers: true,
    rewrite_x_forwarded_for: true,
    support_gzip: true,
    support_brotli: true,
    support_sse: true,
    enable_ntlm: true,
    fallback_self_signed_certificate: true,
    ssl_protocols: ['TLSv1.2', 'TLSv1.3'],
    ssl_ciphers: '',
    rewrite_host_enabled: true,
    rewrite_host_value: '$http_host',
    header_operations: [],
  }
}

const loading = ref(true)
const saving = ref(false)
const error = ref('')
const successMessage = ref('')
const trustedProxyCidrsText = ref('')
const form = reactive<AdvancedGlobalSettingsForm>(
  createDefaultAdvancedSettings(),
)

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: 'L7 管理',
  successTitle: 'L7 管理',
  errorDuration: 5600,
  successDuration: 3200,
})

function assignForm(payload: GlobalSettingsPayload) {
  form.enable_http1_0 = payload.enable_http1_0
  form.source_ip_strategy = payload.source_ip_strategy
  form.custom_source_ip_header = payload.custom_source_ip_header
  form.trusted_proxy_cidrs = [...payload.trusted_proxy_cidrs]
  form.http_to_https_redirect = payload.http_to_https_redirect
  form.enable_hsts = payload.enable_hsts
  form.add_x_forwarded_headers = payload.add_x_forwarded_headers
  form.rewrite_x_forwarded_for = payload.rewrite_x_forwarded_for
  form.support_gzip = payload.support_gzip
  form.support_brotli = payload.support_brotli
  form.support_sse = payload.support_sse
  form.enable_ntlm = payload.enable_ntlm
  form.fallback_self_signed_certificate =
    payload.fallback_self_signed_certificate
  form.ssl_protocols = [...payload.ssl_protocols]
  form.ssl_ciphers = payload.ssl_ciphers
  form.rewrite_host_enabled = payload.rewrite_host_enabled
  form.rewrite_host_value = payload.rewrite_host_value
  form.header_operations = payload.header_operations.map((item) => ({ ...item }))
  trustedProxyCidrsText.value = payload.trusted_proxy_cidrs.join('\n')
}

function toggleSslProtocol(protocol: string, enabled: boolean) {
  const next = new Set(form.ssl_protocols)
  if (enabled) {
    next.add(protocol)
  } else {
    next.delete(protocol)
  }
  form.ssl_protocols = [...next]
}

function addHeaderOperation() {
  form.header_operations.push({
    scope: 'request',
    action: 'set',
    header: '',
    value: '',
  })
}

function removeHeaderOperation(index: number) {
  form.header_operations.splice(index, 1)
}

async function loadSettings() {
  loading.value = true
  error.value = ''
  try {
    assignForm(await fetchGlobalSettings())
  } catch (err) {
    error.value = err instanceof Error ? err.message : '加载高级配置失败'
  } finally {
    loading.value = false
  }
}

async function saveSettings() {
  saving.value = true
  error.value = ''
  successMessage.value = ''
  try {
    const latest = await fetchGlobalSettings()
    const payload: GlobalSettingsPayload = {
      ...latest,
      ...form,
      trusted_proxy_cidrs: trustedProxyCidrsText.value
        .split('\n')
        .map((item) => item.trim())
        .filter(Boolean),
      custom_source_ip_header: form.custom_source_ip_header.trim(),
      ssl_ciphers: form.ssl_ciphers.trim(),
      rewrite_host_value: form.rewrite_host_value.trim(),
      header_operations: form.header_operations.map(
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
    assignForm(await fetchGlobalSettings())
  } catch (err) {
    error.value = err instanceof Error ? err.message : '保存高级配置失败'
  } finally {
    saving.value = false
  }
}

onMounted(loadSettings)
</script>

<template>
  <section
    class="rounded-xl border border-white/80 bg-white/78 p-4 shadow-[0_18px_48px_rgba(90,60,30,0.08)]"
  >
    <div
      class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
    >
      <div>
        <p class="text-sm tracking-wider text-blue-700">高级配置</p>
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
          {{ saving ? '保存中...' : '保存高级配置' }}
        </button>
      </div>
    </div>

    <div
      v-if="loading"
      class="mt-4 rounded-xl border border-slate-200 bg-white px-4 py-6 text-sm text-slate-500 shadow-sm"
    >
      正在加载高级配置...
    </div>

    <template v-else>
      <section class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <p class="text-sm font-semibold text-stone-900">真实来源 IP 获取</p>
        <p class="mt-1 text-xs leading-5 text-slate-500">
          决定网关从连接、真实来源 IP Header 或代理协议中识别真实来源。
        </p>

        <div class="mt-4 grid gap-x-8 gap-y-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5 items-start">
          <label class="flex items-center justify-between gap-2 text-sm text-stone-700 md:col-span-2 lg:col-span-1">
            <span class="font-medium whitespace-nowrap">获取方式</span>
            <select
              v-model="form.source_ip_strategy"
              class="w-48 flex-1 rounded border border-slate-200 bg-transparent px-2 py-1 text-sm outline-none transition focus:border-blue-500 text-left"
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

          <label class="space-y-1.5">
            <span class="text-xs font-medium text-slate-500">真实来源 IP Header</span>
            <input
              v-model="form.custom_source_ip_header"
              class="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5 text-sm outline-none transition focus:border-blue-500 focus:bg-white"
              type="text"
              placeholder="例如 x-cdn-real-ip"
            />
          </label>
          <label class="space-y-1.5 md:col-span-2 lg:col-span-1">
            <span class="text-xs font-medium text-slate-500">可信代理 CIDR</span>
            <textarea
              v-model="trustedProxyCidrsText"
              class="min-h-[6rem] w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5 text-sm outline-none transition focus:border-blue-500 focus:bg-white"
              placeholder="每行一个，如 10.0.0.0/8"
            />
          </label>
        </div>
      </section>

      <section class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <p class="text-sm font-semibold text-stone-900">协议兼容</p>
        <div class="mt-4 grid gap-3">
          <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
            <input v-model="form.enable_http1_0" type="checkbox" class="ui-switch" />
            启用 HTTP/1.0
          </label>
        </div>
      </section>

      <section class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
        <p class="text-sm font-semibold text-stone-900">SSL 合规配置</p>
        <div class="mt-4 grid gap-x-8 gap-y-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5 items-start">
          <div class="flex items-center gap-4 text-sm text-stone-700 md:col-span-2">
            <span class="font-medium whitespace-nowrap">SSL 协议版本</span>
            <div class="flex flex-wrap gap-4">
              <label
                v-for="protocol in ['TLSv1.2', 'TLSv1.3']"
                :key="protocol"
                class="inline-flex items-center gap-1.5"
              >
                <input
                  :checked="form.ssl_protocols.includes(protocol)"
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
          </div>
          <label class="flex items-center justify-between gap-2 text-sm text-stone-700 md:col-span-2 lg:col-span-1">
            <span class="font-medium whitespace-nowrap">SSL Ciphers</span>
            <input
              v-model="form.ssl_ciphers"
              class="w-48 flex-1 rounded border border-slate-200 bg-transparent px-2 py-1 text-sm outline-none transition focus:border-blue-500 text-left"
              type="text"
              placeholder="留空则沿用默认"
            />
          </label>
        </div>
      </section>

      <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.http_to_https_redirect" type="checkbox" class="ui-switch" />
          HTTP 自动跳转到 HTTPS
        </label>
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.enable_hsts" type="checkbox" class="ui-switch" />
          启用 HSTS
        </label>
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.add_x_forwarded_headers" type="checkbox" class="ui-switch" />
          为上游服务器传递 X-Forwarded-Host / Proto
        </label>
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.rewrite_x_forwarded_for" type="checkbox" class="ui-switch" />
          清空并重写 X-Forwarded-For
        </label>
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.support_gzip" type="checkbox" class="ui-switch" />
          支持 Gzip 压缩
        </label>
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.support_brotli" type="checkbox" class="ui-switch" />
          支持 Brotli 压缩
        </label>
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.support_sse" type="checkbox" class="ui-switch" />
          支持 SSE 流式响应
        </label>
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.enable_ntlm" type="checkbox" class="ui-switch" />
          启用 NTLM 认证
        </label>
        <label class="flex items-center justify-between gap-2 text-sm text-stone-700">
          <span class="font-medium">应用不存在时返回自置证书</span>
          <input v-model="form.fallback_self_signed_certificate" type="checkbox" class="ui-switch" />
        </label>
      </div>

      <div class="mt-4 grid gap-x-8 gap-y-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5">
        <label class="flex items-center justify-between gap-2 text-sm text-stone-700">
          <span class="font-medium">代理时修改请求中的 Host 头</span>
          <input v-model="form.rewrite_host_enabled" type="checkbox" class="ui-switch" />
        </label>
        <label class="flex items-center justify-between gap-2 text-sm text-stone-700">
          <span class="font-medium whitespace-nowrap">Host 头</span>
          <input
            v-model="form.rewrite_host_value"
            :disabled="!form.rewrite_host_enabled"
            class="w-24 flex-1 rounded border border-slate-200 px-2 py-1 text-sm outline-none transition focus:border-blue-500 disabled:bg-slate-50 text-left"
            type="text"
            placeholder="$http_host"
          />
        </label>
      </div>

      <section class="mt-4 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
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

        <div v-if="form.header_operations.length" class="mt-4 space-y-3">
          <div
            v-for="(item, index) in form.header_operations"
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
  </section>
</template>

<style scoped>
.ui-switch {
  appearance: none;
  width: 2.25rem;
  height: 1.25rem;
  border-radius: 9999px;
  background: rgb(203 213 225);
  position: relative;
  cursor: pointer;
  transition: background-color 0.2s ease;
}

.ui-switch::after {
  content: '';
  position: absolute;
  top: 0.125rem;
  left: 0.125rem;
  width: 1rem;
  height: 1rem;
  border-radius: 9999px;
  background: white;
  transition: transform 0.2s ease;
}

.ui-switch:checked {
  background: rgb(37 99 235);
}

.ui-switch:checked::after {
  transform: translateX(1rem);
}
</style>
ate>
