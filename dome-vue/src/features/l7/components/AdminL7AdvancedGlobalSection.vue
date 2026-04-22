<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { Plus, Trash2, X } from 'lucide-vue-next'
import { fetchGlobalSettings, updateGlobalSettings } from '@/shared/api/settings'
import type { GlobalSettingsPayload, HeaderOperationItem } from '@/shared/types'
import { useFlashMessages } from '@/shared/composables/useNotifications'

type AdvancedGlobalSettingsForm = Pick<
  GlobalSettingsPayload,
  | 'source_ip_strategy'
  | 'custom_source_ip_header'
  | 'http_to_https_redirect'
  | 'enable_hsts'
  | 'add_x_forwarded_headers'
  | 'rewrite_x_forwarded_for'
  | 'support_sse'
  | 'enable_ntlm'
  | 'ssl_protocols'
  | 'ssl_ciphers'
  | 'header_operations'
>

function createDefaultAdvancedSettings(): AdvancedGlobalSettingsForm {
  return {
    source_ip_strategy: 'connection',
    custom_source_ip_header: '',
    http_to_https_redirect: true,
    enable_hsts: true,
    add_x_forwarded_headers: true,
    rewrite_x_forwarded_for: true,
    support_sse: true,
    enable_ntlm: true,
    ssl_protocols: ['TLSv1.2', 'TLSv1.3'],
    ssl_ciphers: '',
    header_operations: [],
  }
}

const loading = ref(true)
const saving = ref(false)
const error = ref('')
const successMessage = ref('')
const sslCiphersDialogOpen = ref(false)
const form = reactive<AdvancedGlobalSettingsForm>(
  createDefaultAdvancedSettings(),
)

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: '高级配置',
  successTitle: '高级配置',
  errorDuration: 5600,
  successDuration: 3200,
})

function assignForm(payload: GlobalSettingsPayload) {
  form.source_ip_strategy = payload.source_ip_strategy
  form.custom_source_ip_header = payload.custom_source_ip_header
  form.http_to_https_redirect = payload.http_to_https_redirect
  form.enable_hsts = payload.enable_hsts
  form.add_x_forwarded_headers = payload.add_x_forwarded_headers
  form.rewrite_x_forwarded_for = payload.rewrite_x_forwarded_for
  form.support_sse = payload.support_sse
  form.enable_ntlm = payload.enable_ntlm
  form.ssl_protocols = [...payload.ssl_protocols]
  form.ssl_ciphers = payload.ssl_ciphers
  form.header_operations = payload.header_operations.map((item) => ({ ...item }))
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
      custom_source_ip_header: form.custom_source_ip_header.trim(),
      ssl_ciphers: form.ssl_ciphers.trim(),
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
    return true
  } catch (err) {
    error.value = err instanceof Error ? err.message : '保存高级配置失败'
    return false
  } finally {
    saving.value = false
  }
}

defineExpose({
  saveSettings,
})

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
    </div>

    <div
      v-if="loading"
      class="mt-4 rounded-xl border border-slate-200 bg-white px-4 py-6 text-sm text-slate-500 shadow-sm"
    >
      正在加载高级配置...
    </div>

    <template v-else>
      <div>
        <p class="text-sm font-semibold text-stone-900">真实来源 IP 获取</p>

        <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
          <label
            v-if="false"
            class="flex items-center justify-start gap-2 text-sm text-stone-700"
          >
            <span class="font-medium whitespace-nowrap">获取方式</span>
            <select
              v-model="form.source_ip_strategy"
              class="w-auto min-w-[15rem] rounded border border-slate-200 bg-transparent px-2 py-1 text-sm outline-none transition focus:border-blue-500 text-left"
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

          <label class="flex items-center justify-start gap-2 text-sm text-stone-700">
            <span class="font-medium whitespace-nowrap">真实来源 IP Header</span>
            <input
              v-model="form.custom_source_ip_header"
              class="w-[12rem] rounded border border-slate-200 bg-transparent px-2 py-1 text-sm outline-none transition focus:border-blue-500 text-left"
              type="text"
              placeholder="例如 x-cdn-real-ip"
            />
          </label>
        </div>
      </div>

      <div class="border-t border-slate-200 pt-4">
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
          <div class="flex items-center justify-between gap-2 text-sm text-stone-700 md:col-span-2 lg:col-span-1">
            <span class="font-medium whitespace-nowrap">SSL 加密套件</span>
            <button
              type="button"
              class="rounded border border-slate-200 bg-transparent px-3 py-1 text-sm text-stone-700 outline-none transition hover:border-blue-500 hover:text-blue-700"
              @click="sslCiphersDialogOpen = true"
            >
              {{ form.ssl_ciphers.trim() ? '已自定义' : '默认' }}
            </button>
          </div>
        </div>
      </div>

      <div class="mt-4 flex flex-wrap items-center gap-x-6 gap-y-3">
        <label class="inline-flex items-center justify-start gap-3 text-sm text-stone-800">
          <span>HTTP 自动跳转到 HTTPS</span>
          <input v-model="form.http_to_https_redirect" type="checkbox" class="ui-switch" />
        </label>
        <label class="inline-flex items-center justify-start gap-3 text-sm text-stone-800">
          <span>启用 HSTS</span>
          <input v-model="form.enable_hsts" type="checkbox" class="ui-switch" />
        </label>
        <label class="inline-flex items-center justify-start gap-3 text-sm text-stone-800">
          <span>为上游服务器传递 X-Forwarded-Host / Proto</span>
          <input v-model="form.add_x_forwarded_headers" type="checkbox" class="ui-switch" />
        </label>
        <label class="inline-flex items-center justify-start gap-3 text-sm text-stone-800">
          <span>清空并重写 X-Forwarded-For</span>
          <input v-model="form.rewrite_x_forwarded_for" type="checkbox" class="ui-switch" />
        </label>
        <label class="inline-flex items-center justify-start gap-3 text-sm text-stone-800">
          <span>支持 SSE 流式响应</span>
          <input v-model="form.support_sse" type="checkbox" class="ui-switch" />
        </label>
        <label class="inline-flex items-center justify-start gap-3 text-sm text-stone-800">
          <span>启用 NTLM 认证</span>
          <input v-model="form.enable_ntlm" type="checkbox" class="ui-switch" />
        </label>
      </div>

      <div class="mt-4 border-t border-slate-200 pt-4">
        <div class="flex items-center justify-between gap-3">
          <p class="text-sm font-semibold text-stone-900">HTTP 请求头操作</p>
          <button
            class="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
            @click="addHeaderOperation"
          >
            <Plus :size="12" />
            添加一项请求头操作
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
              placeholder="请求头名称"
            />
            <input
              v-model="item.value"
              :disabled="item.action === 'remove'"
              class="rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500 disabled:bg-slate-100"
              type="text"
              placeholder="请求头值"
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
          还没有添加请求头操作。
        </p>
      </div>

      <div
        v-if="sslCiphersDialogOpen"
        class="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/30 px-4"
        @click.self="sslCiphersDialogOpen = false"
      >
        <div
          class="w-full max-w-xl rounded-2xl border border-slate-200 bg-white p-5 shadow-[0_24px_60px_rgba(15,23,42,0.18)]"
        >
          <div class="flex items-start justify-between gap-4">
            <div>
              <p class="text-sm tracking-wider text-blue-700">SSL 加密套件</p>
              <h3 class="mt-2 text-lg font-semibold text-stone-900">
                自定义 TLS Cipher
              </h3>
            </div>
            <button
              type="button"
              class="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 text-stone-600 transition hover:border-slate-300 hover:text-stone-900"
              @click="sslCiphersDialogOpen = false"
            >
              <X :size="14" />
            </button>
          </div>

          <label class="mt-4 block text-sm text-stone-700">
            Cipher 字符串
            <textarea
              v-model="form.ssl_ciphers"
              class="mt-2 min-h-[8rem] w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 font-mono text-xs outline-none transition focus:border-blue-500"
              placeholder="留空则沿用默认"
            />
          </label>

          <div class="mt-5 flex justify-end gap-2">
            <button
              type="button"
              class="rounded-lg border border-slate-200 px-4 py-2 text-sm text-stone-700 transition hover:border-slate-300 hover:text-stone-900"
              @click="sslCiphersDialogOpen = false"
            >
              完成
            </button>
          </div>
        </div>
      </div>

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
