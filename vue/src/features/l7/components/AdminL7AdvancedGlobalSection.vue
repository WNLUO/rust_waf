<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { Plus, RefreshCw, Save, Trash2 } from 'lucide-vue-next'
import { fetchGlobalSettings, updateGlobalSettings } from '@/shared/api/settings'
import type { GlobalSettingsPayload, HeaderOperationItem } from '@/shared/types'
import { useFlashMessages } from '@/shared/composables/useNotifications'

type AdvancedGlobalSettingsForm = Pick<
  GlobalSettingsPayload,
  | 'http_to_https_redirect'
  | 'enable_hsts'
  | 'add_x_forwarded_headers'
  | 'rewrite_x_forwarded_for'
  | 'support_gzip'
  | 'support_brotli'
  | 'support_sse'
  | 'enable_ntlm'
  | 'fallback_self_signed_certificate'
  | 'rewrite_host_enabled'
  | 'rewrite_host_value'
  | 'header_operations'
>

function createDefaultAdvancedSettings(): AdvancedGlobalSettingsForm {
  return {
    http_to_https_redirect: true,
    enable_hsts: true,
    add_x_forwarded_headers: true,
    rewrite_x_forwarded_for: true,
    support_gzip: true,
    support_brotli: true,
    support_sse: true,
    enable_ntlm: true,
    fallback_self_signed_certificate: true,
    rewrite_host_enabled: true,
    rewrite_host_value: '',
    header_operations: [],
  }
}

const loading = ref(true)
const saving = ref(false)
const error = ref('')
const successMessage = ref('')
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
  form.rewrite_host_enabled = payload.rewrite_host_enabled
  form.rewrite_host_value = payload.rewrite_host_value
  form.header_operations = payload.header_operations.map((item) => ({ ...item }))
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
        <h3 class="mt-2 text-2xl font-semibold text-stone-900">
          其他高级配置
        </h3>
        <p class="mt-2 text-sm leading-6 text-slate-500">
          这里集中管理 HTTP 跳转、压缩、转发头与 Host 改写等影响 L7
          行为的全局高级选项。
        </p>
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
      <div class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.http_to_https_redirect" type="checkbox" class="h-4 w-4 accent-blue-600" />
          HTTP 自动跳转到 HTTPS
        </label>
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.enable_hsts" type="checkbox" class="h-4 w-4 accent-blue-600" />
          启用 HSTS
        </label>
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.add_x_forwarded_headers" type="checkbox" class="h-4 w-4 accent-blue-600" />
          为上游服务器传递 X-Forwarded-Host / Proto
        </label>
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.rewrite_x_forwarded_for" type="checkbox" class="h-4 w-4 accent-blue-600" />
          清空并重写 X-Forwarded-For
        </label>
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.support_gzip" type="checkbox" class="h-4 w-4 accent-blue-600" />
          支持 Gzip 压缩
        </label>
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.support_brotli" type="checkbox" class="h-4 w-4 accent-blue-600" />
          支持 Brotli 压缩
        </label>
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.support_sse" type="checkbox" class="h-4 w-4 accent-blue-600" />
          支持 SSE 流式响应
        </label>
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.enable_ntlm" type="checkbox" class="h-4 w-4 accent-blue-600" />
          启用 NTLM 认证
        </label>
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.fallback_self_signed_certificate" type="checkbox" class="h-4 w-4 accent-blue-600" />
          应用不存在时返回自置证书
        </label>
      </div>

      <div class="mt-4 grid gap-4 md:grid-cols-[16rem_minmax(0,1fr)]">
        <label class="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-3 text-sm">
          <input v-model="form.rewrite_host_enabled" type="checkbox" class="h-4 w-4 accent-blue-600" />
          代理时修改请求中的 Host 头
        </label>
        <label class="space-y-1.5">
          <span class="text-xs text-slate-500">Host 头</span>
          <input
            v-model="form.rewrite_host_value"
            :disabled="!form.rewrite_host_enabled"
            class="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500 disabled:bg-slate-50"
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
