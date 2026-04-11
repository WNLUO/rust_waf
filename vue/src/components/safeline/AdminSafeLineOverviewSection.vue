<script setup lang="ts">
import { PlugZap, ServerCog } from 'lucide-vue-next'
import type { SafeLineTestResponse, SettingsPayload } from '../../lib/types'
import UiStatusBadge from '../ui/StatusBadge.vue'

defineProps<{
  actions: {
    testing: boolean
    loadingSites: boolean
  }
  authMode: string
  hasSavedConfig: boolean
  settings: SettingsPayload | null
  testResult: SafeLineTestResponse | null
}>()

defineEmits<{
  loadSites: []
  test: []
}>()
</script>

<template>
  <div
    class="rounded-xl border border-white/80 bg-white/78 p-4 shadow-[0_14px_40px_rgba(90,60,30,0.07)]"
  >
    <div class="flex items-center justify-between gap-3">
      <div>
        <p class="text-sm font-semibold text-stone-900">接入概况</p>
        <p class="mt-1 text-xs leading-5 text-slate-500">
          当前展示的是已保存到后端数据库的雷池配置。
        </p>
      </div>
      <UiStatusBadge
        :text="settings?.safeline.enabled ? '已启用' : '未启用'"
        :type="settings?.safeline.enabled ? 'success' : 'warning'"
        compact
      />
    </div>

    <div class="mt-4 grid gap-3 md:grid-cols-2">
      <div class="rounded-lg bg-slate-50 p-4">
        <p class="text-xs text-slate-500">雷池地址</p>
        <p class="mt-2 break-all text-sm font-medium text-stone-900">
          {{ settings?.safeline.base_url || '未配置' }}
        </p>
      </div>
      <div class="rounded-lg bg-slate-50 p-4">
        <p class="text-xs text-slate-500">鉴权方式</p>
        <p class="mt-2 text-sm font-medium text-stone-900">
          {{ authMode }}
        </p>
      </div>
      <div class="rounded-lg bg-slate-50 p-4">
        <p class="text-xs text-slate-500">站点列表路径</p>
        <p class="mt-2 break-all font-mono text-xs text-stone-900">
          {{ settings?.safeline.site_list_path || '未配置' }}
        </p>
      </div>
      <div class="rounded-lg bg-slate-50 p-4">
        <p class="text-xs text-slate-500">事件列表路径</p>
        <p class="mt-2 break-all font-mono text-xs text-stone-900">
          {{ settings?.safeline.event_list_path || '未配置' }}
        </p>
      </div>
    </div>

    <div
      v-if="!hasSavedConfig"
      class="mt-4 rounded-lg border border-dashed border-slate-200 bg-white px-4 py-3 text-sm text-slate-500"
    >
      还没有保存雷池地址。请先到系统设置填写连接参数并保存，再回来执行联调。
    </div>

    <div class="mt-4 flex flex-wrap gap-2.5">
      <button
        :disabled="actions.testing || !hasSavedConfig"
        class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-slate-50 px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
        @click="$emit('test')"
      >
        <PlugZap :size="12" />
        {{ actions.testing ? '测试中...' : '测试连接' }}
      </button>
      <button
        :disabled="actions.loadingSites || !hasSavedConfig"
        class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-white px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-60"
        @click="$emit('loadSites')"
      >
        <ServerCog :size="12" />
        {{ actions.loadingSites ? '读取中...' : '读取远端站点' }}
      </button>
    </div>

    <div
      v-if="testResult"
      class="mt-4 rounded-lg border border-slate-200 bg-slate-50 p-4"
    >
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p class="text-sm font-medium text-stone-900">最近一次测试结果</p>
          <p class="mt-1 text-xs leading-5 text-slate-500">
            {{ testResult.message }}
          </p>
        </div>
        <UiStatusBadge
          :text="
            testResult.status === 'ok'
              ? '通过'
              : testResult.status === 'warning'
                ? '需确认'
                : '失败'
          "
          :type="
            testResult.status === 'ok'
              ? 'success'
              : testResult.status === 'warning'
                ? 'warning'
                : 'error'
          "
          compact
        />
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
            >
              （HTTP {{ testResult.openapi_doc_status }}）
            </span>
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
            >
              （HTTP {{ testResult.auth_probe_status }}）
            </span>
          </p>
        </div>
      </div>
    </div>
  </div>
</template>
