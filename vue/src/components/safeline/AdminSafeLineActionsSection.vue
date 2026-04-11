<script setup lang="ts">
import { Download, RefreshCw, ShieldCheck, Upload } from 'lucide-vue-next'
import type { SafeLineSyncStateResponse } from '../../lib/types'
import StatusBadge from '../ui/StatusBadge.vue'

defineProps<{
  actions: {
    syncingEvents: boolean
    pullingBlocked: boolean
    pushingBlocked: boolean
    refreshing: boolean
  }
  formatTimestamp: (value?: number | null) => string
  syncCards: Array<{
    key: string
    title: string
    description: string
    data: SafeLineSyncStateResponse | null
  }>
  syncStatusText: (item: SafeLineSyncStateResponse | null) => string
  syncStatusType: (
    item: SafeLineSyncStateResponse | null,
  ) => 'success' | 'warning' | 'muted'
}>()

defineEmits<{
  pullBlocked: []
  pushBlocked: []
  refresh: []
  syncEvents: []
}>()
</script>

<template>
  <div
    class="rounded-xl border border-white/80 bg-white/78 p-4 shadow-[0_14px_40px_rgba(90,60,30,0.07)]"
  >
    <div class="flex items-center justify-between gap-3">
      <div>
        <p class="text-sm font-semibold text-stone-900">联动操作</p>
        <p class="mt-1 text-xs leading-5 text-slate-500">
          这些按钮直接调用后端已实现的雷池同步接口。
        </p>
      </div>
      <ShieldCheck :size="18" class="text-blue-700" />
    </div>

    <div class="mt-4 grid gap-3 md:grid-cols-2">
      <button
        :disabled="actions.syncingEvents"
        class="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-left transition hover:border-blue-500/40 disabled:cursor-not-allowed disabled:opacity-60"
        @click="$emit('syncEvents')"
      >
        <span>
          <span class="block text-sm font-medium text-stone-900"
            >同步雷池事件</span
          >
          <span class="mt-1 block text-xs text-slate-500"
            >写入本地事件库并套用站点映射。</span
          >
        </span>
        <RefreshCw
          :size="16"
          :class="{ 'animate-spin': actions.syncingEvents }"
        />
      </button>

      <button
        :disabled="actions.pullingBlocked"
        class="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-left transition hover:border-blue-500/40 disabled:cursor-not-allowed disabled:opacity-60"
        @click="$emit('pullBlocked')"
      >
        <span>
          <span class="block text-sm font-medium text-stone-900"
            >拉取雷池封禁</span
          >
          <span class="mt-1 block text-xs text-slate-500"
            >把远端封禁同步到本地封禁名单。</span
          >
        </span>
        <Download :size="16" />
      </button>

      <button
        :disabled="actions.pushingBlocked"
        class="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-left transition hover:border-blue-500/40 disabled:cursor-not-allowed disabled:opacity-60"
        @click="$emit('pushBlocked')"
      >
        <span>
          <span class="block text-sm font-medium text-stone-900"
            >推送本地封禁</span
          >
          <span class="mt-1 block text-xs text-slate-500"
            >把本地封禁联动到雷池。</span
          >
        </span>
        <Upload :size="16" />
      </button>

      <button
        :disabled="actions.refreshing"
        class="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-left transition hover:border-blue-500/40 disabled:cursor-not-allowed disabled:opacity-60"
        @click="$emit('refresh')"
      >
        <span>
          <span class="block text-sm font-medium text-stone-900"
            >刷新执行状态</span
          >
          <span class="mt-1 block text-xs text-slate-500"
            >查看最近一次成功时间和导入统计。</span
          >
        </span>
        <RefreshCw :size="16" :class="{ 'animate-spin': actions.refreshing }" />
      </button>
    </div>

    <div class="mt-3 grid gap-3">
      <article
        v-for="item in syncCards"
        :key="item.key"
        class="rounded-lg border border-slate-200 bg-white/80 p-4"
      >
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p class="text-sm font-medium text-stone-900">{{ item.title }}</p>
            <p class="mt-1 text-xs leading-5 text-slate-500">
              {{ item.description }}
            </p>
          </div>
          <StatusBadge
            :text="syncStatusText(item.data)"
            :type="syncStatusType(item.data)"
            compact
          />
        </div>
        <div class="mt-3 grid gap-2 text-xs text-slate-500 md:grid-cols-2">
          <p>最近成功：{{ formatTimestamp(item.data?.last_success_at) }}</p>
          <p>最近更新：{{ formatTimestamp(item.data?.updated_at) }}</p>
          <p>最近导入：{{ item.data?.last_imported_count ?? 0 }}</p>
          <p>最近跳过：{{ item.data?.last_skipped_count ?? 0 }}</p>
        </div>
      </article>
    </div>
  </div>
</template>
