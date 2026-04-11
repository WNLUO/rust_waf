<script setup lang="ts">
import { computed } from 'vue'
import {
  PlugZap,
  RefreshCw,
  Search,
  ServerCog,
  Settings2,
} from 'lucide-vue-next'
import { RouterLink } from 'vue-router'
import StatusBadge from '../ui/StatusBadge.vue'
import type { SafeLineTestResponse } from '../../lib/types'
import type {
  ScopeFilter,
  SiteRowDraft,
  StateFilter,
} from '../../lib/adminSites'

const props = defineProps<{
  actions: {
    refreshing: boolean
    testing: boolean
    loadingSites: boolean
  }
  filteredRowsCount: number
  formatNumber: (value?: number) => string
  hasSavedConfig: boolean
  keyword: string
  primaryDraft: SiteRowDraft | null
  scope: ScopeFilter
  sitesCount: number
  sitesLoadedAt: number | null
  state: StateFilter
  testResult: SafeLineTestResponse | null
  totalLinkedSites: number
  totalLocalOnly: number
  totalLocalSites: number
  totalMapped: number
  totalMissingRemote: number
  totalOrphaned: number
  totalSyncErrors: number
  totalUnmapped: number
}>()

const emit = defineEmits<{
  refresh: []
  test: []
  loadRemote: []
  'update:keyword': [value: string]
  'update:scope': [value: ScopeFilter]
  'update:state': [value: StateFilter]
}>()

const keywordModel = computed({
  get: () => props.keyword,
  set: (value: string) => emit('update:keyword', value),
})

const scopeModel = computed({
  get: () => props.scope,
  set: (value: ScopeFilter) => emit('update:scope', value),
})

const stateModel = computed({
  get: () => props.state,
  set: (value: StateFilter) => emit('update:state', value),
})
</script>

<template>
  <section class="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
    <div
      class="flex flex-col gap-3 2xl:flex-row 2xl:items-center 2xl:justify-between"
    >
      <div class="flex flex-wrap gap-2">
        <button
          :disabled="actions.refreshing"
          class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('refresh')"
        >
          <RefreshCw
            :size="14"
            :class="{ 'animate-spin': actions.refreshing }"
          />
          {{ actions.refreshing ? '刷新中...' : '刷新' }}
        </button>
        <button
          :disabled="actions.testing || !hasSavedConfig"
          class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('test')"
        >
          <PlugZap :size="14" :class="{ 'animate-pulse': actions.testing }" />
          {{ actions.testing ? '测试中...' : '测试连接' }}
        </button>
        <button
          :disabled="actions.loadingSites || !hasSavedConfig"
          class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('loadRemote')"
        >
          <ServerCog
            :size="14"
            :class="{ 'animate-spin': actions.loadingSites }"
          />
          {{ actions.loadingSites ? '读取中...' : '读取远端' }}
        </button>
        <RouterLink
          to="/admin/settings"
          class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
        >
          <Settings2 :size="14" />
          系统设置
        </RouterLink>
      </div>

      <div class="flex flex-wrap gap-2">
        <StatusBadge
          :text="
            primaryDraft ? `主站点 ${primaryDraft.local_alias}` : '未设置主站点'
          "
          :type="primaryDraft ? 'info' : 'muted'"
          compact
        />
        <StatusBadge
          :text="
            sitesLoadedAt
              ? `远端已读取 ${formatNumber(sitesCount)} 条`
              : '远端站点未读取'
          "
          :type="sitesLoadedAt ? 'success' : 'muted'"
          compact
        />
      </div>
    </div>

    <div class="mt-4 flex flex-nowrap items-end gap-3 overflow-x-auto">
      <label class="min-w-[18rem] flex-1 space-y-1.5">
        <span class="text-xs text-slate-500">搜索</span>
        <div class="relative">
          <Search
            class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
            :size="14"
          />
          <input
            v-model="keywordModel"
            class="w-full rounded-lg border border-slate-200 bg-white px-9 py-2.5 text-sm outline-none transition focus:border-blue-500"
            type="text"
            placeholder="别名 / 本地域名 / 雷池域名 / 站点 ID / 备注"
          />
        </div>
      </label>

      <label class="w-[11rem] shrink-0 space-y-1.5">
        <span class="text-xs text-slate-500">对账视图</span>
        <select
          v-model="scopeModel"
          class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
        >
          <option value="all">全部站点</option>
          <option value="mapped">只看已映射</option>
          <option value="unmapped">只看待建映射</option>
          <option value="orphaned">只看孤儿映射</option>
          <option value="local_only">只看仅本地</option>
          <option value="missing_remote">只看远端缺失</option>
        </select>
      </label>

      <label class="w-[11rem] shrink-0 space-y-1.5">
        <span class="text-xs text-slate-500">映射状态</span>
        <select
          v-model="stateModel"
          class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
        >
          <option value="all">全部状态</option>
          <option value="enabled">只看启用映射</option>
          <option value="disabled">只看停用映射</option>
          <option value="primary">只看主站点</option>
        </select>
      </label>
    </div>

    <div class="mt-3 flex flex-wrap gap-2">
      <StatusBadge
        :text="`当前列表 ${formatNumber(filteredRowsCount)} 条`"
        type="info"
        compact
      />
      <StatusBadge
        :text="`已映射 ${formatNumber(totalMapped)} 条`"
        type="success"
        compact
      />
      <StatusBadge
        :text="`待建映射 ${formatNumber(totalUnmapped)} 条`"
        type="muted"
        compact
      />
      <StatusBadge
        :text="`孤儿映射 ${formatNumber(totalOrphaned)} 条`"
        type="warning"
        compact
      />
      <StatusBadge
        :text="`仅本地 ${formatNumber(totalLocalOnly)} 条`"
        type="info"
        compact
      />
      <StatusBadge
        :text="`远端缺失 ${formatNumber(totalMissingRemote)} 条`"
        type="warning"
        compact
      />
      <StatusBadge
        :text="`本地站点 ${formatNumber(totalLocalSites)} 条`"
        type="muted"
        compact
      />
      <StatusBadge
        :text="
          totalSyncErrors
            ? `链路 ${formatNumber(totalLinkedSites)} 条，错误 ${formatNumber(totalSyncErrors)} 条`
            : `链路 ${formatNumber(totalLinkedSites)} 条`
        "
        :type="totalSyncErrors ? 'warning' : 'muted'"
        compact
      />
    </div>

    <div
      class="mt-3 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600"
    >
      这个页面现在聚焦站点对账与同步操作。本地别名、主站点和映射启停请到
      <RouterLink
        to="/admin/safeline"
        class="font-medium text-blue-700 hover:underline"
      >
        雷池联动
      </RouterLink>
      页面维护。
    </div>

    <div
      v-if="!hasSavedConfig"
      class="mt-3 rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600"
    >
      还没有保存雷池地址或鉴权参数，当前只能查看本地站点和本地映射。
    </div>

    <div
      v-if="testResult"
      class="mt-3 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-600"
    >
      <div class="flex flex-wrap items-center gap-2">
        <StatusBadge
          :text="
            testResult.status === 'ok'
              ? '连接测试通过'
              : testResult.status === 'warning'
                ? '连接测试需确认'
                : '连接测试失败'
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
        <span>{{ testResult.message }}</span>
      </div>
    </div>
  </section>
</template>
