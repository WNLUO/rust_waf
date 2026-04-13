<script setup lang="ts">
import { computed } from 'vue'
import { CloudDownload, Plus, RefreshCw, Search } from 'lucide-vue-next'
import type { LocalSitesStateFilter } from '@/features/sites/composables/useAdminSites'

const props = defineProps<{
  actions: {
    refreshing: boolean
    loadingSites: boolean
  }
  hasSavedConfig: boolean
  keyword: string
  state: LocalSitesStateFilter
}>()

const emit = defineEmits<{
  createLocalSite: []
  refresh: []
  loadRemote: []
  'update:keyword': [value: string]
  'update:state': [value: LocalSitesStateFilter]
}>()

const keywordModel = computed({
  get: () => props.keyword,
  set: (value: string) => emit('update:keyword', value),
})

const stateModel = computed({
  get: () => props.state,
  set: (value: LocalSitesStateFilter) => emit('update:state', value),
})
</script>

<template>
  <section class="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
    <div
      class="flex flex-col gap-3 border-b border-slate-200 pb-4 xl:flex-row xl:items-start xl:justify-between"
    >
      <div>
        <p class="text-sm font-semibold text-stone-900">站点列表</p>
      </div>

      <div class="flex flex-wrap gap-2">
        <button
          class="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-2 text-xs font-medium text-white shadow-sm transition hover:bg-blue-600/90"
          @click="emit('createLocalSite')"
        >
          <Plus :size="14" />
          新建本地站点
        </button>
        <button
          :disabled="actions.loadingSites || !hasSavedConfig"
          class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('loadRemote')"
        >
          <CloudDownload
            :size="14"
            :class="{ 'animate-spin': actions.loadingSites }"
          />
          {{ actions.loadingSites ? '读取中...' : '从雷池同步' }}
        </button>
        <button
          :disabled="actions.refreshing"
          class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
          @click="emit('refresh')"
        >
          <RefreshCw
            :size="14"
            :class="{ 'animate-spin': actions.refreshing }"
          />
          {{ actions.refreshing ? '刷新中...' : '刷新列表' }}
        </button>
      </div>
    </div>

    <div class="mt-4 flex flex-col gap-3 lg:flex-row lg:items-end">
      <label class="min-w-0 flex-1 space-y-1.5">
        <span class="text-xs text-slate-500">搜索本地站点</span>
        <div class="relative">
          <Search
            class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
            :size="14"
          />
          <input
            v-model="keywordModel"
            class="w-full rounded-lg border border-slate-200 bg-white px-9 py-2.5 text-sm outline-none transition focus:border-blue-500"
            type="text"
            placeholder="站点名称 / 域名 / Upstream / 备注"
          />
        </div>
      </label>

      <label class="w-full space-y-1.5 lg:w-[11rem]">
        <span class="text-xs text-slate-500">启停状态</span>
        <select
          v-model="stateModel"
          class="w-full rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm outline-none transition focus:border-blue-500"
        >
          <option value="all">全部站点</option>
          <option value="enabled">只看启用</option>
          <option value="disabled">只看停用</option>
        </select>
      </label>
    </div>
  </section>
</template>
