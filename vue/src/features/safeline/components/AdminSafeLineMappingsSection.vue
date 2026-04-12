<script setup lang="ts">
import { Save } from 'lucide-vue-next'
import type { SafeLineMappingDraft } from '@/features/safeline/utils/adminSafeLine'
import StatusBadge from '@/shared/ui/StatusBadge.vue'

defineProps<{
  actions: {
    savingMappings: boolean
  }
  formatTimestamp: (value?: number | null) => string
  sortedDrafts: SafeLineMappingDraft[]
}>()

defineEmits<{
  clearPrimary: []
  save: []
  selectPrimary: [siteId: string]
}>()
</script>

<template>
  <section
    class="rounded-xl border border-white/80 bg-white/78 p-4 shadow-[0_14px_40px_rgba(90,60,30,0.07)]"
  >
    <div
      class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
    >
      <div>
        <p class="text-sm font-semibold text-stone-900">站点映射管理</p>
        <p class="mt-1 text-xs leading-5 text-slate-500">
          读取远端站点后，可以在这里补本地别名、是否启用和主站点标识。未出现在本次远端读取中的历史映射会保留。
        </p>
      </div>
      <div class="flex flex-wrap gap-2">
        <button
          class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
          @click="$emit('clearPrimary')"
        >
          清空主站点
        </button>
        <button
          :disabled="actions.savingMappings || !sortedDrafts.length"
          class="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/25 bg-slate-50 px-3 py-1.5 text-xs font-medium text-blue-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
          @click="$emit('save')"
        >
          <Save :size="12" />
          {{ actions.savingMappings ? '保存中...' : '保存映射' }}
        </button>
      </div>
    </div>

    <div
      v-if="!sortedDrafts.length"
      class="mt-4 rounded-lg border border-dashed border-slate-200 bg-white px-4 py-8 text-sm text-slate-500"
    >
      还没有可编辑的站点映射。先点击上方"读取远端站点"，或确认数据库里已经有历史映射。
    </div>

    <div v-else class="mt-4 grid gap-4">
      <article
        v-for="draft in sortedDrafts"
        :key="draft.safeline_site_id"
        class="rounded-xl border border-slate-200 bg-slate-50 p-4"
      >
        <div
          class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between"
        >
          <div class="space-y-2">
            <div class="flex flex-wrap items-center gap-2">
              <p class="text-sm font-medium text-stone-900">
                {{ draft.safeline_site_name || '未命名站点' }}
              </p>
              <StatusBadge
                v-if="draft.enabled"
                text="启用映射"
                type="success"
                compact
              />
              <StatusBadge v-else text="停用映射" type="muted" compact />
              <StatusBadge
                v-if="draft.is_primary"
                text="主站点"
                type="info"
                compact
              />
              <StatusBadge
                v-if="draft.orphaned"
                text="历史映射"
                type="warning"
                compact
              />
            </div>
            <p class="font-mono text-xs text-slate-500">
              站点 ID：{{ draft.safeline_site_id }}
            </p>
            <p class="font-mono text-xs text-slate-500">
              域名：{{ draft.safeline_site_domain || '未提供域名' }}
            </p>
            <p class="text-xs text-slate-500">
              上次更新：{{ formatTimestamp(draft.updated_at) }}
            </p>
          </div>

          <div class="grid gap-3 md:grid-cols-[1.2fr_1fr] lg:w-[520px]">
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">本地别名</span>
              <input
                v-model="draft.local_alias"
                type="text"
                class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
              />
            </label>
            <label class="space-y-1.5">
              <span class="text-xs text-slate-500">备注</span>
              <input
                v-model="draft.notes"
                type="text"
                class="w-full rounded-[16px] border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition focus:border-blue-500"
              />
            </label>
            <label
              class="flex items-center gap-2 rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
            >
              <input
                v-model="draft.enabled"
                type="checkbox"
                class="accent-blue-600"
              />
              启用该映射
            </label>
            <label
              class="flex items-center gap-2 rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
            >
              <input
                type="radio"
                name="safeline-primary"
                :checked="draft.is_primary"
                class="accent-blue-600"
                @change="$emit('selectPrimary', draft.safeline_site_id)"
              />
              设为主站点
            </label>
          </div>
        </div>
      </article>
    </div>
  </section>
</template>
