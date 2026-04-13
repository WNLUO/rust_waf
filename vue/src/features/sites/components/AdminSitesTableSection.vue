<script setup lang="ts">
import { PencilLine, RefreshCw } from 'lucide-vue-next'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import type { SiteRowDraft } from '@/features/sites/utils/adminSites'

defineProps<{
  filteredRows: SiteRowDraft[]
  hasSavedConfig: boolean
  localActionLabel: (row: SiteRowDraft) => string
}>()

const emit = defineEmits<{
  editLocalSite: [row: SiteRowDraft]
  syncLocalSite: [row: SiteRowDraft]
}>()
</script>

<template>
  <section class="rounded-2xl border border-slate-200 bg-white shadow-sm">
    <div
      class="flex flex-col gap-2 border-b border-slate-200 px-4 py-4 xl:flex-row xl:items-end xl:justify-between"
    >
      <div>
        <p class="text-sm font-semibold text-stone-900">站点列表</p>
      </div>
    </div>

    <div
      v-if="filteredRows.length === 0"
      class="px-4 py-8 text-center text-sm text-slate-500"
    >
      当前筛选条件下没有本地站点。
    </div>

    <div v-else class="overflow-x-auto">
      <table class="w-full min-w-[1080px] text-left text-sm text-slate-700">
        <thead
          class="bg-slate-50 text-xs uppercase tracking-wide text-slate-500"
        >
          <tr>
            <th class="px-4 py-3 font-medium">站点</th>
            <th class="px-4 py-3 font-medium">主域名</th>
            <th class="px-4 py-3 font-medium">本地配置</th>
            <th class="px-4 py-3 font-medium">同步状态</th>
            <th class="px-4 py-3 font-medium">操作</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-200">
          <tr
            v-for="row in filteredRows"
            :key="row.row_key"
            class="transition hover:bg-slate-50/50"
          >
            <td class="px-4 py-3 align-top">
              <div class="space-y-1.5">
                <div class="flex flex-wrap items-center gap-1.5">
                  <p
                    class="max-w-[260px] truncate font-medium text-stone-900"
                    :title="row.local_site_name || row.local_primary_hostname"
                  >
                    {{ row.local_site_name || '未命名站点' }}
                  </p>
                  <StatusBadge
                    :text="row.local_enabled ? '已启用' : '已停用'"
                    :type="row.local_enabled ? 'success' : 'warning'"
                    compact
                  />
                  <StatusBadge
                    v-if="row.is_primary"
                    text="主站点"
                    type="info"
                    compact
                  />
                  <StatusBadge
                    v-if="row.link_id"
                    text="已关联雷池"
                    type="muted"
                    compact
                  />
                </div>
              </div>
            </td>

            <td class="px-4 py-3 align-top">
              <p
                class="max-w-[220px] truncate text-xs text-slate-500"
                :title="row.local_primary_hostname || '未设置'"
              >
                {{ row.local_primary_hostname || '未设置' }}
              </p>
            </td>

            <td class="px-4 py-3 align-top">
              <div class="grid gap-1.5 text-xs text-slate-500">
                <p class="truncate" :title="row.local_upstreams.join(' / ')">
                  {{
                    row.local_upstreams.length
                      ? row.local_upstreams.join(' / ')
                      : '未设置'
                  }}
                </p>
              </div>
            </td>

            <td class="px-4 py-3 align-top">
              <div class="space-y-2">
                <div class="flex flex-wrap items-center gap-1.5">
                  <StatusBadge
                    :text="row.link_last_error ? '同步异常' : '同步正常'"
                    :type="row.link_last_error ? 'warning' : 'success'"
                    compact
                  />
                  <StatusBadge
                    :text="row.link_id ? '已建同步链路' : '未建同步链路'"
                    :type="row.link_id ? 'info' : 'muted'"
                    compact
                  />
                </div>
                <div
                  v-if="row.link_last_error"
                  class="rounded-md border border-red-200 bg-red-50 px-2.5 py-2 text-xs text-red-700"
                >
                  {{ row.link_last_error }}
                </div>
              </div>
            </td>

            <td class="px-4 py-3 align-top">
              <div class="flex flex-wrap items-center gap-2">
                <button
                  class="inline-flex h-8 items-center gap-1.5 rounded border border-slate-200 bg-white px-2.5 text-xs text-stone-700 transition hover:border-blue-400 hover:text-blue-700"
                  @click="emit('editLocalSite', row)"
                >
                  <PencilLine :size="14" />
                  <span>编辑本地</span>
                </button>

                <button
                  :disabled="!hasSavedConfig"
                  class="inline-flex h-8 items-center gap-1.5 rounded border border-amber-200 bg-amber-50 px-2.5 text-xs text-amber-900 transition hover:border-amber-400 disabled:cursor-not-allowed disabled:opacity-60"
                  @click="emit('syncLocalSite', row)"
                >
                  <RefreshCw :size="14" />
                  <span>{{ localActionLabel(row) }}</span>
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
