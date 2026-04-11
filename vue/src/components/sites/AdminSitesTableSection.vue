<script setup lang="ts">
import { PencilLine, Plus, RefreshCw } from 'lucide-vue-next'
import StatusBadge from '../ui/StatusBadge.vue'
import {
  mappingStateText,
  mappingStateType,
  remoteStatusText,
  remoteStatusType,
  syncModeLabel,
  type SiteRowDraft,
} from '../../lib/adminSites'

defineProps<{
  filteredRows: SiteRowDraft[]
  formatTimestamp: (timestamp?: number | null) => string
  hasSavedConfig: boolean
  localActionLabel: (row: SiteRowDraft) => string
  remoteActionLabel: (row: SiteRowDraft) => string
  rowActionPending: (row: SiteRowDraft, action: 'pull' | 'push') => boolean
  rowBusy: (row: SiteRowDraft) => boolean
  rowSyncText: (row: SiteRowDraft) => string
  sitesLoadedAt: number | null
}>()

const emit = defineEmits<{
  createLocalSite: []
  editLocalSite: [row: SiteRowDraft]
  syncLocalSite: [row: SiteRowDraft]
  syncRemoteSite: [row: SiteRowDraft]
}>()
</script>

<template>
  <section class="rounded-2xl border border-slate-200 bg-white shadow-sm">
    <div
      class="flex flex-col gap-4 border-b border-slate-200 px-4 py-4 xl:flex-row xl:items-end xl:justify-between"
    >
      <div>
        <p class="text-sm font-semibold text-stone-900">站点对账列表</p>
        <p class="mt-1 text-xs text-slate-500">
          按“本地站点、雷池站点、映射、同步链路”四类数据合并展示，方便排查缺链路、孤儿映射和双端配置漂移。
        </p>
      </div>
      <div class="flex flex-wrap items-center gap-3">
        <button
          class="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-2 text-xs font-medium text-white shadow-sm transition hover:bg-blue-600/90"
          @click="emit('createLocalSite')"
        >
          <Plus :size="14" />
          新建本地站点
        </button>
        <p class="text-xs text-slate-500">
          {{
            sitesLoadedAt
              ? `最近一次远端读取：${formatTimestamp(sitesLoadedAt)}`
              : '还没有读取远端站点。'
          }}
        </p>
      </div>
    </div>

    <div
      v-if="filteredRows.length === 0"
      class="px-4 py-8 text-center text-sm text-slate-500"
    >
      当前筛选条件下没有可展示的站点。可以先读取远端站点，或者调整搜索与筛选条件。
    </div>

    <div v-else class="overflow-x-auto">
      <table class="w-full min-w-[1420px] text-left text-sm text-slate-700">
        <thead
          class="bg-slate-50 text-xs uppercase tracking-wide text-slate-500"
        >
          <tr>
            <th class="px-4 py-3 font-medium">站点标识</th>
            <th class="px-4 py-3 font-medium">本地配置</th>
            <th class="px-4 py-3 font-medium">雷池配置</th>
            <th class="px-4 py-3 font-medium">同步状态</th>
            <th class="px-4 py-3 font-medium">操作</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-200">
          <tr
            v-for="row in filteredRows"
            :key="row.row_key"
            class="items-center transition hover:bg-slate-50/50"
          >
            <td class="px-4 py-2">
              <div class="space-y-1.5">
                <div class="flex flex-wrap items-center gap-1.5">
                  <p
                    class="max-w-[220px] truncate font-medium text-stone-900"
                    :title="
                      row.local_alias ||
                      row.local_primary_hostname ||
                      row.safeline_site_domain ||
                      row.local_site_name
                    "
                  >
                    {{
                      row.local_alias ||
                      row.local_primary_hostname ||
                      row.safeline_site_domain ||
                      row.local_site_name ||
                      '未命名'
                    }}
                  </p>
                  <StatusBadge
                    v-if="row.saved"
                    text="已映射"
                    type="success"
                    compact
                  />
                  <StatusBadge
                    v-else-if="row.remote_present"
                    text="待建映射"
                    type="muted"
                    compact
                  />
                  <StatusBadge
                    v-if="row.is_primary"
                    text="主站点"
                    type="info"
                    compact
                  />
                  <StatusBadge
                    v-if="row.orphaned"
                    text="历史映射"
                    type="warning"
                    compact
                  />
                </div>
                <p class="text-xs text-slate-500">
                  {{
                    row.local_primary_hostname ||
                    row.safeline_site_domain ||
                    row.local_site_name ||
                    '暂无主机标识'
                  }}
                </p>
                <div class="flex flex-wrap gap-2 text-xs text-slate-400">
                  <span v-if="row.local_site_id" class="font-mono">
                    LOCAL:{{ row.local_site_id }}
                  </span>
                  <span v-if="row.safeline_site_id" class="font-mono">
                    SAFE:{{ row.safeline_site_id }}
                  </span>
                </div>
              </div>
            </td>

            <td class="px-4 py-2">
              <div v-if="row.local_present" class="space-y-1.5">
                <div class="flex flex-wrap items-center gap-1.5">
                  <span class="font-medium text-stone-900">{{
                    row.local_site_name
                  }}</span>
                  <span class="font-mono text-[10px] text-slate-400"
                    >ID:{{ row.local_site_id }}</span
                  >
                  <StatusBadge
                    :text="row.local_enabled ? '本地启用' : '本地停用'"
                    :type="row.local_enabled ? 'success' : 'warning'"
                    compact
                  />
                  <StatusBadge
                    :text="
                      row.local_sync_mode
                        ? `模式 ${syncModeLabel(row.local_sync_mode)}`
                        : '模式未设置'
                    "
                    type="muted"
                    compact
                  />
                  <StatusBadge
                    :text="row.local_upstreams.length ? '已配上游' : '未配上游'"
                    :type="row.local_upstreams.length ? 'info' : 'warning'"
                    compact
                  />
                </div>
                <div class="grid gap-1 text-xs text-slate-500">
                  <p class="truncate" :title="row.local_primary_hostname">
                    主域名：{{ row.local_primary_hostname || '未设置' }}
                  </p>
                  <p class="truncate" :title="row.local_hostnames.join(' / ')">
                    Hostnames：{{
                      row.local_hostnames.length
                        ? row.local_hostnames.join(' / ')
                        : '未设置'
                    }}
                  </p>
                  <p>
                    监听端口：{{
                      row.local_listen_ports.length
                        ? row.local_listen_ports.join(' / ')
                        : '未设置'
                    }}
                  </p>
                  <p class="truncate" :title="row.local_upstreams.join(' / ')">
                    Upstream：{{
                      row.local_upstreams.length
                        ? row.local_upstreams.join(' / ')
                        : '未设置'
                    }}
                  </p>
                </div>
              </div>
              <p v-else class="text-xs text-slate-400 italic">未落本地站点</p>
            </td>

            <td class="px-4 py-2">
              <div v-if="row.remote_present" class="space-y-1.5">
                <div class="flex flex-wrap items-center gap-1.5">
                  <span class="font-medium text-stone-900">{{
                    row.safeline_site_name || '未命名'
                  }}</span>
                  <span class="font-mono text-[10px] text-slate-400"
                    >ID:{{ row.safeline_site_id }}</span
                  >
                  <StatusBadge
                    :text="remoteStatusText(row.status)"
                    :type="remoteStatusType(row.status)"
                    compact
                  />
                  <StatusBadge
                    :text="
                      row.remote_enabled === null
                        ? '未返回启停'
                        : row.remote_enabled
                          ? '远端启用'
                          : '远端停用'
                    "
                    :type="
                      row.remote_enabled === null
                        ? 'muted'
                        : row.remote_enabled
                          ? 'success'
                          : 'warning'
                    "
                    compact
                  />
                  <StatusBadge
                    :text="row.remote_ssl_enabled ? 'TLS' : '明文'"
                    :type="row.remote_ssl_enabled ? 'info' : 'muted'"
                    compact
                  />
                </div>
                <div class="grid gap-1 text-xs text-slate-500">
                  <p class="truncate" :title="row.safeline_site_domain">
                    域名：{{ row.safeline_site_domain || '未提供' }}
                  </p>
                  <p class="truncate" :title="row.server_names.join(' / ')">
                    Server Names：{{
                      row.server_names.length
                        ? row.server_names.join(' / ')
                        : '未提供'
                    }}
                  </p>
                  <p>
                    HTTP/HTTPS 端口：{{
                      row.remote_ports.length
                        ? row.remote_ports.join(' / ')
                        : '-'
                    }}
                    <span class="text-slate-300"> / </span>
                    {{
                      row.remote_ssl_ports.length
                        ? row.remote_ssl_ports.join(' / ')
                        : '-'
                    }}
                  </p>
                  <p class="truncate" :title="row.remote_upstreams.join(' / ')">
                    Upstream：{{
                      row.remote_upstreams.length
                        ? row.remote_upstreams.join(' / ')
                        : '未提供'
                    }}
                  </p>
                </div>
              </div>
              <div v-else class="space-y-1">
                <p class="text-xs text-slate-400 italic">雷池未见</p>
                <span
                  v-if="row.safeline_site_id"
                  class="font-mono text-[10px] text-slate-400"
                >
                  ID:{{ row.safeline_site_id }}
                </span>
              </div>
            </td>

            <td class="px-4 py-2">
              <div class="space-y-2">
                <div class="flex flex-wrap items-center gap-1.5">
                  <StatusBadge
                    :text="mappingStateText(row)"
                    :type="mappingStateType(row)"
                    compact
                  />
                  <StatusBadge
                    v-if="row.safeline_site_id"
                    :text="row.enabled ? '映射启用' : '映射停用'"
                    :type="row.enabled ? 'success' : 'warning'"
                    compact
                  />
                  <StatusBadge
                    :text="`同步 ${syncModeLabel(row.local_sync_mode)}`"
                    type="info"
                    compact
                  />
                </div>
                <div
                  v-if="row.link_last_error"
                  class="rounded-md border border-red-200 bg-red-50 px-2.5 py-2 text-xs text-red-700"
                >
                  {{ row.link_last_error }}
                </div>
                <div v-else class="text-xs text-slate-500">
                  {{ rowSyncText(row) }}
                </div>
                <p
                  v-if="row.notes || row.local_notes"
                  class="text-xs text-slate-400"
                  :title="row.notes || row.local_notes"
                >
                  备注：{{ row.notes || row.local_notes }}
                </p>
              </div>
            </td>

            <td class="px-4 py-2">
              <div class="flex flex-wrap items-center gap-2">
                <button
                  class="inline-flex h-8 items-center gap-1.5 rounded border border-slate-200 bg-white px-2.5 text-xs text-stone-700 transition hover:border-blue-400 hover:text-blue-700"
                  @click="emit('editLocalSite', row)"
                >
                  <PencilLine :size="14" />
                  <span>{{ row.local_present ? '编辑本地' : '新建本地' }}</span>
                </button>

                <button
                  v-if="row.remote_present"
                  :disabled="rowBusy(row) || !hasSavedConfig"
                  class="inline-flex h-8 items-center gap-1.5 rounded border border-emerald-200 bg-emerald-50 px-2.5 text-xs text-emerald-800 transition hover:border-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
                  @click="emit('syncRemoteSite', row)"
                >
                  <RefreshCw
                    :size="14"
                    :class="{ 'animate-spin': rowActionPending(row, 'pull') }"
                  />
                  <span>{{ remoteActionLabel(row) }}</span>
                </button>

                <button
                  v-if="row.local_present"
                  :disabled="rowBusy(row) || !hasSavedConfig"
                  class="inline-flex h-8 items-center gap-1.5 rounded border border-amber-200 bg-amber-50 px-2.5 text-xs text-amber-900 transition hover:border-amber-400 disabled:cursor-not-allowed disabled:opacity-60"
                  @click="emit('syncLocalSite', row)"
                >
                  <RefreshCw
                    :size="14"
                    :class="{ 'animate-spin': rowActionPending(row, 'push') }"
                  />
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
