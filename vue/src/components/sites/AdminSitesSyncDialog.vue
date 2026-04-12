<script setup lang="ts">
import { computed } from 'vue'
import {
  CheckCircle2,
  CircleHelp,
  RefreshCw,
  ShieldAlert,
  X,
} from 'lucide-vue-next'
import StatusBadge from '../ui/StatusBadge.vue'
import type { RemoteSyncCandidate } from '../../composables/useAdminSites'
import type { SafeLineSitePullOptions } from '../../lib/types'

const props = defineProps<{
  isOpen: boolean
  loading: boolean
  saving: boolean
  candidates: RemoteSyncCandidate[]
  selectedSiteIds: string[]
  sitePullOptions: Record<string, SafeLineSitePullOptions>
}>()

const emit = defineEmits<{
  close: []
  submit: []
  toggleSite: [siteId: string]
  toggleField: [siteId: string, field: keyof SafeLineSitePullOptions]
  selectRecommended: []
  clearSelection: []
  reload: []
}>()

const selectedCount = computed(() => props.selectedSiteIds.length)
const recommendedCount = computed(
  () => props.candidates.filter((item) => item.defaultSelected).length,
)

const fieldOptions: Array<{
  key: keyof SafeLineSitePullOptions
  label: string
  description: string
}> = [
  { key: 'name', label: '名称', description: '站点展示名称' },
  { key: 'primary_hostname', label: '主域名', description: '本地主域名字段' },
  { key: 'hostnames', label: 'Server Names', description: '附加域名列表' },
  { key: 'listen_ports', label: '端口', description: '监听端口列表' },
  { key: 'upstreams', label: 'Upstream', description: '上游地址列表' },
  { key: 'enabled', label: '启用状态', description: '是否启用该站点' },
  { key: 'tls_enabled', label: 'TLS', description: 'TLS 开关状态' },
  { key: 'local_certificate_id', label: '证书', description: '关联远端证书' },
]

function fieldChecked(
  siteId: string,
  field: keyof SafeLineSitePullOptions,
) {
  return props.sitePullOptions[siteId]?.[field] ?? false
}

function fieldDisabled(
  candidate: RemoteSyncCandidate,
  field: keyof SafeLineSitePullOptions,
) {
  return field === 'primary_hostname' && candidate.linkedLocalSiteId === null
}
</script>

<template>
  <div
    v-if="isOpen"
    class="fixed inset-0 z-[110] flex items-center justify-center p-4 md:p-6"
  >
    <div
      class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm"
      @click="emit('close')"
    ></div>

    <div
      class="relative flex max-h-[calc(100vh-2rem)] w-full max-w-[92vw] flex-col rounded-[28px] border border-slate-200 bg-white shadow-[0_24px_80px_rgba(60,40,20,0.24)] md:max-h-[calc(100vh-3rem)]"
    >
      <div class="border-b border-slate-200 px-4 py-4 md:px-6">
        <div class="flex flex-col gap-3">
          <div class="flex items-start justify-between gap-3">
            <div>
              <p class="text-sm font-semibold text-stone-900">从雷池同步站点</p>
            </div>
            <div class="flex flex-wrap items-center gap-2">
              <StatusBadge
                :text="`已选择 ${selectedCount} 项`"
                type="info"
                compact
              />
              <StatusBadge
                :text="`建议导入 ${recommendedCount} 项`"
                type="success"
                compact
              />
              <button
                class="flex h-10 w-10 items-center justify-center rounded-full border border-slate-200 bg-white/75 text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                @click="emit('close')"
              >
                <X :size="18" />
              </button>
            </div>
          </div>

          <div class="flex flex-wrap items-center gap-2">
            <button
              class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
              @click="emit('selectRecommended')"
            >
              <CheckCircle2 :size="14" />
              勾选建议项
            </button>
            <button
              class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
              @click="emit('clearSelection')"
            >
              <ShieldAlert :size="14" />
              清空选择
            </button>
            <button
              :disabled="loading"
              class="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
              @click="emit('reload')"
            >
              <RefreshCw :size="14" :class="{ 'animate-spin': loading }" />
              {{ loading ? '重新读取中...' : '重新读取雷池站点' }}
            </button>
          </div>
        </div>
      </div>

      <div class="flex min-h-0 flex-1 flex-col space-y-4 px-4 py-4 md:px-6 md:py-6">
        <div
          v-if="loading"
          class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-8 text-center text-sm text-slate-500"
        >
          正在读取雷池站点配置...
        </div>

        <div
          v-else-if="candidates.length === 0"
          class="rounded-xl border border-slate-200 bg-slate-50 px-4 py-8 text-center text-sm text-slate-500"
        >
          这次没有读取到可供同步的雷池站点。
        </div>

        <div
          v-else
          class="min-h-0 flex-1 overflow-auto rounded-xl border border-slate-200 bg-white"
        >
          <table class="min-w-[1180px] w-full table-auto border-collapse">
            <thead class="bg-slate-50">
              <tr class="text-left text-xs font-medium text-slate-500">
                <th class="w-[5%] px-3 py-2 text-center">选</th>
                <th class="px-3 py-2">域名</th>
                <th class="px-2 py-2 whitespace-nowrap">端口</th>
                <th class="px-3 py-2">下游地址</th>
                <th class="px-3 py-2 whitespace-nowrap">
                  <span class="inline-flex items-center gap-2">
                    <CircleHelp :size="14" class="text-slate-400" />
                    导入字段
                  </span>
                </th>
              </tr>
            </thead>

            <tbody>
              <tr
                v-for="candidate in candidates"
                :key="candidate.id"
                class="border-t border-slate-200 align-top text-sm hover:bg-slate-50/40"
              >
                <td class="px-3 py-2 text-center">
                  <input
                    :checked="selectedSiteIds.includes(candidate.id)"
                    class="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                    type="checkbox"
                    @change="emit('toggleSite', candidate.id)"
                  />
                </td>

                <td class="py-2 pl-3 pr-1 text-xs text-slate-600">
                  <p class="truncate" :title="candidate.domain">
                    {{ candidate.domain || '未提供' }}
                  </p>
                  <p class="truncate text-[11px] text-slate-400" :title="candidate.name">
                    {{ candidate.name }}
                  </p>
                  <p
                    v-if="candidate.localMatchLabel"
                    class="truncate text-[11px] text-slate-400"
                  >
                    匹配到：{{ candidate.localMatchLabel }}
                  </p>
                </td>

                <td class="px-2 py-2 text-xs text-slate-600 whitespace-nowrap">
                  <div class="space-y-0.5">
                    <p>{{ candidate.ports.length ? candidate.ports.join(' / ') : '-' }}</p>
                    <p class="text-slate-400">
                      TLS:
                      {{
                        candidate.sslPorts.length
                          ? candidate.sslPorts.join(' / ')
                          : '-'
                      }}
                    </p>
                  </div>
                </td>

                <td class="px-2 py-2 text-xs text-slate-600">
                  <p class="truncate" :title="candidate.upstreams.join(' / ')">
                    {{
                      candidate.upstreams.length
                        ? candidate.upstreams.join(' / ')
                        : '未提供'
                    }}
                  </p>
                </td>

                <td class="px-3 py-2">
                  <div class="flex flex-nowrap gap-1.5 whitespace-nowrap">
                    <button
                      v-for="field in fieldOptions"
                      :key="field.key"
                      type="button"
                      :disabled="fieldDisabled(candidate, field.key)"
                      class="inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs transition disabled:cursor-not-allowed disabled:opacity-60"
                      :class="
                        fieldChecked(candidate.id, field.key)
                          ? 'border-blue-300 bg-blue-50 text-blue-900'
                          : 'border-slate-200 bg-white text-slate-500'
                      "
                      @click.stop.prevent="emit('toggleField', candidate.id, field.key)"
                    >
                      <input
                        :checked="fieldChecked(candidate.id, field.key)"
                        :disabled="fieldDisabled(candidate, field.key)"
                        class="h-3.5 w-3.5 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                        type="checkbox"
                        tabindex="-1"
                      />
                      <span>
                        {{ field.label }}
                        {{
                          fieldDisabled(candidate, field.key)
                            ? '（必选）'
                            : ''
                        }}
                      </span>
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <div
        class="flex flex-col gap-3 border-t border-slate-200 px-4 py-4 md:flex-row md:items-center md:justify-between md:px-6"
      >
        <p class="text-sm text-slate-500">
          确认后会按选择结果逐条导入本地站点，存在疑似重复的项也会按你的选择继续处理。
        </p>
        <div class="flex flex-wrap gap-2">
          <button
            class="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
            @click="emit('close')"
          >
            取消
          </button>
          <button
            :disabled="saving || selectedCount === 0"
            class="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3 py-2 text-sm font-medium text-white shadow-sm transition hover:bg-blue-600/90 disabled:cursor-not-allowed disabled:opacity-60"
            @click="emit('submit')"
          >
            <RefreshCw :size="14" :class="{ 'animate-spin': saving }" />
            {{ saving ? '同步中...' : `同步已选 ${selectedCount} 项` }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
