<script setup lang="ts">
import AppLayout from '@/app/layout/AppLayout.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import { Eye, RefreshCw, X } from 'lucide-vue-next'
import { useAdminEventsPage } from '@/features/events/composables/useAdminEventsPage'

const {
  formatTimestamp,
  layerLabel,
  loading,
  refreshing,
  syncing,
  currentPage,
  previewTitle,
  previewContent,
  pendingRealtimeCount,
  realtimeState,
  eventsPayload,
  eventsFilters,
  showAdvancedFiltersDialog,
  advancedFiltersDraft,
  openAdvancedFilters,
  closeAdvancedFilters,
  resetAdvancedFilters,
  applyAdvancedFilters,
  totalPages,
  pageStart,
  pageEnd,
  loadEvents,
  runSafeLineSync,
  openPreview,
  closePreview,
  eventActionLabel,
  eventActionBadgeType,
  shouldShowActionBadge,
  eventAttackTypeLabel,
  eventReasonLabel,
  eventReasonPreview,
  isReasonTruncated,
  eventPathText,
  eventPathPreview,
  isPathTruncated,
  eventIdentityStateLabel,
  eventPrimarySignalLabel,
  eventLabelsPreview,
  isStorageSummaryEvent,
  storageSummaryScopeLabel,
  storageSummaryCountLabel,
  storageSummaryWindowLabel,
  storageSummaryRouteLabel,
  openStorageSummaryPreview,
  hasClientIdentityDebug,
  hasUpstreamHttp2Debug,
  openClientIdentityDebug,
  openUpstreamHttp2Debug,
  siteOptions,
  goToPage,
} = useAdminEventsPage()
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <div class="flex flex-wrap items-center gap-2">
        <span class="text-xs text-slate-500">
          {{
            realtimeState.connected
              ? '实时通道已连接'
              : realtimeState.connecting
                ? '实时通道连接中'
                : '实时通道未连接'
          }}
        </span>
        <button
          v-if="pendingRealtimeCount > 0"
          class="inline-flex items-center gap-2 rounded-md border border-emerald-300 bg-emerald-50 px-3 py-1.5 text-xs text-emerald-700 hover:bg-emerald-100"
          @click="loadEvents()"
        >
          有 {{ pendingRealtimeCount }} 条新事件
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-60"
          :disabled="syncing"
          @click="runSafeLineSync"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': syncing }" />
          {{ syncing ? '同步中' : '同步雷池' }}
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-60"
          :disabled="refreshing"
          @click="loadEvents()"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
          刷新
        </button>
      </div>
    </template>

    <div class="space-y-3">
      <div class="flex flex-wrap items-center gap-2 xl:flex-nowrap">
        <select
          v-model="eventsFilters.layer"
          class="w-full min-w-[140px] rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 xl:w-auto"
        >
          <option value="all">全部层级</option>
          <option value="l4">四层</option>
          <option value="l7">HTTP</option>
          <option value="safeline">雷池</option>
        </select>
        <select
          v-model="eventsFilters.action"
          class="w-full min-w-[140px] rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 xl:w-auto"
        >
          <option value="all">全部动作</option>
          <option value="block">拦截</option>
          <option value="allow">放行</option>
          <option value="alert">告警</option>
          <option value="log">记录</option>
        </select>
        <select
          v-model="eventsFilters.identity_state"
          class="w-full min-w-[160px] rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 xl:w-auto"
        >
          <option value="all">全部身份态</option>
          <option value="trusted_cdn_forwarded">可信 CDN</option>
          <option value="trusted_cdn_unresolved">CDN 未解析</option>
          <option value="direct_client">直连客户端</option>
          <option value="spoofed_forward_header">伪造头部</option>
        </select>
        <input
          v-model="eventsFilters.primary_signal"
          type="text"
          placeholder="主信号，如 slow_attack / l7_cc:block"
          class="w-full min-w-[210px] rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 xl:w-[260px]"
        />
        <select
          v-model="eventsFilters.handled"
          class="w-full min-w-[140px] rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 xl:w-auto"
        >
          <option value="all">全部状态</option>
          <option value="unhandled">未处理</option>
          <option value="handled">已处理</option>
        </select>
        <input
          v-model="eventsFilters.source_ip"
          type="text"
          placeholder="源 IP"
          class="w-full min-w-[180px] rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 xl:w-[220px]"
        />
        <button
          class="inline-flex items-center justify-center rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700 hover:bg-slate-50"
          @click="openAdvancedFilters"
        >
          高级筛选
        </button>
      </div>

      <div v-if="loading" class="text-sm text-slate-500">加载中...</div>

      <div
        v-else
        class="overflow-hidden rounded-md border border-slate-200 bg-white"
      >
        <div class="overflow-x-auto">
          <table
            class="min-w-max w-full border-collapse text-sm whitespace-nowrap"
          >
            <thead class="bg-slate-50 text-slate-600">
              <tr>
                <th class="px-3 py-2 text-center font-medium">时间</th>
                <th class="px-3 py-2 text-center font-medium">层级/动作</th>
                <th class="px-3 py-2 text-center font-medium">来源</th>
                <th class="px-3 py-2 text-center font-medium">目标/请求</th>
                <th class="px-3 py-2 text-center font-medium">原因</th>
                <th class="px-3 py-2 text-center font-medium">路径</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="event in eventsPayload.events"
                :key="event.id"
                class="border-t border-slate-200 align-middle text-slate-800"
                :class="{
                  'bg-amber-50/40': isStorageSummaryEvent(event),
                }"
              >
                <td class="px-3 py-2">
                  <div class="space-y-1 text-center">
                    <div class="font-mono text-xs text-slate-900">
                      {{ formatTimestamp(event.created_at) }}
                    </div>
                  </div>
                </td>
                <td class="px-3 py-2">
                  <div class="flex flex-nowrap justify-center gap-1">
                    <StatusBadge
                      :text="layerLabel(event.layer)"
                      :type="
                        event.layer.toLowerCase() === 'l7' ? 'info' : 'warning'
                      "
                      compact
                    />
                    <StatusBadge
                      v-if="isStorageSummaryEvent(event)"
                      :text="storageSummaryScopeLabel(event)"
                      type="warning"
                      compact
                    />
                    <StatusBadge
                      v-if="shouldShowActionBadge(event.action)"
                      :text="eventActionLabel(event.action)"
                      :type="eventActionBadgeType(event.action)"
                      compact
                    />
                    <StatusBadge
                      v-if="eventAttackTypeLabel(event)"
                      :text="eventAttackTypeLabel(event)"
                      type="muted"
                      compact
                    />
                  </div>
                </td>
                <td class="px-3 py-2">
                  <div class="space-y-1 text-center">
                    <div class="font-mono text-xs text-slate-900">
                      {{ event.source_ip }}
                    </div>
                    <div
                      v-if="isStorageSummaryEvent(event)"
                      class="text-[11px] text-amber-700"
                    >
                      {{ storageSummaryCountLabel(event) }}
                    </div>
                    <div
                      v-if="eventIdentityStateLabel(event)"
                      class="text-[11px] text-slate-500"
                    >
                      {{ eventIdentityStateLabel(event) }}
                    </div>
                  </div>
                </td>
                <td class="px-3 py-2">
                  <div class="space-y-1 text-center">
                    <div class="font-mono text-xs text-slate-600">
                      <template v-if="isStorageSummaryEvent(event)">
                        {{ storageSummaryWindowLabel(event) || event.protocol }}
                      </template>
                      <template v-else>
                        {{ event.protocol }}
                        <span v-if="event.http_version">
                          / {{ event.http_version }}</span
                        >
                      </template>
                    </div>
                    <div
                      v-if="eventPrimarySignalLabel(event)"
                      class="text-[11px] text-slate-500"
                    >
                      {{ eventPrimarySignalLabel(event) }}
                    </div>
                  </div>
                </td>
                <td class="px-3 py-2">
                  <div class="space-y-2">
                    <div class="flex items-center justify-center gap-2">
                      <div class="min-w-0">
                        <div
                          class="event-reason-text text-sm text-slate-900"
                          :title="eventReasonLabel(event)"
                        >
                          {{ eventReasonPreview(event) }}
                        </div>
                      </div>
                      <button
                        v-if="isStorageSummaryEvent(event)"
                        class="inline-flex h-7 items-center justify-center whitespace-nowrap rounded-md border border-amber-200 bg-amber-50 px-2 text-xs text-amber-700 hover:bg-amber-100"
                        title="查看攻击摘要"
                        @click="openStorageSummaryPreview(event)"
                      >
                        摘要
                      </button>
                      <button
                        v-if="isReasonTruncated(event)"
                        class="inline-flex h-7 items-center justify-center whitespace-nowrap rounded-md border border-slate-300 bg-white px-2 text-xs text-slate-600 hover:bg-slate-50"
                        title="查看完整原因"
                        @click="
                          openPreview('完整原因', eventReasonLabel(event))
                        "
                      >
                        更多
                      </button>
                      <button
                        v-if="event.details_json"
                        class="inline-flex h-7 w-7 items-center justify-center rounded-md border border-slate-300 bg-white text-slate-600 hover:bg-slate-50"
                        title="查看详情"
                        @click="openPreview('事件详情', event.details_json)"
                      >
                        <Eye :size="14" />
                      </button>
                      <button
                        v-if="hasClientIdentityDebug(event)"
                        class="inline-flex h-7 items-center justify-center whitespace-nowrap rounded-md border border-blue-200 bg-blue-50 px-2 text-xs text-blue-700 hover:bg-blue-100"
                        title="查看客户端身份调试"
                        @click="openClientIdentityDebug(event)"
                      >
                        身份调试
                      </button>
                      <button
                        v-if="hasUpstreamHttp2Debug(event)"
                        class="inline-flex h-7 items-center justify-center whitespace-nowrap rounded-md border border-emerald-200 bg-emerald-50 px-2 text-xs text-emerald-700 hover:bg-emerald-100"
                        title="查看上游 HTTP/2 调试"
                        @click="openUpstreamHttp2Debug(event)"
                      >
                        上游调试
                      </button>
                    </div>
                    <div
                      v-if="eventLabelsPreview(event).length"
                      class="flex flex-wrap justify-center gap-1"
                    >
                      <StatusBadge
                        v-for="label in eventLabelsPreview(event)"
                        :key="label"
                        :text="label"
                        type="muted"
                        compact
                      />
                    </div>
                  </div>
                </td>
                <td class="px-3 py-2">
                  <div class="flex items-center justify-center gap-2">
                    <div
                      class="event-path-text font-mono text-xs text-slate-700"
                      :title="
                        isStorageSummaryEvent(event)
                          ? storageSummaryRouteLabel(event) ||
                            eventPathText(event)
                          : eventPathText(event)
                      "
                    >
                      {{
                        isStorageSummaryEvent(event)
                          ? storageSummaryRouteLabel(event) ||
                            eventPathPreview(event)
                          : eventPathPreview(event)
                      }}
                    </div>
                    <button
                      v-if="
                        !isStorageSummaryEvent(event) && isPathTruncated(event)
                      "
                      class="inline-flex h-7 items-center justify-center whitespace-nowrap rounded-md border border-slate-300 bg-white px-2 text-xs text-slate-600 hover:bg-slate-50"
                      title="查看完整路径"
                      @click="openPreview('完整路径', eventPathText(event))"
                    >
                      更多
                    </button>
                  </div>
                </td>
              </tr>
              <tr v-if="!eventsPayload.events.length">
                <td
                  colspan="6"
                  class="px-3 py-6 text-center text-sm text-slate-500"
                >
                  无数据
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div
          class="flex flex-wrap items-center justify-between gap-2 border-t border-slate-200 px-3 py-2 text-xs text-slate-600"
        >
          <div>{{ pageStart }}-{{ pageEnd }} / {{ eventsPayload.total }}</div>
          <div class="flex items-center gap-2">
            <button
              class="rounded-md border border-slate-300 bg-white px-2 py-1 hover:bg-slate-50 disabled:opacity-50"
              :disabled="currentPage <= 1"
              @click="goToPage(currentPage - 1)"
            >
              上一页
            </button>
            <span>{{ currentPage }} / {{ totalPages }}</span>
            <button
              class="rounded-md border border-slate-300 bg-white px-2 py-1 hover:bg-slate-50 disabled:opacity-50"
              :disabled="currentPage >= totalPages"
              @click="goToPage(currentPage + 1)"
            >
              下一页
            </button>
          </div>
        </div>
      </div>
    </div>

    <div
      v-if="showAdvancedFiltersDialog"
      class="fixed inset-0 z-[95] flex items-center justify-center bg-slate-950/30 px-4"
    >
      <div class="absolute inset-0" @click="closeAdvancedFilters"></div>
      <div
        class="relative z-[96] w-full max-w-2xl rounded-md border border-slate-300 bg-white"
      >
        <div
          class="flex items-center justify-between border-b border-slate-200 px-4 py-3"
        >
          <div class="text-sm font-medium text-slate-900">高级筛选</div>
          <button
            class="inline-flex h-8 w-8 items-center justify-center rounded-md border border-slate-300 bg-white text-slate-600 hover:bg-slate-50"
            @click="closeAdvancedFilters"
          >
            <X :size="16" />
          </button>
        </div>
        <div class="grid gap-3 p-4 md:grid-cols-2">
          <select
            v-model="advancedFiltersDraft.provider"
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
          >
            <option value="all">全部来源</option>
            <option value="browser_fingerprint">浏览器指纹</option>
            <option value="safeline">雷池</option>
          </select>
          <select
            v-model="advancedFiltersDraft.provider_site_id"
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
          >
            <option value="all">全部雷池站点</option>
            <option v-for="site in siteOptions" :key="site.id" :value="site.id">
              {{ site.label }}
            </option>
          </select>
          <select
            v-model="advancedFiltersDraft.identity_state"
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
          >
            <option value="all">全部身份态</option>
            <option value="trusted_cdn_forwarded">可信 CDN</option>
            <option value="trusted_cdn_unresolved">CDN 未解析</option>
            <option value="direct_client">直连客户端</option>
            <option value="spoofed_forward_header">伪造头部</option>
          </select>
          <input
            v-model="advancedFiltersDraft.primary_signal"
            type="text"
            placeholder="主信号，如 slow_attack / l7_cc:block"
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
          />
          <input
            v-model="advancedFiltersDraft.labels"
            type="text"
            placeholder="标签，逗号分隔，如 identity:trusted_cdn_forwarded"
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 md:col-span-2"
          />
          <label
            class="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700"
          >
            <input
              v-model="advancedFiltersDraft.blocked_only"
              type="checkbox"
              class="accent-blue-600"
            />
            仅拦截
          </label>
          <select
            v-model="advancedFiltersDraft.sort_by"
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
          >
            <option value="created_at">按时间</option>
            <option value="source_ip">按来源 IP</option>
            <option value="dest_port">按目标端口</option>
          </select>
          <input
            v-model="advancedFiltersDraft.created_from"
            type="datetime-local"
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
          />
          <input
            v-model="advancedFiltersDraft.created_to"
            type="datetime-local"
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
          />
          <select
            v-model="advancedFiltersDraft.sort_direction"
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 md:col-span-2"
          >
            <option value="desc">降序</option>
            <option value="asc">升序</option>
          </select>
        </div>
        <div
          class="flex items-center justify-end gap-2 border-t border-slate-200 px-4 py-3"
        >
          <button
            class="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
            @click="resetAdvancedFilters"
          >
            重置
          </button>
          <button
            class="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
            @click="closeAdvancedFilters"
          >
            取消
          </button>
          <button
            class="rounded-md border border-blue-600 bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-700"
            @click="applyAdvancedFilters"
          >
            应用筛选
          </button>
        </div>
      </div>
    </div>

    <div
      v-if="previewContent"
      class="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/30 px-4"
    >
      <div class="absolute inset-0" @click="closePreview"></div>
      <div
        class="relative z-[101] w-full max-w-5xl rounded-md border border-slate-300 bg-white"
      >
        <div
          class="flex items-center justify-between border-b border-slate-200 px-4 py-3"
        >
          <div class="text-sm font-medium text-slate-900">
            {{ previewTitle }}
          </div>
          <button
            class="inline-flex h-8 w-8 items-center justify-center rounded-md border border-slate-300 bg-white text-slate-600 hover:bg-slate-50"
            @click="closePreview"
          >
            <X :size="16" />
          </button>
        </div>
        <pre
          class="max-h-[70vh] overflow-auto whitespace-pre-wrap break-all px-4 py-3 text-xs text-slate-800"
          >{{ previewContent }}</pre
        >
      </div>
    </div>
  </AppLayout>
</template>

<style scoped>
.event-reason-text {
  max-width: 18rem;
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
}

.event-path-text {
  max-width: 22rem;
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
}
</style>
