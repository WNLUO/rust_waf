<script setup lang="ts">
import AppLayout from '@/app/layout/AppLayout.vue'
import { RefreshCw, X } from 'lucide-vue-next'
import { useAdminBlockedPage } from '@/features/blocked/composables/useAdminBlockedPage'

const {
  formatTimestamp,
  timeRemaining,
  loading,
  refreshing,
  pulling,
  pushing,
  mutatingId,
  creatingBlockedIp,
  batchUnblocking,
  cleaningExpired,
  showBlockDialog,
  currentPage,
  pendingRealtimeCount,
  selectedIds,
  loadingSyncState,
  realtimeState,
  blockedPayload,
  blockedFilters,
  blockForm,
  totalPages,
  pageStart,
  pageEnd,
  isAllSelected,
  canUnblock,
  isSelected,
  onSelectAllChange,
  onSelectOneChange,
  relatedEventsQuery,
  syncStateItems,
  blockExpiresAtPreview,
  loadBlockedIps,
  openBlockDialog,
  closeBlockDialog,
  handleCreateBlockedIp,
  runSafeLinePull,
  runSafeLinePush,
  handleBatchUnblock,
  handleCleanupExpired,
  handleUnblock,
  goToPage,
} = useAdminBlockedPage()
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
          @click="loadBlockedIps()"
        >
          有 {{ pendingRealtimeCount }} 条新封禁
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-60"
          :disabled="pulling"
          @click="runSafeLinePull"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': pulling }" />
          {{ pulling ? '拉取中' : '拉取雷池' }}
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-60"
          :disabled="pushing"
          @click="runSafeLinePush"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': pushing }" />
          {{ pushing ? '推送中' : '推送本地' }}
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-60"
          :disabled="refreshing"
          @click="loadBlockedIps()"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
          刷新
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-md border border-blue-300 bg-blue-50 px-3 py-1.5 text-xs text-blue-700 hover:bg-blue-100 disabled:opacity-60"
          @click="openBlockDialog"
        >
          手动封禁
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-md border border-amber-300 bg-amber-50 px-3 py-1.5 text-xs text-amber-700 hover:bg-amber-100 disabled:opacity-60"
          :disabled="cleaningExpired"
          @click="handleCleanupExpired"
        >
          {{ cleaningExpired ? '清理中' : '清理过期' }}
        </button>
        <button
          class="inline-flex items-center gap-2 rounded-md border border-rose-300 bg-rose-50 px-3 py-1.5 text-xs text-rose-700 hover:bg-rose-100 disabled:opacity-60"
          :disabled="batchUnblocking || !selectedIds.length"
          @click="handleBatchUnblock"
        >
          {{
            batchUnblocking
              ? '批量处理中'
              : selectedIds.length
                ? `批量解封(${selectedIds.length})`
                : '批量解封'
          }}
        </button>
      </div>
    </template>

    <div class="space-y-3">
      <div class="grid gap-2 md:grid-cols-3">
        <div
          v-for="item in syncStateItems"
          :key="item.key"
          class="rounded-md border border-slate-200 bg-white px-3 py-2"
        >
          <div class="text-xs text-slate-500">{{ item.label }}</div>
          <div class="mt-1 text-sm text-slate-800">
            {{
              item.state?.last_success_at
                ? `上次成功：${formatTimestamp(item.state.last_success_at)}`
                : loadingSyncState
                  ? '读取中...'
                  : '暂无成功记录'
            }}
          </div>
          <div class="mt-1 text-xs text-slate-600">
            导入/跳过：{{ item.state?.last_imported_count ?? 0 }} /
            {{ item.state?.last_skipped_count ?? 0 }}
          </div>
        </div>
      </div>

      <div class="grid gap-2 md:grid-cols-3 xl:grid-cols-6">
        <select
          v-model="blockedFilters.source_scope"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
        >
          <option value="all">全部范围</option>
          <option value="local">仅本地</option>
          <option value="remote">仅远端</option>
        </select>
        <select
          v-model="blockedFilters.provider"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
        >
          <option value="all">全部来源</option>
          <option value="safeline">雷池</option>
        </select>
        <input
          v-model="blockedFilters.ip"
          type="text"
          placeholder="IP"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
        />
        <input
          v-model="blockedFilters.keyword"
          type="text"
          placeholder="关键词"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
        />
        <select
          v-model="blockedFilters.sort_by"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
        >
          <option value="blocked_at">按封禁时间</option>
          <option value="expires_at">按到期时间</option>
          <option value="ip">按 IP</option>
        </select>
        <select
          v-model="blockedFilters.sort_direction"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
        >
          <option value="desc">降序</option>
          <option value="asc">升序</option>
        </select>
      </div>

      <div class="grid gap-2 md:grid-cols-4 xl:grid-cols-6">
        <label
          class="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700"
        >
          <input
            v-model="blockedFilters.active_only"
            type="checkbox"
            class="accent-blue-600"
          />
          仅有效
        </label>
        <input
          v-model="blockedFilters.blocked_from"
          type="datetime-local"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
        />
        <input
          v-model="blockedFilters.blocked_to"
          type="datetime-local"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
        />
      </div>

      <div v-if="loading" class="text-sm text-slate-500">加载中...</div>

      <div
        v-else
        class="overflow-hidden rounded-md border border-slate-200 bg-white"
      >
        <div class="overflow-x-auto">
          <table class="w-full min-w-[980px] border-collapse text-left text-sm">
            <thead class="bg-slate-50 text-slate-600">
              <tr>
                <th class="px-3 py-2 font-medium">
                  <input
                    type="checkbox"
                    class="accent-blue-600"
                    :checked="isAllSelected"
                    @change="onSelectAllChange"
                  />
                </th>
                <th class="px-3 py-2 font-medium">IP</th>
                <th class="px-3 py-2 font-medium">来源</th>
                <th class="px-3 py-2 font-medium">原因</th>
                <th class="px-3 py-2 font-medium">封禁时间</th>
                <th class="px-3 py-2 font-medium">到期</th>
                <th class="px-3 py-2 font-medium">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="ip in blockedPayload.blocked_ips"
                :key="ip.id"
                class="border-t border-slate-200 align-top text-slate-800"
              >
                <td class="px-3 py-2">
                  <input
                    type="checkbox"
                    class="accent-blue-600"
                    :disabled="!canUnblock(ip)"
                    :checked="isSelected(ip.id)"
                    @change="onSelectOneChange(ip.id, $event)"
                  />
                </td>
                <td class="px-3 py-2 font-mono text-xs text-slate-900">
                  {{ ip.ip }}
                </td>
                <td class="px-3 py-2">
                  <div class="space-y-1 text-xs">
                    <div class="text-slate-900">
                      {{ ip.provider || 'local' }}
                    </div>
                    <div v-if="ip.provider_remote_id" class="text-slate-500">
                      ID: {{ ip.provider_remote_id }}
                    </div>
                  </div>
                </td>
                <td class="px-3 py-2 text-sm text-slate-900">
                  <div class="max-w-[420px] break-all">{{ ip.reason }}</div>
                </td>
                <td class="px-3 py-2 text-xs text-slate-600">
                  {{ formatTimestamp(ip.blocked_at) }}
                </td>
                <td class="px-3 py-2 text-xs text-slate-600">
                  <div>{{ formatTimestamp(ip.expires_at) }}</div>
                  <div>{{ timeRemaining(ip.expires_at) }}</div>
                </td>
                <td class="px-3 py-2">
                  <div class="flex flex-wrap items-center gap-2">
                    <button
                      v-if="canUnblock(ip)"
                      class="rounded-md border border-slate-300 bg-white px-2 py-1 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-60"
                      :disabled="mutatingId === ip.id"
                      @click="handleUnblock(ip.id)"
                    >
                      {{
                        mutatingId === ip.id
                          ? '处理中'
                          : ip.provider === 'safeline'
                            ? '雷池解封'
                            : '解除封禁'
                      }}
                    </button>
                    <span v-else class="text-xs text-slate-500">不可操作</span>
                    <RouterLink
                      class="rounded-md border border-slate-300 bg-white px-2 py-1 text-xs text-slate-700 hover:bg-slate-50"
                      :to="{
                        name: 'admin-events',
                        query: relatedEventsQuery(ip),
                      }"
                    >
                      相关事件
                    </RouterLink>
                  </div>
                </td>
              </tr>
              <tr v-if="!blockedPayload.blocked_ips.length">
                <td
                  colspan="7"
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
          <div>{{ pageStart }}-{{ pageEnd }} / {{ blockedPayload.total }}</div>
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
      v-if="showBlockDialog"
      class="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/30 px-4"
    >
      <div class="absolute inset-0" @click="closeBlockDialog"></div>
      <div
        class="relative z-[101] w-full max-w-xl rounded-md border border-slate-300 bg-white"
      >
        <div
          class="flex items-center justify-between border-b border-slate-200 px-4 py-3"
        >
          <div>
            <div class="text-sm font-medium text-slate-900">手动封禁 IP</div>
            <div class="text-xs text-slate-500">
              只需填 IP，其他优先用预设即可
            </div>
          </div>
          <button
            class="inline-flex h-8 w-8 items-center justify-center rounded-md border border-slate-300 bg-white text-slate-600 hover:bg-slate-50"
            :disabled="creatingBlockedIp"
            @click="closeBlockDialog"
          >
            <X :size="16" />
          </button>
        </div>
        <div class="space-y-3 px-4 py-3">
          <div class="space-y-1">
            <label class="text-xs text-slate-600">IP 地址</label>
            <input
              v-model="blockForm.ip"
              type="text"
              placeholder="例如 1.2.3.4 或 2001:db8::1"
              class="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
            />
          </div>

          <div class="grid gap-3 md:grid-cols-2">
            <div class="space-y-1">
              <label class="text-xs text-slate-600">封禁时长</label>
              <select
                v-model="blockForm.duration_preset"
                class="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
              >
                <option value="15m">15 分钟</option>
                <option value="1h">1 小时（推荐）</option>
                <option value="6h">6 小时</option>
                <option value="24h">24 小时</option>
                <option value="7d">7 天</option>
                <option value="custom">自定义</option>
              </select>
            </div>
            <div
              v-if="blockForm.duration_preset === 'custom'"
              class="space-y-1"
            >
              <label class="text-xs text-slate-600">自定义时长（分钟）</label>
              <input
                v-model.number="blockForm.duration_custom_minutes"
                type="number"
                min="1"
                step="1"
                class="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
              />
            </div>
          </div>

          <div class="space-y-1">
            <label class="text-xs text-slate-600">封禁原因</label>
            <select
              v-model="blockForm.reason_preset"
              class="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
            >
              <option value="manual">人工处置（推荐）</option>
              <option value="scanner">可疑扫描行为</option>
              <option value="flood">高频请求/连接洪泛</option>
              <option value="payload">恶意请求载荷</option>
              <option value="custom">自定义</option>
            </select>
          </div>
          <div v-if="blockForm.reason_preset === 'custom'" class="space-y-1">
            <label class="text-xs text-slate-600">自定义原因</label>
            <input
              v-model="blockForm.reason_custom"
              type="text"
              placeholder="请输入备注，例如：运维人工封禁"
              class="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800"
            />
          </div>

          <div
            class="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600"
          >
            预计解封时间：{{ formatTimestamp(blockExpiresAtPreview) }}
          </div>
        </div>
        <div
          class="flex items-center justify-end gap-2 border-t border-slate-200 px-4 py-3"
        >
          <button
            class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-60"
            :disabled="creatingBlockedIp"
            @click="closeBlockDialog"
          >
            取消
          </button>
          <button
            class="rounded-md border border-blue-300 bg-blue-50 px-3 py-2 text-sm text-blue-700 hover:bg-blue-100 disabled:opacity-60"
            :disabled="creatingBlockedIp"
            @click="handleCreateBlockedIp"
          >
            {{ creatingBlockedIp ? '封禁中...' : '确认封禁' }}
          </button>
        </div>
      </div>
    </div>
  </AppLayout>
</template>
