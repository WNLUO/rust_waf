<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { fetchSecurityEvents, syncSafeLineEvents } from '../lib/api'
import type { SecurityEventItem, SecurityEventsResponse } from '../lib/types'
import AppLayout from '../components/layout/AppLayout.vue'
import StatusBadge from '../components/ui/StatusBadge.vue'
import { useFormatters } from '../composables/useFormatters'
import { Copy, Eye, RefreshCw, X } from 'lucide-vue-next'

const { formatTimestamp, actionLabel, layerLabel } = useFormatters()
const loading = ref(true)
const refreshing = ref(false)
const syncing = ref(false)
const error = ref('')
const successMessage = ref('')
const filtersReady = ref(false)
const previewTitle = ref('')
const previewContent = ref('')
const eventsPayload = ref<SecurityEventsResponse>({
  total: 0,
  limit: 0,
  offset: 0,
  events: [],
})

const eventsFilters = reactive({
  layer: 'all',
  provider: 'all',
  provider_site_id: 'all',
  action: 'all',
  blocked_only: false,
  handled: 'all' as 'all' | 'handled' | 'unhandled',
  sort_by: 'created_at',
  sort_direction: 'desc' as 'asc' | 'desc',
})

const loadEvents = async (showLoader = false) => {
  if (showLoader) loading.value = true
  refreshing.value = true
  try {
    eventsPayload.value = await fetchSecurityEvents({
      limit: 30,
      sort_by: eventsFilters.sort_by,
      sort_direction: eventsFilters.sort_direction,
      blocked_only: eventsFilters.blocked_only,
      layer: eventsFilters.layer === 'all' ? undefined : eventsFilters.layer,
      provider:
        eventsFilters.provider === 'all' ? undefined : eventsFilters.provider,
      provider_site_id:
        eventsFilters.provider_site_id === 'all'
          ? undefined
          : eventsFilters.provider_site_id,
      action: eventsFilters.action === 'all' ? undefined : eventsFilters.action,
      handled_only:
        eventsFilters.handled === 'all'
          ? undefined
          : eventsFilters.handled === 'handled'
            ? true
            : false,
    })
    error.value = ''
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取事件失败'
  } finally {
    if (showLoader) loading.value = false
    refreshing.value = false
  }
}

const runSafeLineSync = async () => {
  syncing.value = true
  error.value = ''
  successMessage.value = ''

  try {
    const response = await syncSafeLineEvents()
    successMessage.value = response.message
    await loadEvents()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '同步雷池事件失败'
  } finally {
    syncing.value = false
  }
}

const copyToClipboard = async (text: string) => {
  try {
    await navigator.clipboard?.writeText(text)
  } catch {
    // ignore clipboard failure
  }
}

const openPreview = (title: string, content: string | null | undefined) => {
  if (!content) return
  previewTitle.value = title
  previewContent.value = content
}

const closePreview = () => {
  previewTitle.value = ''
  previewContent.value = ''
}

const safeLineActionMap: Record<string, string> = {
  '0': '检测',
  '1': '拦截',
}

const safeLineAttackTypeMap: Record<string, string> = {
  '7': '漏洞利用',
  '8': '代码注入',
  '10': '文件上传',
}

const getSafeLineAttackTypeCode = (event: SecurityEventItem) => {
  if (event.layer !== 'safeline') return null
  const matched = event.reason.match(/^safeline:([^:]+):/)
  return matched?.[1] ?? null
}

const eventActionLabel = (action: string) => {
  const normalized = action.trim().toLowerCase()
  if (normalized in safeLineActionMap) {
    return safeLineActionMap[normalized]
  }
  if (['block', 'allow', 'alert', 'log'].includes(normalized)) {
    return actionLabel(normalized)
  }
  return `未知动作(${action})`
}

const eventActionBadgeType = (action: string) => {
  const normalized = action.trim().toLowerCase()
  if (normalized === '1' || normalized === 'block') return 'error'
  if (normalized === 'allow') return 'success'
  if (normalized === '0' || normalized === 'alert' || normalized === 'log')
    return 'warning'
  return 'warning'
}

const eventAttackTypeLabel = (event: SecurityEventItem) => {
  const code = getSafeLineAttackTypeCode(event)
  if (!code) return ''
  return safeLineAttackTypeMap[code] || `未知类型(${code})`
}

const eventReasonLabel = (event: SecurityEventItem) => {
  if (event.layer !== 'safeline') return event.reason

  const attackTypeCode = getSafeLineAttackTypeCode(event)
  const attackTypeLabel = attackTypeCode
    ? safeLineAttackTypeMap[attackTypeCode]
    : ''
  const normalized = event.reason.replace(/^safeline:[^:]+:/, '').trim()

  if (attackTypeCode && normalized === `检测到 ${attackTypeCode} 攻击`) {
    return attackTypeLabel || normalized
  }

  return normalized || event.reason
}

onMounted(async () => {
  await loadEvents(true)
  filtersReady.value = true
})

watch(
  () => ({ ...eventsFilters }),
  () => {
    if (!filtersReady.value) return
    loadEvents()
  },
  { deep: true },
)

const siteOptions = computed(() => {
  const seen = new Map<string, string>()
  for (const event of eventsPayload.value.events) {
    if (!event.provider_site_id) continue
    seen.set(
      event.provider_site_id,
      event.provider_site_name ||
        event.provider_site_domain ||
        event.provider_site_id,
    )
  }
  return Array.from(seen.entries()).map(([id, label]) => ({ id, label }))
})
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        @click="runSafeLineSync"
        class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
        :disabled="syncing"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': syncing }" />
        {{ syncing ? '同步中...' : '同步雷池事件' }}
      </button>
      <button
        @click="loadEvents()"
        class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
        :disabled="refreshing"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
        刷新事件
      </button>
    </template>

    <div class="min-w-0 space-y-6">
      <div
        v-if="error"
        class="rounded-xl border border-red-500/25 bg-red-500/8 px-4 py-3 text-sm text-red-600 shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

      <div
        v-if="successMessage"
        class="rounded-xl border border-emerald-300/60 bg-emerald-50 px-4 py-3 text-sm text-emerald-800 shadow-[0_14px_30px_rgba(16,185,129,0.08)]"
      >
        {{ successMessage }}
      </div>

      <div
        class="flex flex-wrap gap-3 rounded-[28px] border border-white/70 bg-white/60 p-4"
      >
        <select
          v-model="eventsFilters.layer"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="all">全部层级</option>
          <option value="l4">四层</option>
          <option value="l7">七层</option>
          <option value="safeline">雷池</option>
        </select>
        <select
          v-model="eventsFilters.provider"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="all">全部来源系统</option>
          <option value="safeline">雷池</option>
        </select>
        <select
          v-model="eventsFilters.provider_site_id"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="all">全部雷池站点</option>
          <option v-for="site in siteOptions" :key="site.id" :value="site.id">
            {{ site.label }}
          </option>
        </select>
        <select
          v-model="eventsFilters.action"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="all">全部动作</option>
          <option value="block">拦截</option>
          <option value="allow">放行</option>
          <option value="alert">告警</option>
          <option value="log">记录</option>
        </select>
        <label
          class="inline-flex items-center gap-2 rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <input
            v-model="eventsFilters.blocked_only"
            type="checkbox"
            class="accent-blue-600"
          />
          仅显示拦截
        </label>
        <select
          v-model="eventsFilters.handled"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="all">全部状态</option>
          <option value="unhandled">仅未处理</option>
          <option value="handled">仅已处理</option>
        </select>
        <select
          v-model="eventsFilters.sort_by"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="created_at">时间排序</option>
          <option value="source_ip">按来源 IP</option>
          <option value="dest_port">按目标端口</option>
        </select>
        <select
          v-model="eventsFilters.sort_direction"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="desc">降序</option>
          <option value="asc">升序</option>
        </select>
      </div>

      <div v-if="loading" class="text-sm text-slate-500">正在加载事件...</div>

      <div v-else class="min-w-0 space-y-4">
        <div
          class="max-w-full overflow-hidden rounded-xl border border-white/80 bg-white/78 shadow-[0_16px_44px_rgba(90,60,30,0.08)]"
        >
          <div class="max-w-full overflow-x-auto overscroll-x-contain">
            <table class="w-full min-w-[760px] border-collapse text-left">
              <thead class="bg-slate-50 text-sm text-slate-500">
                <tr>
                  <th class="whitespace-nowrap px-4 py-3 font-medium">时间</th>
                  <th class="whitespace-nowrap px-4 py-3 font-medium">分类</th>
                  <th class="whitespace-nowrap px-4 py-3 font-medium">原因</th>
                  <th class="whitespace-nowrap px-4 py-3 font-medium">来源</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="event in eventsPayload.events"
                  :key="event.id"
                  class="border-t border-slate-200 align-top text-sm text-stone-800 transition hover:bg-[#fff8ef]"
                  :class="{ 'opacity-65': event.handled }"
                >
                  <td class="px-4 py-3">
                    <div class="min-w-[154px]">
                      <p class="font-mono text-[13px] leading-6 text-stone-900">
                        {{ formatTimestamp(event.created_at) }}
                      </p>
                    </div>
                  </td>
                  <td class="px-4 py-3">
                    <div
                      class="flex min-w-[236px] flex-nowrap items-center gap-2 whitespace-nowrap"
                    >
                      <StatusBadge
                        :text="layerLabel(event.layer)"
                        :type="event.layer === 'l7' ? 'info' : 'warning'"
                      />
                      <StatusBadge
                        :text="eventActionLabel(event.action)"
                        :type="eventActionBadgeType(event.action)"
                      />
                      <StatusBadge
                        v-if="eventAttackTypeLabel(event)"
                        :text="eventAttackTypeLabel(event)"
                        type="muted"
                        compact
                      />
                      <button
                        v-if="
                          event.provider_site_name || event.provider_site_domain
                        "
                        class="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-slate-200 bg-white/85 text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                        :title="
                          event.provider_site_name ||
                          event.provider_site_domain ||
                          '站点链接预览'
                        "
                        @click="
                          openPreview(
                            '站点链接预览',
                            event.provider_site_name ||
                              event.provider_site_domain,
                          )
                        "
                      >
                        <Eye :size="13" />
                      </button>
                    </div>
                  </td>
                  <td class="px-4 py-3">
                    <div class="min-w-[300px]">
                      <p
                        class="truncate font-medium leading-6 text-stone-900"
                        :title="eventReasonLabel(event)"
                      >
                        {{ eventReasonLabel(event) }}
                      </p>
                    </div>
                  </td>
                  <td class="px-4 py-3">
                    <div class="min-w-[190px]">
                      <p
                        class="truncate font-mono text-[13px] whitespace-nowrap text-stone-900"
                        :title="event.source_ip"
                      >
                        {{ event.source_ip }}
                      </p>
                    </div>
                  </td>
                </tr>
                <tr v-if="!eventsPayload.events.length">
                  <td
                    colspan="4"
                    class="px-4 py-6 text-center text-sm text-slate-500"
                  >
                    当前没有可显示的安全事件。
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <div
      v-if="previewContent"
      class="fixed inset-0 z-[100] flex items-center justify-center px-4 py-8"
    >
      <div
        class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm"
        @click="closePreview"
      ></div>
      <div
        class="relative w-full max-w-5xl rounded-xl border border-white/85 bg-[linear-gradient(160deg,rgba(255,250,244,0.98),rgba(244,239,231,0.98))] p-4 shadow-[0_24px_80px_rgba(60,40,20,0.24)] md:p-5"
      >
        <div class="flex items-start justify-between gap-4">
          <div>
            <p class="text-sm tracking-wide text-blue-700">链接预览</p>
            <h3 class="mt-2 text-2xl font-semibold text-stone-900">
              {{ previewTitle }}
            </h3>
          </div>
          <button
            @click="closePreview"
            class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-slate-200 bg-white/75 transition hover:border-blue-500/40 hover:text-blue-700"
          >
            <X :size="18" />
          </button>
        </div>

        <div class="mt-4 rounded-xl border border-slate-200 bg-white/80 p-5">
          <p class="text-xs tracking-wide text-slate-500">完整内容</p>
          <p class="mt-3 break-all font-mono text-sm leading-7 text-stone-800">
            {{ previewContent }}
          </p>
        </div>

        <div class="mt-4 flex flex-wrap gap-3">
          <button
            class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/80 px-4 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
            @click="copyToClipboard(previewContent)"
          >
            <Copy :size="14" />
            复制内容
          </button>
          <button
            class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
            @click="closePreview"
          >
            关闭
          </button>
        </div>
      </div>
    </div>
  </AppLayout>
</template>
