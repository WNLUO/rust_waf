<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { fetchSecurityEvents, markSecurityEventHandled, syncSafeLineEvents } from '../lib/api'
import type { SecurityEventItem, SecurityEventsResponse } from '../lib/types'
import AppLayout from '../components/layout/AppLayout.vue'
import StatusBadge from '../components/ui/StatusBadge.vue'
import { useFormatters } from '../composables/useFormatters'
import { Check, Copy, RefreshCw } from 'lucide-vue-next'

const { formatTimestamp, actionLabel, layerLabel } = useFormatters()
const loading = ref(true)
const refreshing = ref(false)
const syncing = ref(false)
const error = ref('')
const successMessage = ref('')
const filtersReady = ref(false)
const eventsPayload = ref<SecurityEventsResponse>({ total: 0, limit: 0, offset: 0, events: [] })

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
      provider: eventsFilters.provider === 'all' ? undefined : eventsFilters.provider,
      provider_site_id:
        eventsFilters.provider_site_id === 'all' ? undefined : eventsFilters.provider_site_id,
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

const toggleEventHandled = async (event: SecurityEventItem) => {
  try {
    await markSecurityEventHandled(event.id, !event.handled)
    await loadEvents()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '更新事件状态失败'
  }
}

const copyToClipboard = async (text: string) => {
  try {
    await navigator.clipboard?.writeText(text)
  } catch {
    // ignore clipboard failure
  }
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
      event.provider_site_name || event.provider_site_domain || event.provider_site_id,
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
        class="inline-flex items-center gap-2 rounded-full border border-cyber-border bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong disabled:opacity-60"
        :disabled="syncing"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': syncing }" />
        {{ syncing ? '同步中...' : '同步雷池事件' }}
      </button>
      <button
        @click="loadEvents()"
        class="inline-flex items-center gap-2 rounded-full border border-cyber-border bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong disabled:opacity-60"
        :disabled="refreshing"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
        刷新事件
      </button>
    </template>

    <div class="space-y-6">
      <section class="rounded-[34px] border border-white/85 bg-[linear-gradient(140deg,rgba(255,250,244,0.92),rgba(244,239,231,0.96))] p-7 shadow-[0_26px_80px_rgba(90,60,30,0.10)]">
        <p class="text-sm tracking-[0.22em] text-cyber-accent-strong">事件记录</p>
        <h2 class="mt-3 font-display text-4xl font-semibold text-stone-900">攻击与处置轨迹</h2>
        <p class="mt-4 max-w-2xl text-sm leading-7 text-stone-700">
          事件页单独承担排查工作，你可以在这里过滤高风险事件、标记处理状态，并快速复制来源 IP 与 URL 做进一步分析。
        </p>
      </section>

      <div
        v-if="error"
        class="rounded-[24px] border border-cyber-error/25 bg-cyber-error/8 px-5 py-4 text-sm text-cyber-error shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

      <div
        v-if="successMessage"
        class="rounded-[24px] border border-emerald-300/60 bg-emerald-50 px-5 py-4 text-sm text-emerald-800 shadow-[0_14px_30px_rgba(16,185,129,0.08)]"
      >
        {{ successMessage }}
      </div>

      <div class="flex flex-wrap gap-3 rounded-[28px] border border-white/70 bg-white/60 p-4">
        <select v-model="eventsFilters.layer" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <option value="all">全部层级</option>
          <option value="l4">四层</option>
          <option value="l7">七层</option>
          <option value="safeline">雷池</option>
        </select>
        <select v-model="eventsFilters.provider" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <option value="all">全部来源系统</option>
          <option value="safeline">雷池</option>
        </select>
        <select v-model="eventsFilters.provider_site_id" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <option value="all">全部雷池站点</option>
          <option v-for="site in siteOptions" :key="site.id" :value="site.id">{{ site.label }}</option>
        </select>
        <select v-model="eventsFilters.action" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <option value="all">全部动作</option>
          <option value="block">拦截</option>
          <option value="allow">放行</option>
          <option value="alert">告警</option>
          <option value="log">记录</option>
        </select>
        <label class="inline-flex items-center gap-2 rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <input v-model="eventsFilters.blocked_only" type="checkbox" class="accent-[var(--color-cyber-accent)]" />
          仅显示拦截
        </label>
        <select v-model="eventsFilters.handled" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <option value="all">全部状态</option>
          <option value="unhandled">仅未处理</option>
          <option value="handled">仅已处理</option>
        </select>
        <select v-model="eventsFilters.sort_by" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <option value="created_at">时间排序</option>
          <option value="source_ip">按来源 IP</option>
          <option value="dest_port">按目标端口</option>
        </select>
        <select v-model="eventsFilters.sort_direction" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <option value="desc">降序</option>
          <option value="asc">升序</option>
        </select>
      </div>

      <div v-if="loading" class="text-sm text-cyber-muted">正在加载事件...</div>

      <div v-else class="grid gap-4">
        <article
          v-for="event in eventsPayload.events"
          :key="event.id"
          class="rounded-[30px] border border-white/80 bg-white/78 p-6 shadow-[0_14px_40px_rgba(90,60,30,0.07)] transition"
          :class="{ 'opacity-65': event.handled }"
        >
          <div class="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
            <div class="space-y-3">
              <div class="flex flex-wrap items-center gap-3">
                <StatusBadge :text="layerLabel(event.layer)" :type="event.layer === 'l7' ? 'info' : 'warning'" />
                <StatusBadge :text="actionLabel(event.action)" :type="event.action === 'block' ? 'error' : 'warning'" />
                <StatusBadge v-if="event.provider" :text="event.provider" type="muted" compact />
                <StatusBadge
                  v-if="event.provider_site_name || event.provider_site_domain"
                  :text="event.provider_site_name || event.provider_site_domain || ''"
                  type="info"
                  compact
                />
                <StatusBadge v-if="event.handled" text="已处理" type="success" compact />
                <span class="text-sm font-medium text-stone-900">{{ event.reason }}</span>
              </div>
              <div class="grid gap-2 text-sm text-stone-700 md:grid-cols-2">
                <p>来源：{{ event.source_ip }}:{{ event.source_port }}</p>
                <p>目标：{{ event.dest_ip }}:{{ event.dest_port }}</p>
                <p>协议：{{ event.protocol }}</p>
                <p>请求方法：{{ event.http_method || '无' }}</p>
                <p class="md:col-span-2">访问路径：{{ event.uri || '无' }}</p>
              </div>
            </div>
            <div class="rounded-[20px] bg-cyber-surface-strong px-4 py-3 text-sm text-cyber-muted">
              {{ formatTimestamp(event.created_at) }}
            </div>
          </div>
          <div class="mt-4 flex flex-wrap gap-3 text-xs text-cyber-muted">
            <button
              class="inline-flex items-center gap-1 rounded-full border border-cyber-border/60 px-3 py-1 text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong"
              @click="copyToClipboard(`${event.source_ip}`)"
            >
              <Copy :size="12" />
              复制来源 IP
            </button>
            <button
              class="inline-flex items-center gap-1 rounded-full border border-cyber-border/60 px-3 py-1 text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong"
              @click="copyToClipboard(event.uri || '')"
            >
              <Copy :size="12" />
              复制 URL
            </button>
            <button
              class="inline-flex items-center gap-1 rounded-full border border-cyber-border/60 px-3 py-1 text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong"
              @click="toggleEventHandled(event)"
            >
              <Check :size="12" />
              {{ event.handled ? '标记未处理' : '标记已处理' }}
            </button>
          </div>
        </article>
        <p v-if="!eventsPayload.events.length" class="text-sm text-cyber-muted">当前没有可显示的安全事件。</p>
      </div>
    </div>
  </AppLayout>
</template>
