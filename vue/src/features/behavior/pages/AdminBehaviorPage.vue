<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import AppLayout from '@/app/layout/AppLayout.vue'
import CyberCard from '@/shared/ui/CyberCard.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import { fetchSecurityEvents } from '@/shared/api/events'
import { fetchMetrics } from '@/shared/api/system'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import {
  useAdminRealtimeState,
  useAdminRealtimeTopic,
} from '@/shared/realtime/adminRealtime'
import type { MetricsResponse, SecurityEventItem } from '@/shared/types'
import {
  Activity,
  Ban,
  Fingerprint,
  RefreshCw,
  ShieldAlert,
} from 'lucide-vue-next'

interface BehaviorDetails {
  action: string | null
  score: number
  identity: string | null
  dominant_route: string | null
  focused_document_route: string | null
  distinct_routes: number
  repeated_ratio: number
  document_repeated_ratio: number
  interval_jitter_ms: number | null
  document_requests: number
  non_document_requests: number
  challenge_count_window: number
  session_span_secs: number
  flags: string[]
}

interface BehaviorEventView {
  id: number
  sourceIp: string
  createdAt: number
  method: string
  uri: string
  reason: string
  action: 'challenge' | 'block' | 'delay' | 'other'
  score: number
  identity: string
  dominantRoute: string
  distinctRoutes: number
  repeatedRatio: number
  documentRepeatedRatio: number
  intervalJitterMs: number | null
  documentRequests: number
  nonDocumentRequests: number
  challengeCountWindow: number
  sessionSpanSecs: number
  flags: string[]
}

interface BehaviorProfileView {
  key: string
  identity: string
  sourceIp: string
  latestAction: BehaviorEventView['action']
  latestSeenAt: number
  latestUri: string
  dominantRoute: string
  eventCount: number
  challengeCount: number
  blockCount: number
  maxScore: number
  avgScore: number
  maxRepeatedRatio: number
  maxDocumentRepeatedRatio: number
  distinctRoutes: number
  intervalJitterMs: number | null
  documentRequests: number
  nonDocumentRequests: number
  challengeCountWindow: number
  focusedDocumentRoute: string
  sessionSpanSecs: number
  flags: string[]
}

const MAX_EVENTS = 120

const { formatNumber, formatTimestamp } = useFormatters()
const realtimeState = useAdminRealtimeState()
const loading = ref(true)
const refreshing = ref(false)
const error = ref('')
const lastUpdated = ref<number | null>(null)
const metrics = ref<MetricsResponse | null>(null)
const behaviorEvents = ref<BehaviorEventView[]>([])
const selectedProfileKey = ref('')

useFlashMessages({
  error,
  errorTitle: '行为观测',
  errorDuration: 5600,
})

function parseInteger(value: unknown): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string') {
    const parsed = Number.parseInt(value, 10)
    if (Number.isFinite(parsed)) return parsed
  }
  return 0
}

function parseNullableInteger(value: unknown): number | null {
  if (value === null || value === undefined || value === '') return null
  const parsed = parseInteger(value)
  return Number.isFinite(parsed) ? parsed : null
}

function parseBehaviorDetails(event: SecurityEventItem): BehaviorDetails | null {
  if (!event.reason.toLowerCase().includes('l7 behavior guard')) {
    return null
  }

  if (!event.details_json) {
    return null
  }

  try {
    const payload = JSON.parse(event.details_json) as {
      l7_behavior?: Record<string, unknown>
    }
    const details = payload.l7_behavior
    if (!details) return null

    return {
      action:
        typeof details.action === 'string' && details.action.trim()
          ? details.action.trim()
          : null,
      score: parseInteger(details.score),
      identity:
        typeof details.identity === 'string' && details.identity.trim()
          ? details.identity.trim()
          : null,
      dominant_route:
        typeof details.dominant_route === 'string' && details.dominant_route.trim()
          ? details.dominant_route.trim()
          : null,
      focused_document_route:
        typeof details.focused_document_route === 'string' &&
        details.focused_document_route.trim()
          ? details.focused_document_route.trim()
          : null,
      distinct_routes: parseInteger(details.distinct_routes),
      repeated_ratio: parseInteger(details.repeated_ratio),
      document_repeated_ratio: parseInteger(details.document_repeated_ratio),
      interval_jitter_ms: parseNullableInteger(details.interval_jitter_ms),
      document_requests: parseInteger(details.document_requests),
      non_document_requests: parseInteger(details.non_document_requests),
      challenge_count_window: parseInteger(details.challenge_count_window),
      session_span_secs: parseInteger(details.session_span_secs),
      flags:
        typeof details.flags === 'string' && details.flags.trim()
          ? details.flags
              .split(',')
              .map((item) => item.trim())
              .filter(Boolean)
          : [],
    }
  } catch {
    return null
  }
}

function normalizeBehaviorAction(action: string | null): BehaviorEventView['action'] {
  if (!action) return 'other'
  if (action === 'challenge') return 'challenge'
  if (action === 'block') return 'block'
  if (action.startsWith('delay:')) return 'delay'
  return 'other'
}

function toBehaviorEvent(event: SecurityEventItem): BehaviorEventView | null {
  const details = parseBehaviorDetails(event)
  if (!details) return null

  return {
    id: event.id,
    sourceIp: event.source_ip,
    createdAt: event.created_at,
    method: event.http_method || '-',
    uri: event.uri || '-',
    reason: event.reason,
    action: normalizeBehaviorAction(details.action),
    score: details.score,
    identity: details.identity || `ip:${event.source_ip}`,
    dominantRoute: details.dominant_route || '-',
    distinctRoutes: details.distinct_routes,
    repeatedRatio: details.repeated_ratio,
    documentRepeatedRatio: details.document_repeated_ratio,
    intervalJitterMs: details.interval_jitter_ms,
    documentRequests: details.document_requests,
    nonDocumentRequests: details.non_document_requests,
    challengeCountWindow: details.challenge_count_window,
    sessionSpanSecs: details.session_span_secs,
    flags: details.flags,
  }
}

const profiles = computed<BehaviorProfileView[]>(() => {
  const groups = new Map<string, BehaviorEventView[]>()
  for (const event of behaviorEvents.value) {
    const key = event.identity || `ip:${event.sourceIp}`
    const bucket = groups.get(key) ?? []
    bucket.push(event)
    groups.set(key, bucket)
  }

  return Array.from(groups.entries())
    .map(([key, events]) => {
      const sorted = [...events].sort((left, right) => right.createdAt - left.createdAt)
      const latest = sorted[0]
      const challengeCount = events.filter((item) => item.action === 'challenge').length
      const blockCount = events.filter((item) => item.action === 'block').length
      const scoreTotal = events.reduce((sum, item) => sum + item.score, 0)
      const maxRepeatedRatio = Math.max(...events.map((item) => item.repeatedRatio))
      const maxDocumentRepeatedRatio = Math.max(
        ...events.map((item) => item.documentRepeatedRatio),
      )
      const maxScore = Math.max(...events.map((item) => item.score))
      const flags = Array.from(new Set(events.flatMap((item) => item.flags)))

      return {
        key,
        identity: key,
        sourceIp: latest.sourceIp,
        latestAction: latest.action,
        latestSeenAt: latest.createdAt,
        latestUri: latest.uri,
        dominantRoute: latest.dominantRoute,
        eventCount: events.length,
        challengeCount,
        blockCount,
        maxScore,
        avgScore: Number((scoreTotal / events.length).toFixed(1)),
        maxRepeatedRatio,
        maxDocumentRepeatedRatio,
        distinctRoutes: latest.distinctRoutes,
        intervalJitterMs: latest.intervalJitterMs,
        documentRequests: latest.documentRequests,
        nonDocumentRequests: latest.nonDocumentRequests,
        challengeCountWindow: latest.challengeCountWindow,
        focusedDocumentRoute: latest.dominantRoute,
        sessionSpanSecs: latest.sessionSpanSecs,
        flags,
      }
    })
    .sort((left, right) => {
      if (right.maxScore !== left.maxScore) return right.maxScore - left.maxScore
      if (right.blockCount !== left.blockCount) return right.blockCount - left.blockCount
      return right.latestSeenAt - left.latestSeenAt
    })
})

const selectedProfile = computed(
  () =>
    profiles.value.find((item) => item.key === selectedProfileKey.value) ||
    profiles.value[0] ||
    null,
)

const selectedProfileEvents = computed(() => {
  if (!selectedProfile.value) return []
  return behaviorEvents.value
    .filter((item) => item.identity === selectedProfile.value?.identity)
    .slice(0, 12)
})

const statusLabel = computed(() => {
  if (refreshing.value) return '正在同步行为观测...'
  if (realtimeState.connected && lastUpdated.value) {
    return `实时通道已连接：${new Intl.DateTimeFormat('zh-CN', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).format(new Date(lastUpdated.value))}`
  }
  if (realtimeState.connecting) return '实时通道连接中...'
  if (lastUpdated.value) {
    return `上次刷新：${new Intl.DateTimeFormat('zh-CN', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).format(new Date(lastUpdated.value))}`
  }
  return '等待首次同步'
})

function actionBadgeType(action: BehaviorEventView['action']) {
  if (action === 'block') return 'error' as const
  if (action === 'challenge') return 'warning' as const
  if (action === 'delay') return 'info' as const
  return 'muted' as const
}

function actionLabel(action: BehaviorEventView['action']) {
  if (action === 'block') return '已封禁'
  if (action === 'challenge') return '已挑战'
  if (action === 'delay') return '已延迟'
  return '已记录'
}

function mergeBehaviorEvent(event: BehaviorEventView) {
  const merged = [event, ...behaviorEvents.value].filter(
    (item, index, items) => items.findIndex((candidate) => candidate.id === item.id) === index,
  )
  behaviorEvents.value = merged
    .sort((left, right) => right.createdAt - left.createdAt)
    .slice(0, MAX_EVENTS)
  if (!selectedProfileKey.value) {
    selectedProfileKey.value = event.identity
  }
}

async function loadPage(showLoader = false) {
  if (showLoader) loading.value = true
  refreshing.value = true
  try {
    const [metricsPayload, eventsPayload] = await Promise.all([
      fetchMetrics(),
      fetchSecurityEvents({
        limit: MAX_EVENTS,
        offset: 0,
        layer: 'L7',
        action: 'respond',
        sort_by: 'created_at',
        sort_direction: 'desc',
      }),
    ])
    metrics.value = metricsPayload
    behaviorEvents.value = eventsPayload.events
      .map(toBehaviorEvent)
      .filter((item): item is BehaviorEventView => item !== null)
      .sort((left, right) => right.createdAt - left.createdAt)
    if (
      !selectedProfileKey.value ||
      !behaviorEvents.value.some((item) => item.identity === selectedProfileKey.value)
    ) {
      selectedProfileKey.value = behaviorEvents.value[0]?.identity || ''
    }
    lastUpdated.value = Date.now()
  } catch (err) {
    error.value = err instanceof Error ? err.message : '加载行为观测失败'
  } finally {
    loading.value = false
    refreshing.value = false
  }
}

useAdminRealtimeTopic<MetricsResponse>('metrics', (payload) => {
  metrics.value = payload
  lastUpdated.value = Date.now()
})

useAdminRealtimeTopic<SecurityEventItem>('security_event_delta', (payload) => {
  const event = toBehaviorEvent(payload)
  if (!event) return
  mergeBehaviorEvent(event)
  lastUpdated.value = Date.now()
})

useAdminRealtimeTopic<{ events: SecurityEventItem[] }>('recent_events', (payload) => {
  const incoming = payload.events
    .map(toBehaviorEvent)
    .filter((item): item is BehaviorEventView => item !== null)
  if (!incoming.length) return
  for (const event of incoming) {
    mergeBehaviorEvent(event)
  }
  lastUpdated.value = Date.now()
})

onMounted(() => {
  loadPage(true)
})
</script>

<template>
  <AppLayout>
    <div class="space-y-6">
      <section
        class="overflow-hidden rounded-[28px] border border-slate-200 bg-gradient-to-br from-white via-slate-50 to-amber-50 shadow-sm"
      >
        <div class="flex flex-col gap-6 px-6 py-6 lg:flex-row lg:items-end lg:justify-between">
          <div class="space-y-3">
            <div class="inline-flex items-center gap-2 rounded-full border border-amber-200 bg-white/80 px-3 py-1 text-xs font-medium text-amber-700">
              <Fingerprint :size="14" />
              行为画像观测
            </div>
            <div class="space-y-2">
              <h1 class="text-2xl font-semibold tracking-tight text-slate-900">
                看见“像真人但不正常”的会话
              </h1>
              <p class="max-w-3xl text-sm leading-6 text-slate-600">
                这里展示的是行为风控层命中的会话画像，不只是 IP 限速。你可以看到重复率、主命中路径、页面联动缺失、机械节奏，以及它最终走到了 challenge 还是 block。
              </p>
            </div>
          </div>

          <div class="flex flex-col items-start gap-3 lg:items-end">
            <StatusBadge
              :type="realtimeState.connected ? 'success' : realtimeState.connecting ? 'info' : 'muted'"
              :text="statusLabel"
            />
            <button
              type="button"
              class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:border-slate-300 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
              :disabled="refreshing"
              @click="loadPage()"
            >
              <RefreshCw :size="16" :class="{ 'animate-spin': refreshing }" />
              刷新观测
            </button>
          </div>
        </div>
      </section>

      <section class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <CyberCard no-padding>
          <div class="flex items-start justify-between px-5 py-4">
            <div>
              <p class="text-sm text-slate-500">可疑身份</p>
              <p class="mt-2 text-3xl font-semibold text-slate-900">
                {{ formatNumber(profiles.length) }}
              </p>
              <p class="mt-2 text-xs text-slate-500">
                最近 {{ formatNumber(behaviorEvents.length) }} 条行为事件聚合
              </p>
            </div>
            <div class="rounded-2xl bg-slate-100 p-3 text-slate-600">
              <Fingerprint :size="18" />
            </div>
          </div>
        </CyberCard>

        <CyberCard no-padding>
          <div class="flex items-start justify-between px-5 py-4">
            <div>
              <p class="text-sm text-slate-500">行为挑战</p>
              <p class="mt-2 text-3xl font-semibold text-amber-700">
                {{ formatNumber(metrics?.l7_behavior_challenges || 0) }}
              </p>
              <p class="mt-2 text-xs text-slate-500">
                当前仍以 challenge-first 为主
              </p>
            </div>
            <div class="rounded-2xl bg-amber-50 p-3 text-amber-700">
              <ShieldAlert :size="18" />
            </div>
          </div>
        </CyberCard>

        <CyberCard no-padding>
          <div class="flex items-start justify-between px-5 py-4">
            <div>
              <p class="text-sm text-slate-500">行为封禁</p>
              <p class="mt-2 text-3xl font-semibold text-red-700">
                {{ formatNumber(metrics?.l7_behavior_blocks || 0) }}
              </p>
              <p class="mt-2 text-xs text-slate-500">
                反复 challenge 后会升级到名单页
              </p>
            </div>
            <div class="rounded-2xl bg-red-50 p-3 text-red-700">
              <Ban :size="18" />
            </div>
          </div>
        </CyberCard>

        <CyberCard no-padding>
          <div class="flex items-start justify-between px-5 py-4">
            <div>
              <p class="text-sm text-slate-500">行为延迟</p>
              <p class="mt-2 text-3xl font-semibold text-blue-700">
                {{ formatNumber(metrics?.l7_behavior_delays || 0) }}
              </p>
              <p class="mt-2 text-xs text-slate-500">
                低分异常会先进入柔性摩擦
              </p>
            </div>
            <div class="rounded-2xl bg-blue-50 p-3 text-blue-700">
              <Activity :size="18" />
            </div>
          </div>
        </CyberCard>
      </section>

      <section class="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <CyberCard
          title="可疑会话画像"
          sub-title="按 identity 聚合最近命中的行为风控事件，优先展示风险更高的会话"
        >
          <div v-if="loading" class="py-16 text-center text-sm text-slate-500">
            正在加载行为画像...
          </div>
          <div
            v-else-if="!profiles.length"
            class="rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-6 py-12 text-center text-sm text-slate-500"
          >
            还没有采集到行为风控事件。等你继续用 `curl` 或真实流量命中后，这里会自动出现画像。
          </div>
          <div v-else class="space-y-3">
            <button
              v-for="profile in profiles"
              :key="profile.key"
              type="button"
              class="w-full rounded-2xl border px-4 py-4 text-left transition"
              :class="
                selectedProfile?.key === profile.key
                  ? 'border-amber-300 bg-amber-50/70 shadow-sm'
                  : 'border-slate-200 bg-white hover:border-slate-300'
              "
              @click="selectedProfileKey = profile.key"
            >
              <div class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div class="min-w-0 space-y-2">
                  <div class="flex flex-wrap items-center gap-2">
                    <StatusBadge
                      :type="actionBadgeType(profile.latestAction)"
                      :text="actionLabel(profile.latestAction)"
                    />
                    <span class="rounded-full bg-slate-900 px-2.5 py-0.5 text-xs font-medium text-white">
                      最高分 {{ formatNumber(profile.maxScore) }}
                    </span>
                    <span class="text-xs text-slate-500">
                      最近命中 {{ formatTimestamp(profile.latestSeenAt) }}
                    </span>
                  </div>
                  <div class="font-mono text-sm text-slate-900 break-all">
                    {{ profile.identity }}
                  </div>
                  <div class="flex flex-wrap items-center gap-3 text-xs text-slate-500">
                    <span>源 IP {{ profile.sourceIp }}</span>
                    <span>主路径 {{ profile.dominantRoute }}</span>
                    <span>最近 URI {{ profile.latestUri }}</span>
                  </div>
                </div>
                <div class="grid grid-cols-2 gap-3 text-sm text-slate-600 lg:min-w-[18rem]">
                  <div>
                    <div class="text-xs text-slate-400">事件数</div>
                    <div class="mt-1 font-semibold text-slate-900">
                      {{ formatNumber(profile.eventCount) }}
                    </div>
                  </div>
                  <div>
                    <div class="text-xs text-slate-400">挑战 / 封禁</div>
                    <div class="mt-1 font-semibold text-slate-900">
                      {{ formatNumber(profile.challengeCount) }} / {{ formatNumber(profile.blockCount) }}
                    </div>
                  </div>
                    <div>
                      <div class="text-xs text-slate-400">重复率峰值</div>
                      <div class="mt-1 font-semibold text-slate-900">
                        {{ formatNumber(profile.maxRepeatedRatio) }}%
                      </div>
                    </div>
                  <div>
                    <div class="text-xs text-slate-400">页面重载率</div>
                    <div class="mt-1 font-semibold text-slate-900">
                      {{ formatNumber(profile.maxDocumentRepeatedRatio) }}%
                    </div>
                  </div>
                  <div>
                    <div class="text-xs text-slate-400">平均分</div>
                    <div class="mt-1 font-semibold text-slate-900">
                      {{ profile.avgScore.toFixed(1) }}
                    </div>
                  </div>
                </div>
              </div>
            </button>
          </div>
        </CyberCard>

        <CyberCard
          title="画像详情"
          sub-title="把行为风控打分拆成你能直接读懂的字段"
        >
          <div
            v-if="!selectedProfile"
            class="rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-6 py-12 text-center text-sm text-slate-500"
          >
            暂无可展示的画像详情。
          </div>
          <div v-else class="space-y-5">
            <div class="space-y-3">
              <div class="flex flex-wrap items-center gap-2">
                <StatusBadge
                  :type="actionBadgeType(selectedProfile.latestAction)"
                  :text="actionLabel(selectedProfile.latestAction)"
                />
                <StatusBadge
                  type="info"
                  :text="`当前窗口 challenge 次数 ${formatNumber(selectedProfile.challengeCountWindow)}`"
                />
              </div>
              <div class="font-mono text-sm text-slate-900 break-all">
                {{ selectedProfile.identity }}
              </div>
            </div>

            <div class="grid gap-3 sm:grid-cols-2">
              <div class="rounded-2xl bg-slate-50 p-4">
                <div class="text-xs uppercase tracking-[0.18em] text-slate-400">路径画像</div>
                <div class="mt-3 text-sm text-slate-600">
                  主路径
                  <span class="font-semibold text-slate-900">{{ selectedProfile.dominantRoute }}</span>
                </div>
                <div class="mt-2 text-sm text-slate-600">
                  路径多样性
                  <span class="font-semibold text-slate-900">{{ formatNumber(selectedProfile.distinctRoutes) }}</span>
                </div>
                <div class="mt-2 text-sm text-slate-600">
                  重复率峰值
                  <span class="font-semibold text-slate-900">{{ formatNumber(selectedProfile.maxRepeatedRatio) }}%</span>
                </div>
                <div class="mt-2 text-sm text-slate-600">
                  页面重载率
                  <span class="font-semibold text-slate-900">{{ formatNumber(selectedProfile.maxDocumentRepeatedRatio) }}%</span>
                </div>
              </div>

              <div class="rounded-2xl bg-slate-50 p-4">
                <div class="text-xs uppercase tracking-[0.18em] text-slate-400">请求形状</div>
                <div class="mt-3 text-sm text-slate-600">
                  页面请求
                  <span class="font-semibold text-slate-900">{{ formatNumber(selectedProfile.documentRequests) }}</span>
                </div>
                <div class="mt-2 text-sm text-slate-600">
                  非页面请求
                  <span class="font-semibold text-slate-900">{{ formatNumber(selectedProfile.nonDocumentRequests) }}</span>
                </div>
                <div class="mt-2 text-sm text-slate-600">
                  节奏抖动
                  <span class="font-semibold text-slate-900">
                    {{ selectedProfile.intervalJitterMs === null ? '未采样' : `${formatNumber(selectedProfile.intervalJitterMs)} ms` }}
                  </span>
                </div>
                <div class="mt-2 text-sm text-slate-600">
                  会话跨度
                  <span class="font-semibold text-slate-900">{{ formatNumber(selectedProfile.sessionSpanSecs) }} s</span>
                </div>
              </div>
            </div>

            <div v-if="selectedProfile.flags.length" class="rounded-2xl bg-amber-50/70 p-4">
              <div class="text-xs uppercase tracking-[0.18em] text-amber-700">命中标签</div>
              <div class="mt-3 flex flex-wrap gap-2">
                <span
                  v-for="flag in selectedProfile.flags"
                  :key="flag"
                  class="rounded-full border border-amber-200 bg-white px-3 py-1 text-xs font-medium text-amber-800"
                >
                  {{ flag }}
                </span>
              </div>
            </div>

            <div class="rounded-2xl border border-slate-200 bg-white">
              <div class="border-b border-slate-200 px-4 py-3">
                <h3 class="text-sm font-semibold text-slate-900">最近动作轨迹</h3>
              </div>
              <div class="divide-y divide-slate-100">
                <div
                  v-for="event in selectedProfileEvents"
                  :key="event.id"
                  class="flex flex-col gap-2 px-4 py-3"
                >
                  <div class="flex flex-wrap items-center gap-2">
                    <StatusBadge
                      compact
                      :type="actionBadgeType(event.action)"
                      :text="actionLabel(event.action)"
                    />
                    <span class="text-xs text-slate-500">
                      {{ formatTimestamp(event.createdAt) }}
                    </span>
                    <span class="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-700">
                      score {{ formatNumber(event.score) }}
                    </span>
                  </div>
                  <div class="text-sm font-medium text-slate-900">
                    {{ event.method }} {{ event.uri }}
                  </div>
                  <div class="text-xs text-slate-500">
                    dominant {{ event.dominantRoute }} · repeat {{ formatNumber(event.repeatedRatio) }}% · doc-repeat {{ formatNumber(event.documentRepeatedRatio) }}% · routes {{ formatNumber(event.distinctRoutes) }}
                  </div>
                </div>
              </div>
            </div>

            <div class="flex flex-wrap gap-3">
              <RouterLink
                v-if="selectedProfile.latestAction === 'block'"
                to="/admin/blocked"
                class="inline-flex items-center gap-2 rounded-full border border-red-200 bg-red-50 px-4 py-2 text-sm font-medium text-red-700 transition hover:border-red-300 hover:text-red-800"
              >
                <Ban :size="16" />
                查看封禁名单
              </RouterLink>
              <RouterLink
                to="/admin/events"
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 transition hover:border-slate-300 hover:text-slate-900"
              >
                <Activity :size="16" />
                打开事件记录
              </RouterLink>
            </div>
          </div>
        </CyberCard>
      </section>
    </div>
  </AppLayout>
</template>
