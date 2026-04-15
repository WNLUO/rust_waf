<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import AppLayout from '@/app/layout/AppLayout.vue'
import AdminAiAuditSection from '@/features/behavior/components/AdminAiAuditSection.vue'
import CyberCard from '@/shared/ui/CyberCard.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import {
  fetchBehaviorProfiles,
  fetchBehaviorSessions,
  fetchFingerprintProfiles,
} from '@/shared/api/events'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import type {
  BehaviorProfileItem,
  BehaviorSessionItem,
  FingerprintProfileItem,
} from '@/shared/types'
import { BrainCircuit, Fingerprint, RefreshCw, Route } from 'lucide-vue-next'

const loading = ref(true)
const refreshing = ref(false)
const error = ref('')
const tab = ref<'fingerprints' | 'sessions'>('fingerprints')
const fingerprintProfiles = ref<FingerprintProfileItem[]>([])
const behaviorSessions = ref<BehaviorSessionItem[]>([])
const liveProfiles = ref<BehaviorProfileItem[]>([])

const { formatNumber, formatTimestamp } = useFormatters()

useFlashMessages({
  error,
  errorTitle: '智能档案',
  errorDuration: 5600,
})

const liveProfilesByIdentity = computed(
  () => new Map(liveProfiles.value.map((profile) => [profile.identity, profile])),
)
const currentRiskCount = computed(
  () => liveProfiles.value.filter((profile) => profile.blocked || profile.score >= 60).length,
)
const currentWatchingCount = computed(
  () =>
    liveProfiles.value.filter(
      (profile) => !profile.blocked && profile.score >= 20 && profile.score < 60,
    ).length,
)
const currentHealthyCount = computed(
  () => liveProfiles.value.filter((profile) => !profile.blocked && profile.score < 20).length,
)

function actionType(action: string | null) {
  if (action === 'block') return 'error' as const
  if (action === 'challenge') return 'warning' as const
  if (action?.startsWith('delay')) return 'info' as const
  return 'muted' as const
}

function actionLabel(action: string | null) {
  if (action === 'block') return '已封禁'
  if (action === 'challenge') return '已挑战'
  if (action?.startsWith('delay')) return '已延迟'
  if (action) return action
  return '已记录'
}

function currentStateType(profile: BehaviorProfileItem | undefined) {
  if (!profile) return 'muted' as const
  if (profile.blocked) return 'error' as const
  if (profile.score >= 60) return 'warning' as const
  if (profile.score >= 20) return 'info' as const
  return 'success' as const
}

function currentStateLabel(profile: BehaviorProfileItem | undefined) {
  if (!profile) return '当前不活跃'
  if (profile.blocked) return '当前封禁中'
  if (profile.score >= 60) return '当前高风险'
  if (profile.score >= 20) return '当前观察中'
  return '当前正常'
}

async function loadPage(showLoader = false) {
  if (showLoader) loading.value = true
  refreshing.value = true
  try {
    const [liveProfilesPayload, fingerprintsPayload, sessionsPayload] = await Promise.all([
      fetchBehaviorProfiles(),
      fetchFingerprintProfiles(),
      fetchBehaviorSessions(),
    ])
    liveProfiles.value = liveProfilesPayload.profiles
    fingerprintProfiles.value = fingerprintsPayload.profiles
    behaviorSessions.value = sessionsPayload.sessions
  } catch (err) {
    error.value = err instanceof Error ? err.message : '加载智能档案失败'
  } finally {
    loading.value = false
    refreshing.value = false
  }
}

onMounted(() => {
  void loadPage(true)
})
</script>

<template>
  <AppLayout>
    <div class="space-y-6">
      <section
        class="overflow-hidden rounded-[28px] border border-slate-200 bg-gradient-to-br from-white via-slate-50 to-cyan-50 shadow-sm"
      >
        <div class="flex flex-col gap-6 px-6 py-6 lg:flex-row lg:items-end lg:justify-between">
          <div class="space-y-3">
            <div class="inline-flex items-center gap-2 rounded-full border border-cyan-200 bg-white/80 px-3 py-1 text-xs font-medium text-cyan-700">
              <BrainCircuit :size="14" />
              智能档案
            </div>
            <div class="space-y-2">
              <h1 class="text-2xl font-semibold tracking-tight text-slate-900">
                当前状态与历史档案
              </h1>
              <p class="max-w-3xl text-sm leading-6 text-slate-600">
                先看当前活跃身份是不是正常，再看已经入库的历史风险档案。这样测试时不会把过去的挑战或封禁，误读成“现在仍在发生”。
              </p>
            </div>
          </div>

          <button
            type="button"
            class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:border-slate-300 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-60"
            :disabled="refreshing"
            @click="loadPage()"
          >
            <RefreshCw :size="16" :class="{ 'animate-spin': refreshing }" />
            刷新档案
          </button>
        </div>
      </section>

      <section class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <CyberCard no-padding>
          <div class="flex items-start justify-between px-5 py-4">
            <div>
              <p class="text-sm text-slate-500">当前活跃</p>
              <p class="mt-2 text-3xl font-semibold text-slate-900">
                {{ formatNumber(liveProfiles.length) }}
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
              <p class="text-sm text-slate-500">当前高风险</p>
              <p class="mt-2 text-3xl font-semibold text-slate-900">
                {{ formatNumber(currentRiskCount) }}
              </p>
            </div>
            <div class="rounded-2xl bg-slate-100 p-3 text-slate-600">
              <Route :size="18" />
            </div>
          </div>
        </CyberCard>
        <CyberCard no-padding>
          <div class="flex items-start justify-between px-5 py-4">
            <div>
              <p class="text-sm text-slate-500">当前观察中</p>
              <p class="mt-2 text-lg font-semibold text-amber-700">
                {{ formatNumber(currentWatchingCount) }}
              </p>
            </div>
          </div>
        </CyberCard>
        <CyberCard no-padding>
          <div class="flex items-start justify-between px-5 py-4">
            <div>
              <p class="text-sm text-slate-500">当前正常</p>
              <p class="mt-2 text-lg font-semibold text-emerald-700">
                {{ formatNumber(currentHealthyCount) }}
              </p>
            </div>
          </div>
        </CyberCard>
      </section>

      <AdminAiAuditSection />

      <CyberCard
        title="当前实时状态"
        sub-title="这里只看最近活跃身份的当前风险，不混入历史 challenge / block 记录"
      >
        <div v-if="loading" class="py-16 text-center text-sm text-slate-500">正在加载实时状态...</div>
        <div v-else-if="!liveProfiles.length" class="py-16 text-center text-sm text-slate-500">
          当前没有活跃画像
        </div>
        <div v-else class="space-y-3">
          <div
            v-for="profile in liveProfiles"
            :key="profile.identity"
            class="rounded-2xl border border-slate-200 bg-white px-4 py-4"
          >
            <div class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div class="space-y-2 min-w-0">
                <div class="flex flex-wrap items-center gap-2">
                  <StatusBadge
                    :type="currentStateType(profile)"
                    :text="currentStateLabel(profile)"
                  />
                  <StatusBadge
                    type="muted"
                    :text="`当前分数 ${formatNumber(profile.score || 0)}`"
                  />
                  <span class="text-xs text-slate-500">
                    最近活跃 {{ formatTimestamp(profile.latest_seen_at) }}
                  </span>
                </div>
                <div class="font-mono text-sm text-slate-900 break-all">{{ profile.identity }}</div>
                <div class="text-xs text-slate-500">
                  {{ profile.source_ip || '-' }} · 当前路径 {{ profile.latest_route || '-' }}
                </div>
                <div class="text-xs text-slate-500">
                  主路径 {{ profile.dominant_route || '-' }} · 页面 {{ formatNumber(profile.document_requests) }} · 接口 {{ formatNumber(profile.api_requests) }}
                </div>
                <div
                  v-if="profile.blocked"
                  class="text-xs text-red-700"
                >
                  当前封禁原因 {{ profile.blocked_reason || '-' }}
                  <template v-if="profile.blocked_expires_at">
                    · 预计结束 {{ formatTimestamp(profile.blocked_expires_at) }}
                  </template>
                </div>
              </div>
              <div class="grid grid-cols-2 gap-3 text-sm text-slate-600 lg:min-w-[22rem]">
                <div>
                  <div class="text-xs text-slate-400">总重复率</div>
                  <div class="mt-1 font-semibold text-slate-900">{{ formatNumber(profile.repeated_ratio) }}%</div>
                </div>
                <div>
                  <div class="text-xs text-slate-400">页面 / 接口重复率</div>
                  <div class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(profile.document_repeated_ratio) }}% / {{ formatNumber(profile.api_repeated_ratio) }}%
                  </div>
                </div>
                <div>
                  <div class="text-xs text-slate-400">不同路径</div>
                  <div class="mt-1 font-semibold text-slate-900">{{ formatNumber(profile.distinct_routes) }}</div>
                </div>
                <div>
                  <div class="text-xs text-slate-400">窗口挑战数</div>
                  <div class="mt-1 font-semibold text-slate-900">{{ formatNumber(profile.challenge_count_window) }}</div>
                </div>
              </div>
            </div>
            <div v-if="profile.flags?.length" class="mt-3 flex flex-wrap gap-2">
              <span
                v-for="flag in profile.flags"
                :key="flag"
                class="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-700"
              >
                {{ flag }}
              </span>
            </div>
          </div>
        </div>
      </CyberCard>

      <section class="flex flex-wrap gap-3">
        <button
          type="button"
          class="rounded-full px-4 py-2 text-sm font-medium transition"
          :class="tab === 'fingerprints' ? 'bg-slate-900 text-white' : 'border border-slate-200 bg-white text-slate-700'"
          @click="tab = 'fingerprints'"
        >
          指纹档案
        </button>
        <button
          type="button"
          class="rounded-full px-4 py-2 text-sm font-medium transition"
          :class="tab === 'sessions' ? 'bg-slate-900 text-white' : 'border border-slate-200 bg-white text-slate-700'"
          @click="tab = 'sessions'"
        >
          历史会话
        </button>
      </section>

      <CyberCard
        v-if="tab === 'fingerprints'"
        title="指纹档案"
        sub-title="这是历史风险档案，不代表当前仍在挑战或封禁"
      >
        <div v-if="loading" class="py-16 text-center text-sm text-slate-500">正在加载档案...</div>
        <div v-else class="space-y-3">
          <div
            v-for="profile in fingerprintProfiles"
            :key="profile.identity"
            class="rounded-2xl border border-slate-200 bg-white px-4 py-4"
          >
            <div class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div class="space-y-2 min-w-0">
                <div class="flex flex-wrap items-center gap-2">
                  <StatusBadge
                    :type="currentStateType(liveProfilesByIdentity.get(profile.identity))"
                    :text="currentStateLabel(liveProfilesByIdentity.get(profile.identity))"
                  />
                  <StatusBadge
                    :type="actionType(profile.latest_action)"
                    :text="`历史风险动作 ${actionLabel(profile.latest_action)}`"
                  />
                  <span class="rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-700">
                    {{ profile.identity_kind }}
                  </span>
                  <span class="text-xs text-slate-500">历史最近出现 {{ formatTimestamp(profile.last_seen_at) }}</span>
                </div>
                <div class="font-mono text-sm text-slate-900 break-all">{{ profile.identity }}</div>
                <div class="text-xs text-slate-500">
                  IP {{ profile.source_ip || '-' }} · 站点 {{ profile.last_site_domain || '-' }}
                </div>
                <div
                  v-if="liveProfilesByIdentity.get(profile.identity)"
                  class="text-xs text-cyan-700"
                >
                  当前主路径
                  {{ liveProfilesByIdentity.get(profile.identity)?.dominant_route || liveProfilesByIdentity.get(profile.identity)?.latest_route || '-' }}
                  · 当前分数
                  {{ formatNumber(liveProfilesByIdentity.get(profile.identity)?.score || 0) }}
                </div>
              </div>
              <div class="grid grid-cols-2 gap-3 text-sm text-slate-600 lg:min-w-[20rem]">
                <div>
                  <div class="text-xs text-slate-400">安全事件</div>
                  <div class="mt-1 font-semibold text-slate-900">{{ formatNumber(profile.total_security_events) }}</div>
                </div>
                <div>
                  <div class="text-xs text-slate-400">行为事件</div>
                  <div class="mt-1 font-semibold text-slate-900">{{ formatNumber(profile.total_behavior_events) }}</div>
                </div>
                <div>
                  <div class="text-xs text-slate-400">挑战 / 封禁</div>
                  <div class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(profile.total_challenges) }} / {{ formatNumber(profile.total_blocks) }}
                  </div>
                </div>
                <div>
                  <div class="text-xs text-slate-400">最新 / 最高分</div>
                  <div class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(profile.latest_score || 0) }} / {{ formatNumber(profile.max_score) }}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </CyberCard>

      <CyberCard
        v-else
        title="历史会话"
        sub-title="按 identity + site 归档的历史风险快照，不等于当前实时状态"
      >
        <div v-if="loading" class="py-16 text-center text-sm text-slate-500">正在加载会话...</div>
        <div v-else class="space-y-3">
          <div
            v-for="session in behaviorSessions"
            :key="session.session_key"
            class="rounded-2xl border border-slate-200 bg-white px-4 py-4"
          >
            <div class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div class="space-y-2 min-w-0">
                <div class="flex flex-wrap items-center gap-2">
                  <StatusBadge
                    :type="currentStateType(liveProfilesByIdentity.get(session.identity))"
                    :text="currentStateLabel(liveProfilesByIdentity.get(session.identity))"
                  />
                  <StatusBadge
                    :type="actionType(session.latest_action)"
                    :text="`历史风险动作 ${actionLabel(session.latest_action)}`"
                  />
                  <span class="text-xs text-slate-500">历史最近活跃 {{ formatTimestamp(session.last_seen_at) }}</span>
                </div>
                <div class="font-mono text-sm text-slate-900 break-all">{{ session.identity }}</div>
                <div class="text-xs text-slate-500">
                  {{ session.site_domain || '-' }} · {{ session.source_ip || '-' }} · {{ session.latest_uri || '-' }}
                </div>
              </div>
              <div class="grid grid-cols-2 gap-3 text-sm text-slate-600 lg:min-w-[24rem]">
                <div>
                  <div class="text-xs text-slate-400">事件数</div>
                  <div class="mt-1 font-semibold text-slate-900">{{ formatNumber(session.event_count) }}</div>
                </div>
                <div>
                  <div class="text-xs text-slate-400">挑战 / 封禁</div>
                  <div class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(session.challenge_count) }} / {{ formatNumber(session.block_count) }}
                  </div>
                </div>
                <div>
                  <div class="text-xs text-slate-400">页面 / 接口</div>
                  <div class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(session.document_requests) }} / {{ formatNumber(session.api_requests) }}
                  </div>
                </div>
                <div>
                  <div class="text-xs text-slate-400">页面 / 接口重复率</div>
                  <div class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(session.document_repeated_ratio) }}% / {{ formatNumber(session.api_repeated_ratio) }}%
                  </div>
                </div>
              </div>
            </div>
            <div class="mt-3 text-xs text-slate-500">
              主路径 {{ session.dominant_route || '-' }} · 关注页面 {{ session.focused_document_route || '-' }} · 关注接口 {{ session.focused_api_route || '-' }}
            </div>
            <div
              v-if="liveProfilesByIdentity.get(session.identity)"
              class="mt-2 text-xs text-cyan-700"
            >
              当前画像分数 {{ formatNumber(liveProfilesByIdentity.get(session.identity)?.score || 0) }}
              · 当前路径 {{ liveProfilesByIdentity.get(session.identity)?.latest_route || '-' }}
            </div>
          </div>
        </div>
      </CyberCard>
    </div>
  </AppLayout>
</template>
