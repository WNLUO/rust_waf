<script setup lang="ts">
import AppLayout from '@/app/layout/AppLayout.vue'
import AdminAiAuditSection from '@/features/behavior/components/AdminAiAuditSection.vue'
import CyberCard from '@/shared/ui/CyberCard.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import { useAdminIntelligencePage } from '@/features/behavior/composables/useAdminIntelligencePage'
import {
  actionLabel,
  actionType,
  aiBusinessTypes,
  aiDecisionLabel,
  aiDecisionType,
  aiTopRoutes,
  aiVisitorStateLabel,
  aiVisitorStateType,
  currentStateLabel,
  currentStateType,
  pageEnd,
  pageStart,
} from '@/features/behavior/utils/intelligenceDisplay'
import { Fingerprint, RefreshCw, Route } from 'lucide-vue-next'

const {
  loading,
  refreshing,
  tab,
  livePage,
  fingerprintPage,
  sessionPage,
  fingerprintProfiles,
  behaviorSessions,
  liveProfiles,
  aiVisitorIntelligence,
  realtimeState,
  formatNumber,
  formatTimestamp,
  liveProfilesByIdentity,
  currentRiskCount,
  currentWatchingCount,
  currentHealthyCount,
  aiVisitorProfiles,
  aiVisitorRecommendations,
  aiPriorityVisitors,
  aiChallengeJsReports,
  aiAuthRejectedCount,
  aiBusinessTypeCount,
  liveTotalPages,
  fingerprintTotalPages,
  sessionTotalPages,
  pagedLiveProfiles,
  pagedFingerprintProfiles,
  pagedBehaviorSessions,
  statusLabel,
  goToLivePage,
  goToFingerprintPage,
  goToSessionPage,
  switchTab,
  loadPage,
} = useAdminIntelligencePage()
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <div class="flex items-center gap-3">
        <StatusBadge
          :type="
            realtimeState.connected
              ? 'success'
              : realtimeState.connecting
                ? 'info'
                : 'muted'
          "
          :text="statusLabel"
        />
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
    </template>

    <div class="space-y-5">
      <section class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <CyberCard no-padding>
          <div class="flex items-start justify-between px-5 py-4">
            <div>
              <p class="text-sm text-slate-500">当前活跃</p>
              <p class="mt-2 text-3xl font-semibold text-slate-900">
                {{ formatNumber(liveProfiles.length) }}
              </p>
            </div>
            <div class="rounded-md bg-slate-100 p-3 text-slate-600">
              <Fingerprint :size="18" />
            </div>
          </div>
        </CyberCard>
        <CyberCard no-padding>
          <div class="flex items-start justify-between px-5 py-4">
            <div>
              <p class="text-sm text-slate-500">当前高风险</p>
              <p class="mt-2 text-3xl font-semibold text-red-700">
                {{ formatNumber(currentRiskCount) }}
              </p>
            </div>
            <div class="rounded-md bg-red-50 p-3 text-red-700">
              <Route :size="18" />
            </div>
          </div>
        </CyberCard>
        <CyberCard no-padding>
          <div class="px-5 py-4">
            <p class="text-sm text-slate-500">当前观察中</p>
            <p class="mt-2 text-3xl font-semibold text-amber-700">
              {{ formatNumber(currentWatchingCount) }}
            </p>
          </div>
        </CyberCard>
        <CyberCard no-padding>
          <div class="px-5 py-4">
            <p class="text-sm text-slate-500">当前正常</p>
            <p class="mt-2 text-3xl font-semibold text-emerald-700">
              {{ formatNumber(currentHealthyCount) }}
            </p>
          </div>
        </CyberCard>
      </section>

      <CyberCard title="AI 访客智能">
        <template #header-action>
          <div class="flex flex-wrap items-center gap-2">
            <StatusBadge
              :type="aiVisitorIntelligence?.enabled ? 'info' : 'muted'"
              :text="
                aiVisitorIntelligence?.enabled ? 'AI 自动防御已启用' : '未启用'
              "
            />
            <StatusBadge
              v-if="aiVisitorIntelligence?.degraded_reason"
              type="warning"
              :text="aiVisitorIntelligence.degraded_reason"
            />
          </div>
        </template>

        <div v-if="loading" class="py-12 text-center text-sm text-slate-500">
          正在加载 AI 访客情报...
        </div>
        <div v-else class="space-y-4">
          <section class="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div class="rounded-md border border-slate-200 bg-slate-50 p-4">
              <p class="text-xs text-slate-500">活跃 AI 画像</p>
              <p class="mt-2 text-2xl font-semibold text-slate-900">
                {{
                  formatNumber(
                    aiVisitorIntelligence?.active_profile_count ||
                      aiVisitorProfiles.length,
                  )
                }}
              </p>
            </div>
            <div class="rounded-md border border-slate-200 bg-slate-50 p-4">
              <p class="text-xs text-slate-500">待执行建议</p>
              <p class="mt-2 text-2xl font-semibold text-amber-700">
                {{ formatNumber(aiVisitorRecommendations.length) }}
              </p>
            </div>
            <div class="rounded-md border border-slate-200 bg-slate-50 p-4">
              <p class="text-xs text-slate-500">挑战 JS 上报</p>
              <p class="mt-2 text-2xl font-semibold text-emerald-700">
                {{ formatNumber(aiChallengeJsReports) }}
              </p>
            </div>
            <div class="rounded-md border border-slate-200 bg-slate-50 p-4">
              <p class="text-xs text-slate-500">业务语义 / 拒绝</p>
              <p class="mt-2 text-2xl font-semibold text-slate-900">
                {{ formatNumber(aiBusinessTypeCount) }} /
                {{ formatNumber(aiAuthRejectedCount) }}
              </p>
            </div>
          </section>

          <div
            v-if="!aiVisitorProfiles.length"
            class="rounded-md border border-dashed border-slate-200 bg-slate-50 px-6 py-10 text-center text-sm text-slate-500"
          >
            暂无 AI 访客画像
          </div>
          <div v-else class="grid gap-4 xl:grid-cols-[minmax(0,1fr)_24rem]">
            <div class="divide-y divide-slate-200 rounded-md border border-slate-200">
              <article
                v-for="profile in aiPriorityVisitors"
                :key="`${profile.site_id}-${profile.identity_key}`"
                class="bg-white px-4 py-3"
              >
                <div class="flex flex-wrap items-center gap-2">
                  <StatusBadge
                    :type="aiVisitorStateType(profile)"
                    :text="aiVisitorStateLabel(profile)"
                  />
                  <StatusBadge
                    :type="
                      profile.false_positive_risk === 'high'
                        ? 'success'
                        : profile.tracking_priority === 'high'
                          ? 'warning'
                          : 'muted'
                    "
                    :text="`误伤 ${profile.false_positive_risk}`"
                  />
                  <span class="text-xs text-slate-500">
                    {{ formatTimestamp(profile.last_seen_at) }}
                  </span>
                </div>
                <div class="mt-2 font-mono text-sm text-slate-900 break-all">
                  {{ profile.identity_key }}
                </div>
                <div class="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
                  <span>IP {{ profile.client_ip || '-' }}</span>
                  <span>来源 {{ profile.identity_source }}</span>
                  <span>站点 {{ profile.site_id }}</span>
                </div>
                <div class="mt-3 grid grid-cols-2 gap-3 text-sm text-slate-600 md:grid-cols-4">
                  <div>
                    <p class="text-xs text-slate-400">人类 / 自动化</p>
                    <p class="mt-1 font-semibold text-slate-900">
                      {{ formatNumber(profile.human_confidence) }} /
                      {{ formatNumber(profile.automation_risk) }}
                    </p>
                  </div>
                  <div>
                    <p class="text-xs text-slate-400">探测 / 滥用</p>
                    <p class="mt-1 font-semibold text-slate-900">
                      {{ formatNumber(profile.probe_risk) }} /
                      {{ formatNumber(profile.abuse_risk) }}
                    </p>
                  </div>
                  <div>
                    <p class="text-xs text-slate-400">挑战 JS</p>
                    <p class="mt-1 font-semibold text-slate-900">
                      {{ formatNumber(profile.challenge_js_report_count) }} /
                      {{ formatNumber(profile.challenge_page_report_count) }}
                    </p>
                  </div>
                  <div>
                    <p class="text-xs text-slate-400">认证成功 / 拒绝</p>
                    <p class="mt-1 font-semibold text-slate-900">
                      {{ formatNumber(profile.auth_success_count) }} /
                      {{ formatNumber(profile.auth_rejected_count) }}
                    </p>
                  </div>
                </div>
                <div class="mt-3 flex flex-wrap gap-2">
                  <span
                    v-for="[type, count] in aiBusinessTypes(profile)"
                    :key="`${profile.identity_key}-${type}`"
                    class="rounded-md bg-cyan-50 px-2 py-1 text-xs font-medium text-cyan-700"
                  >
                    {{ type }} · {{ formatNumber(count) }}
                  </span>
                  <span
                    v-for="route in aiTopRoutes(profile)"
                    :key="`${profile.identity_key}-${route.route}`"
                    class="rounded-md bg-slate-100 px-2 py-1 text-xs font-medium text-slate-600"
                  >
                    {{ route.route }} · {{ formatNumber(route.count) }}
                  </span>
                </div>
              </article>
            </div>

            <div class="rounded-md border border-slate-200 bg-slate-50 p-4">
              <div class="flex items-center justify-between gap-3">
                <p class="text-sm font-semibold text-slate-900">AI 建议动作</p>
                <span class="text-xs text-slate-500">
                  {{ formatNumber(aiVisitorRecommendations.length) }}
                </span>
              </div>
              <div
                v-if="!aiVisitorRecommendations.length"
                class="mt-4 rounded-md border border-dashed border-slate-200 bg-white px-4 py-8 text-center text-sm text-slate-500"
              >
                当前没有访客级建议
              </div>
              <div v-else class="mt-3 space-y-3">
                <article
                  v-for="decision in aiVisitorRecommendations.slice(0, 5)"
                  :key="decision.decision_key"
                  class="rounded-md border border-slate-200 bg-white p-3"
                >
                  <div class="flex flex-wrap items-center gap-2">
                    <StatusBadge
                      :type="aiDecisionType(decision.action)"
                      :text="aiDecisionLabel(decision.action)"
                    />
                    <StatusBadge
                      :type="decision.applied ? 'success' : 'muted'"
                      :text="decision.applied ? '已应用' : decision.effect_status"
                    />
                  </div>
                  <p class="mt-2 font-mono text-xs text-slate-600 break-all">
                    {{ decision.identity_key }}
                  </p>
                  <p class="mt-2 text-xs leading-5 text-slate-500">
                    置信度 {{ formatNumber(decision.confidence) }} · TTL
                    {{ formatNumber(decision.ttl_secs) }}s
                  </p>
                </article>
              </div>
            </div>
          </div>
        </div>
      </CyberCard>

      <AdminAiAuditSection />

      <CyberCard title="实时画像">
        <div v-if="loading" class="py-12 text-center text-sm text-slate-500">
          正在加载实时状态...
        </div>
        <div
          v-else-if="!liveProfiles.length"
          class="rounded-md border border-dashed border-slate-200 bg-slate-50 px-6 py-12 text-center text-sm text-slate-500"
        >
          当前没有活跃画像
        </div>
        <div v-else>
          <div
            class="divide-y divide-slate-200 rounded-md border border-slate-200"
          >
            <article
              v-for="profile in pagedLiveProfiles"
              :key="profile.identity"
              class="grid gap-3 bg-white px-4 py-3 xl:grid-cols-[minmax(0,1fr)_28rem]"
            >
              <div class="min-w-0 space-y-2">
                <div class="flex flex-wrap items-center gap-2">
                  <StatusBadge
                    :type="currentStateType(profile)"
                    :text="currentStateLabel(profile)"
                  />
                  <StatusBadge
                    type="muted"
                    :text="`分数 ${formatNumber(profile.score || 0)}`"
                  />
                  <span class="text-xs text-slate-500">
                    {{ formatTimestamp(profile.latest_seen_at) }}
                  </span>
                </div>
                <div class="font-mono text-sm text-slate-900 break-all">
                  {{ profile.identity }}
                </div>
                <div
                  class="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500"
                >
                  <span>{{ profile.source_ip || '-' }}</span>
                  <span>当前路径 {{ profile.latest_route || '-' }}</span>
                  <span>主路径 {{ profile.dominant_route || '-' }}</span>
                </div>
                <div v-if="profile.blocked" class="text-xs text-red-700">
                  {{ profile.blocked_reason || '当前封禁中' }}
                  <template v-if="profile.blocked_expires_at">
                    · {{ formatTimestamp(profile.blocked_expires_at) }}
                  </template>
                </div>
              </div>
              <div
                class="grid grid-cols-2 gap-3 text-sm text-slate-600 md:grid-cols-4"
              >
                <div>
                  <p class="text-xs text-slate-400">总重复率</p>
                  <p class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(profile.repeated_ratio) }}%
                  </p>
                </div>
                <div>
                  <p class="text-xs text-slate-400">页面 / 接口</p>
                  <p class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(profile.document_requests) }} /
                    {{ formatNumber(profile.api_requests) }}
                  </p>
                </div>
                <div>
                  <p class="text-xs text-slate-400">不同路径</p>
                  <p class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(profile.distinct_routes) }}
                  </p>
                </div>
                <div>
                  <p class="text-xs text-slate-400">挑战数</p>
                  <p class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(profile.challenge_count_window) }}
                  </p>
                </div>
              </div>
            </article>
          </div>

          <div
            class="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-600"
          >
            <div>
              {{ pageStart(livePage, liveProfiles.length) }}-{{
                pageEnd(livePage, liveProfiles.length)
              }}
              / {{ formatNumber(liveProfiles.length) }}
            </div>
            <div class="flex items-center gap-2">
              <button
                class="rounded-md border border-slate-300 bg-white px-2 py-1 hover:bg-slate-50 disabled:opacity-50"
                :disabled="livePage <= 1"
                @click="goToLivePage(livePage - 1)"
              >
                上一页
              </button>
              <span>{{ livePage }} / {{ liveTotalPages }}</span>
              <button
                class="rounded-md border border-slate-300 bg-white px-2 py-1 hover:bg-slate-50 disabled:opacity-50"
                :disabled="livePage >= liveTotalPages"
                @click="goToLivePage(livePage + 1)"
              >
                下一页
              </button>
            </div>
          </div>
        </div>
      </CyberCard>

      <section class="flex flex-wrap gap-2">
        <button
          type="button"
          class="rounded-md px-4 py-2 text-sm font-medium transition"
          :class="
            tab === 'fingerprints'
              ? 'bg-slate-900 text-white'
              : 'border border-slate-200 bg-white text-slate-700'
          "
          @click="switchTab('fingerprints')"
        >
          指纹档案
        </button>
        <button
          type="button"
          class="rounded-md px-4 py-2 text-sm font-medium transition"
          :class="
            tab === 'sessions'
              ? 'bg-slate-900 text-white'
              : 'border border-slate-200 bg-white text-slate-700'
          "
          @click="switchTab('sessions')"
        >
          历史会话
        </button>
      </section>

      <CyberCard v-if="tab === 'fingerprints'" title="指纹档案">
        <div v-if="loading" class="py-12 text-center text-sm text-slate-500">
          正在加载档案...
        </div>
        <div
          v-else-if="!fingerprintProfiles.length"
          class="rounded-md border border-dashed border-slate-200 bg-slate-50 px-6 py-12 text-center text-sm text-slate-500"
        >
          暂无指纹档案
        </div>
        <div v-else>
          <div
            class="divide-y divide-slate-200 rounded-md border border-slate-200"
          >
            <article
              v-for="profile in pagedFingerprintProfiles"
              :key="profile.identity"
              class="grid gap-3 bg-white px-4 py-3 xl:grid-cols-[minmax(0,1fr)_24rem]"
            >
              <div class="min-w-0 space-y-2">
                <div class="flex flex-wrap items-center gap-2">
                  <StatusBadge
                    :type="
                      currentStateType(
                        liveProfilesByIdentity.get(profile.identity),
                      )
                    "
                    :text="
                      currentStateLabel(
                        liveProfilesByIdentity.get(profile.identity),
                      )
                    "
                  />
                  <StatusBadge
                    :type="actionType(profile.latest_action)"
                    :text="actionLabel(profile.latest_action)"
                  />
                  <span
                    class="rounded-md bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-700"
                  >
                    {{ profile.identity_kind }}
                  </span>
                  <span class="text-xs text-slate-500">
                    {{ formatTimestamp(profile.last_seen_at) }}
                  </span>
                </div>
                <div class="font-mono text-sm text-slate-900 break-all">
                  {{ profile.identity }}
                </div>
                <div
                  class="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500"
                >
                  <span>IP {{ profile.source_ip || '-' }}</span>
                  <span>站点 {{ profile.last_site_domain || '-' }}</span>
                  <span
                    v-if="liveProfilesByIdentity.get(profile.identity)"
                    class="text-cyan-700"
                  >
                    当前分数
                    {{
                      formatNumber(
                        liveProfilesByIdentity.get(profile.identity)?.score ||
                          0,
                      )
                    }}
                  </span>
                </div>
              </div>
              <div
                class="grid grid-cols-2 gap-3 text-sm text-slate-600 md:grid-cols-4"
              >
                <div>
                  <p class="text-xs text-slate-400">安全事件</p>
                  <p class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(profile.total_security_events) }}
                  </p>
                </div>
                <div>
                  <p class="text-xs text-slate-400">行为事件</p>
                  <p class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(profile.total_behavior_events) }}
                  </p>
                </div>
                <div>
                  <p class="text-xs text-slate-400">挑战 / 封禁</p>
                  <p class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(profile.total_challenges) }} /
                    {{ formatNumber(profile.total_blocks) }}
                  </p>
                </div>
                <div>
                  <p class="text-xs text-slate-400">最新 / 最高分</p>
                  <p class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(profile.latest_score || 0) }} /
                    {{ formatNumber(profile.max_score) }}
                  </p>
                </div>
              </div>
            </article>
          </div>

          <div
            class="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-600"
          >
            <div>
              {{ pageStart(fingerprintPage, fingerprintProfiles.length) }}-{{
                pageEnd(fingerprintPage, fingerprintProfiles.length)
              }}
              / {{ formatNumber(fingerprintProfiles.length) }}
            </div>
            <div class="flex items-center gap-2">
              <button
                class="rounded-md border border-slate-300 bg-white px-2 py-1 hover:bg-slate-50 disabled:opacity-50"
                :disabled="fingerprintPage <= 1"
                @click="goToFingerprintPage(fingerprintPage - 1)"
              >
                上一页
              </button>
              <span>{{ fingerprintPage }} / {{ fingerprintTotalPages }}</span>
              <button
                class="rounded-md border border-slate-300 bg-white px-2 py-1 hover:bg-slate-50 disabled:opacity-50"
                :disabled="fingerprintPage >= fingerprintTotalPages"
                @click="goToFingerprintPage(fingerprintPage + 1)"
              >
                下一页
              </button>
            </div>
          </div>
        </div>
      </CyberCard>

      <CyberCard v-else title="历史会话">
        <div v-if="loading" class="py-12 text-center text-sm text-slate-500">
          正在加载会话...
        </div>
        <div
          v-else-if="!behaviorSessions.length"
          class="rounded-md border border-dashed border-slate-200 bg-slate-50 px-6 py-12 text-center text-sm text-slate-500"
        >
          暂无历史会话
        </div>
        <div v-else>
          <div
            class="divide-y divide-slate-200 rounded-md border border-slate-200"
          >
            <article
              v-for="session in pagedBehaviorSessions"
              :key="session.session_key"
              class="grid gap-3 bg-white px-4 py-3 xl:grid-cols-[minmax(0,1fr)_28rem]"
            >
              <div class="min-w-0 space-y-2">
                <div class="flex flex-wrap items-center gap-2">
                  <StatusBadge
                    :type="
                      currentStateType(
                        liveProfilesByIdentity.get(session.identity),
                      )
                    "
                    :text="
                      currentStateLabel(
                        liveProfilesByIdentity.get(session.identity),
                      )
                    "
                  />
                  <StatusBadge
                    :type="actionType(session.latest_action)"
                    :text="actionLabel(session.latest_action)"
                  />
                  <span class="text-xs text-slate-500">
                    {{ formatTimestamp(session.last_seen_at) }}
                  </span>
                </div>
                <div class="font-mono text-sm text-slate-900 break-all">
                  {{ session.identity }}
                </div>
                <div
                  class="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500"
                >
                  <span>{{ session.site_domain || '-' }}</span>
                  <span>{{ session.source_ip || '-' }}</span>
                  <span>{{ session.latest_uri || '-' }}</span>
                </div>
                <div class="text-xs text-slate-500">
                  主路径 {{ session.dominant_route || '-' }} · 关注页面
                  {{ session.focused_document_route || '-' }} · 关注接口
                  {{ session.focused_api_route || '-' }}
                </div>
              </div>
              <div
                class="grid grid-cols-2 gap-3 text-sm text-slate-600 md:grid-cols-4"
              >
                <div>
                  <p class="text-xs text-slate-400">事件数</p>
                  <p class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(session.event_count) }}
                  </p>
                </div>
                <div>
                  <p class="text-xs text-slate-400">挑战 / 封禁</p>
                  <p class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(session.challenge_count) }} /
                    {{ formatNumber(session.block_count) }}
                  </p>
                </div>
                <div>
                  <p class="text-xs text-slate-400">页面 / 接口</p>
                  <p class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(session.document_requests) }} /
                    {{ formatNumber(session.api_requests) }}
                  </p>
                </div>
                <div>
                  <p class="text-xs text-slate-400">重复率</p>
                  <p class="mt-1 font-semibold text-slate-900">
                    {{ formatNumber(session.document_repeated_ratio) }}% /
                    {{ formatNumber(session.api_repeated_ratio) }}%
                  </p>
                </div>
              </div>
            </article>
          </div>

          <div
            class="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-600"
          >
            <div>
              {{ pageStart(sessionPage, behaviorSessions.length) }}-{{
                pageEnd(sessionPage, behaviorSessions.length)
              }}
              / {{ formatNumber(behaviorSessions.length) }}
            </div>
            <div class="flex items-center gap-2">
              <button
                class="rounded-md border border-slate-300 bg-white px-2 py-1 hover:bg-slate-50 disabled:opacity-50"
                :disabled="sessionPage <= 1"
                @click="goToSessionPage(sessionPage - 1)"
              >
                上一页
              </button>
              <span>{{ sessionPage }} / {{ sessionTotalPages }}</span>
              <button
                class="rounded-md border border-slate-300 bg-white px-2 py-1 hover:bg-slate-50 disabled:opacity-50"
                :disabled="sessionPage >= sessionTotalPages"
                @click="goToSessionPage(sessionPage + 1)"
              >
                下一页
              </button>
            </div>
          </div>
        </div>
      </CyberCard>
    </div>
  </AppLayout>
</template>
