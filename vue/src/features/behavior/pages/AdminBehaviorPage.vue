<script setup lang="ts">
import { RouterLink } from 'vue-router'
import AppLayout from '@/app/layout/AppLayout.vue'
import CyberCard from '@/shared/ui/CyberCard.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import {
  Activity,
  Ban,
  Fingerprint,
  RefreshCw,
  ShieldAlert,
} from 'lucide-vue-next'
import { useAdminBehaviorPage } from '@/features/behavior/composables/useAdminBehaviorPage'

const {
  formatNumber,
  formatTimestamp,
  realtimeState,
  loading,
  refreshing,
  metrics,
  selectedProfileKey,
  profiles,
  selectedProfile,
  selectedProfileEvents,
  statusLabel,
  actionBadgeType,
  actionLabel,
  currentStateType,
  currentStateLabel,
  loadPage,
} = useAdminBehaviorPage()
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
          刷新观测
        </button>
      </div>
    </template>

    <div class="space-y-6">
      <section class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <CyberCard no-padding>
          <div class="flex items-start justify-between px-5 py-4">
            <div>
              <p class="text-sm text-slate-500">活跃身份</p>
              <p class="mt-2 text-3xl font-semibold text-slate-900">
                {{ formatNumber(profiles.length) }}
              </p>
              <p class="mt-2 text-xs text-slate-500">最近活跃会话的实时快照</p>
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
                指当前累计次数，不等于当前仍在挑战
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
                指历史累计次数，不等于当前仍在封禁
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
                指历史累计次数，不等于当前仍在延迟
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
          title="活跃会话画像"
          sub-title="这里只看当前活跃画像，顶部标签表示当前状态，不直接复用历史事件动作"
        >
          <div v-if="loading" class="py-16 text-center text-sm text-slate-500">
            正在加载行为画像...
          </div>
          <div
            v-else-if="!profiles.length"
            class="rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-6 py-12 text-center text-sm text-slate-500"
          >
            还没有采集到活跃会话。等页面有访问进来，这里会自动出现画像。
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
              <div
                class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between"
              >
                <div class="min-w-0 space-y-2">
                  <div class="flex flex-wrap items-center gap-2">
                    <StatusBadge
                      :type="currentStateType(profile)"
                      :text="currentStateLabel(profile)"
                    />
                    <StatusBadge
                      v-if="profile.blocked"
                      type="error"
                      text="封禁名单中"
                    />
                    <StatusBadge
                      v-else
                      type="muted"
                      :text="`历史动作 ${actionLabel(profile.latestAction)}`"
                    />
                    <span
                      class="rounded-full bg-slate-900 px-2.5 py-0.5 text-xs font-medium text-white"
                    >
                      当前分数 {{ formatNumber(profile.maxScore) }}
                    </span>
                    <span class="text-xs text-slate-500">
                      最近活跃 {{ formatTimestamp(profile.latestSeenAt) }}
                    </span>
                  </div>
                  <div class="font-mono text-sm text-slate-900 break-all">
                    {{ profile.identity }}
                  </div>
                  <div
                    class="flex flex-wrap items-center gap-3 text-xs text-slate-500"
                  >
                    <span>源 IP {{ profile.sourceIp }}</span>
                    <span>主路径 {{ profile.dominantRoute }}</span>
                    <span>最近 URI {{ profile.latestUri }}</span>
                  </div>
                </div>
                <div
                  class="grid grid-cols-2 gap-3 text-sm text-slate-600 lg:min-w-[18rem]"
                >
                  <div>
                    <div class="text-xs text-slate-400">历史事件数</div>
                    <div class="mt-1 font-semibold text-slate-900">
                      {{ formatNumber(profile.eventCount) }}
                    </div>
                  </div>
                  <div>
                    <div class="text-xs text-slate-400">历史挑战 / 封禁</div>
                    <div class="mt-1 font-semibold text-slate-900">
                      {{ formatNumber(profile.challengeCount) }} /
                      {{ formatNumber(profile.blockCount) }}
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
                    <div class="text-xs text-slate-400">接口重复率</div>
                    <div class="mt-1 font-semibold text-slate-900">
                      {{ formatNumber(profile.apiRepeatedRatio) }}%
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
          sub-title="先看当前状态，再把历史异常线索拆成你能直接读懂的字段"
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
                  :type="currentStateType(selectedProfile)"
                  :text="currentStateLabel(selectedProfile)"
                />
                <StatusBadge
                  v-if="selectedProfile.blocked"
                  type="error"
                  :text="
                    selectedProfile.blockedExpiresAt
                      ? `已封禁至 ${formatTimestamp(selectedProfile.blockedExpiresAt)}`
                      : '已进入封禁名单'
                  "
                />
                <StatusBadge
                  v-else
                  type="muted"
                  :text="`历史动作 ${actionLabel(selectedProfile.latestAction)}`"
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
                <div class="text-xs uppercase tracking-[0.18em] text-slate-400">
                  路径画像
                </div>
                <div class="mt-3 text-sm text-slate-600">
                  主路径
                  <span class="font-semibold text-slate-900">{{
                    selectedProfile.dominantRoute
                  }}</span>
                </div>
                <div class="mt-2 text-sm text-slate-600">
                  路径多样性
                  <span class="font-semibold text-slate-900">{{
                    formatNumber(selectedProfile.distinctRoutes)
                  }}</span>
                </div>
                <div class="mt-2 text-sm text-slate-600">
                  重复率峰值
                  <span class="font-semibold text-slate-900"
                    >{{ formatNumber(selectedProfile.maxRepeatedRatio) }}%</span
                  >
                </div>
                <div class="mt-2 text-sm text-slate-600">
                  页面重载率
                  <span class="font-semibold text-slate-900"
                    >{{
                      formatNumber(selectedProfile.maxDocumentRepeatedRatio)
                    }}%</span
                  >
                </div>
                <div class="mt-2 text-sm text-slate-600">
                  关注页面
                  <span class="font-semibold text-slate-900">{{
                    selectedProfile.focusedDocumentRoute
                  }}</span>
                </div>
                <div class="mt-2 text-sm text-slate-600">
                  关注接口
                  <span class="font-semibold text-slate-900">{{
                    selectedProfile.focusedApiRoute
                  }}</span>
                </div>
              </div>

              <div class="rounded-2xl bg-slate-50 p-4">
                <div class="text-xs uppercase tracking-[0.18em] text-slate-400">
                  请求形状
                </div>
                <div class="mt-3 text-sm text-slate-600">
                  页面请求
                  <span class="font-semibold text-slate-900">{{
                    formatNumber(selectedProfile.documentRequests)
                  }}</span>
                </div>
                <div class="mt-2 text-sm text-slate-600">
                  接口请求
                  <span class="font-semibold text-slate-900">{{
                    formatNumber(selectedProfile.apiRequests)
                  }}</span>
                </div>
                <div class="mt-2 text-sm text-slate-600">
                  接口重复率
                  <span class="font-semibold text-slate-900"
                    >{{ formatNumber(selectedProfile.apiRepeatedRatio) }}%</span
                  >
                </div>
                <div class="mt-2 text-sm text-slate-600">
                  非页面请求
                  <span class="font-semibold text-slate-900">{{
                    formatNumber(selectedProfile.nonDocumentRequests)
                  }}</span>
                </div>
                <div class="mt-2 text-sm text-slate-600">
                  节奏抖动
                  <span class="font-semibold text-slate-900">
                    {{
                      selectedProfile.intervalJitterMs === null
                        ? '未采样'
                        : `${formatNumber(selectedProfile.intervalJitterMs)} ms`
                    }}
                  </span>
                </div>
                <div class="mt-2 text-sm text-slate-600">
                  会话跨度
                  <span class="font-semibold text-slate-900"
                    >{{ formatNumber(selectedProfile.sessionSpanSecs) }} s</span
                  >
                </div>
              </div>
            </div>

            <div
              v-if="selectedProfile.blocked"
              class="rounded-2xl border border-red-200 bg-red-50/70 p-4"
            >
              <div class="text-xs uppercase tracking-[0.18em] text-red-700">
                封禁状态
              </div>
              <div class="mt-3 grid gap-2 text-sm text-red-900 sm:grid-cols-2">
                <div>
                  封禁开始
                  <span class="font-semibold">
                    {{
                      selectedProfile.blockedAt
                        ? formatTimestamp(selectedProfile.blockedAt)
                        : '-'
                    }}
                  </span>
                </div>
                <div>
                  封禁结束
                  <span class="font-semibold">
                    {{
                      selectedProfile.blockedExpiresAt
                        ? formatTimestamp(selectedProfile.blockedExpiresAt)
                        : '-'
                    }}
                  </span>
                </div>
                <div class="sm:col-span-2">
                  封禁原因
                  <span class="font-semibold">{{
                    selectedProfile.blockedReason
                  }}</span>
                </div>
              </div>
            </div>

            <div
              v-if="selectedProfile.flags.length"
              class="rounded-2xl bg-amber-50/70 p-4"
            >
              <div class="text-xs uppercase tracking-[0.18em] text-amber-700">
                命中标签
              </div>
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
                <h3 class="text-sm font-semibold text-slate-900">
                  历史异常轨迹
                </h3>
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
                    <span
                      class="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-700"
                    >
                      score {{ formatNumber(event.score) }}
                    </span>
                  </div>
                  <div class="text-sm font-medium text-slate-900">
                    {{ event.method }} {{ event.uri }}
                  </div>
                  <div class="text-xs text-slate-500">
                    dominant {{ event.dominantRoute }} · repeat
                    {{ formatNumber(event.repeatedRatio) }}% · doc-repeat
                    {{ formatNumber(event.documentRepeatedRatio) }}% · routes
                    {{ formatNumber(event.distinctRoutes) }}
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
