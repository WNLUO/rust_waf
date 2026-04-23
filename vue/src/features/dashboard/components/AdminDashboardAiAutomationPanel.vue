<script setup lang="ts">
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import type {
  AiAutomationOverviewResponse,
  AiAuditPolicyFeedback,
} from '@/shared/types'

type BadgeType = 'success' | 'warning' | 'error' | 'muted' | 'info'

type SummaryStat = {
  label: string
  value: string
  class?: string
}

type MetaBadge = {
  text: string
  type: BadgeType
}

type PressureRow = {
  label: string
  value: number
  color: string
}

type TrendBar = {
  label: string
  value: number
  color: string
}

type TrendWindow = {
  label: string
  labelText: string
  total_events: number
  blocked_events: number
  challenged_events: number
  delayed_events: number
  bars: TrendBar[]
}

defineProps<{
  overview: AiAutomationOverviewResponse | null
  statusLabel: string
  statusType: BadgeType
  lastRunLabel: string
  stats: SummaryStat[]
  secondaryStats: SummaryStat[]
  metaBadges: MetaBadge[]
  pressureRows: PressureRow[]
  defenseStageReasonTags: string[]
  trendWindows: TrendWindow[]
  trendMax: number
  visiblePolicyFeedback: AiAuditPolicyFeedback[]
  hiddenPolicyFeedbackCount: number
  policyFeedbackExpanded: boolean
  providerLabel: (value?: string) => string
  pressureLabel: (value?: string) => string
  formatPercent: (value?: number) => string
  clampPercent: (value: number) => number
  formatNumber: (value: number) => string
  formatPolicyTime: (value?: number | null) => string
  aiPolicyTitle: (policy: AiAuditPolicyFeedback) => string
  aiPolicyDetailLine: (policy: AiAuditPolicyFeedback) => string
  aiPolicyStatusLabel: (value?: string) => string
}>()

defineEmits<{
  'update:policyFeedbackExpanded': [value: boolean]
}>()
</script>

<template>
  <div
    class="relative min-w-0 overflow-hidden rounded-xl border border-slate-200 bg-white px-3 py-2.5 shadow-sm"
  >
    <div
      class="pointer-events-none absolute inset-x-0 top-0 h-16 bg-gradient-to-b from-blue-50/80 to-transparent"
    ></div>
    <div class="relative flex min-w-0 items-start justify-between gap-3">
      <div
        class="grid min-w-0 flex-1 grid-cols-[auto_minmax(0,1fr)] items-center gap-x-3 gap-y-1 pr-2"
      >
        <p class="truncate text-xs font-semibold text-slate-950">AI自动化</p>
        <div
          class="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-slate-500"
        >
          <span>{{ providerLabel(overview?.provider) }}</span>
          <span class="text-slate-300">/</span>
          <span>{{ overview?.auto_apply_temp_policies ? '自动应用' : '仅建议' }}</span>
          <span class="text-slate-300">/</span>
          <span>{{ pressureLabel(overview?.runtime_pressure_level) }}</span>
          <span class="text-slate-300">/</span>
          <span class="font-medium text-slate-700">
            上次运行 {{ lastRunLabel }}
          </span>
        </div>
      </div>
      <StatusBadge :text="statusLabel" :type="statusType" compact />
    </div>

    <div class="relative mt-2 flex flex-wrap gap-1.5">
      <StatusBadge
        v-for="badge in metaBadges"
        :key="badge.text"
        :text="badge.text"
        :type="badge.type"
        compact
      />
    </div>

    <div
      class="relative mx-auto mt-3 grid w-full max-w-[42rem] grid-cols-3 gap-2 text-center md:grid-cols-6"
    >
      <div v-for="item in stats" :key="item.label" class="min-w-0">
        <p class="truncate text-[10px] text-slate-500">{{ item.label }}</p>
        <p
          class="mt-0.5 truncate text-sm font-semibold text-slate-950"
          :class="item.class"
          :title="item.value"
        >
          {{ item.value }}
        </p>
      </div>
    </div>

    <div
      class="relative mx-auto mt-2 grid w-full max-w-[42rem] grid-cols-3 gap-2 text-center md:grid-cols-6"
    >
      <div v-for="item in secondaryStats" :key="item.label" class="min-w-0">
        <p class="truncate text-[10px] text-slate-500">{{ item.label }}</p>
        <p
          class="mt-0.5 truncate text-sm font-semibold text-slate-900"
          :class="item.class"
          :title="item.value"
        >
          {{ item.value }}
        </p>
      </div>
    </div>

    <div v-if="defenseStageReasonTags.length" class="relative mt-3">
      <div class="mb-1 flex items-center justify-between text-[11px]">
        <span class="font-medium text-slate-700">档位原因</span>
        <span class="text-slate-400">{{
          formatNumber(defenseStageReasonTags.length)
        }} 条</span>
      </div>
      <div class="flex flex-wrap gap-1.5">
        <span
          v-for="tag in defenseStageReasonTags"
          :key="tag"
          class="max-w-full truncate rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[10px] text-slate-600"
          :title="tag"
        >
          {{ tag }}
        </span>
      </div>
    </div>

    <div class="relative mt-3 grid grid-cols-3 gap-3">
      <div v-for="row in pressureRows" :key="row.label" class="min-w-0 text-[11px]">
        <div class="mb-1 flex min-w-0 items-center justify-between gap-2">
          <span class="truncate text-slate-500">{{ row.label }}</span>
          <span class="shrink-0 font-semibold text-slate-800">
            {{ formatPercent(row.value) }}
          </span>
        </div>
        <div class="h-1.5 overflow-hidden rounded-full bg-slate-100">
          <div
            class="h-full rounded-full"
            :class="row.color"
            :style="{ width: `${clampPercent(row.value)}%` }"
          ></div>
        </div>
      </div>
    </div>

    <div
      class="relative mt-3 grid gap-3 border-t border-slate-100 pt-2 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]"
    >
      <div class="min-w-0">
        <div class="mb-1.5 flex items-center justify-between text-[11px]">
          <span class="font-medium text-slate-700">AI判定窗口</span>
          <span class="text-slate-400">
            {{ formatNumber(overview?.active_rules || 0) }} 条规则
          </span>
        </div>
        <div class="grid grid-cols-3 gap-1.5">
          <div
            v-for="window in trendWindows"
            :key="window.label"
            class="min-w-0"
            :title="`${window.labelText}: ${formatNumber(window.total_events)} 事件 / ${formatNumber(window.blocked_events)} 拦截 / ${formatNumber(window.challenged_events)} 挑战 / ${formatNumber(window.delayed_events)} 延迟`"
          >
            <div class="flex h-9 items-end gap-0.5">
              <span
                v-for="bar in window.bars"
                :key="bar.label"
                class="block min-h-1 flex-1 rounded-sm"
                :class="bar.color"
                :style="{
                  height: `${Math.max(4, (bar.value / trendMax) * 36)}px`,
                  opacity: bar.value > 0 ? 1 : 0.25,
                }"
              ></span>
            </div>
            <span
              class="mx-auto mt-1 block max-w-full truncate text-center text-[10px] text-slate-500"
            >
              {{ window.labelText }}
            </span>
            <div class="mt-0.5 grid grid-cols-2 gap-x-1 gap-y-0.5 text-[10px]">
              <span
                v-for="bar in window.bars"
                :key="`${bar.label}-value`"
                class="flex min-w-0 justify-between gap-1 text-slate-500"
              >
                <span class="truncate">{{ bar.label }}</span>
                <span class="font-semibold text-slate-800">
                  {{ formatNumber(bar.value) }}
                </span>
              </span>
            </div>
          </div>
          <div
            v-if="!trendWindows.length"
            class="col-span-3 grid min-h-[3.4rem] place-items-center text-[11px] text-slate-400"
          >
            暂无趋势样本
          </div>
        </div>
      </div>

      <div class="min-w-0">
        <div class="mb-1.5 flex items-center justify-between text-[11px]">
          <span class="font-medium text-slate-700">策略反馈</span>
          <span class="text-slate-400">
            {{ formatNumber(overview?.recent_policy_feedback.length || 0) }}
            条<span v-if="hiddenPolicyFeedbackCount > 0">
              · 还有{{ formatNumber(hiddenPolicyFeedbackCount) }}条</span
            >
          </span>
        </div>
        <div
          class="grid gap-1.5"
          :class="
            policyFeedbackExpanded ? 'max-h-[5.75rem] overflow-y-auto pr-1' : ''
          "
        >
          <div
            v-for="policy in visiblePolicyFeedback"
            :key="policy.policy_key"
            class="grid min-w-0 grid-cols-[minmax(0,1fr)_auto_auto_auto] items-center gap-2 border-b border-slate-100 pb-1.5 text-[11px] last:border-b-0 last:pb-0"
          >
            <span
              class="min-w-0 truncate font-medium leading-4 text-slate-800"
              :title="aiPolicyDetailLine(policy) || aiPolicyTitle(policy)"
            >
              {{ aiPolicyTitle(policy) }}
            </span>
            <span
              class="shrink-0 whitespace-nowrap rounded-full bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-600"
              :title="aiPolicyStatusLabel(policy.action_status)"
            >
              {{ aiPolicyStatusLabel(policy.action_status) }}
            </span>
            <span class="shrink-0 whitespace-nowrap text-[10px] font-semibold text-slate-900">
              {{ formatNumber(policy.hit_count) }} 命中
            </span>
            <span
              class="shrink-0 whitespace-nowrap text-right text-[10px] text-slate-500"
              :title="formatPolicyTime(policy.updated_at)"
            >
              {{ formatPolicyTime(policy.updated_at) }}
            </span>
          </div>
          <div
            v-if="!(overview?.recent_policy_feedback || []).length"
            class="grid min-h-[3.4rem] place-items-center text-[11px] text-slate-400"
          >
            暂无自动策略命中
          </div>
        </div>
        <button
          v-if="(overview?.recent_policy_feedback.length || 0) > 2"
          type="button"
          class="mt-1 h-6 w-full rounded-md border border-slate-200 bg-white text-[11px] font-medium text-slate-600 transition hover:border-blue-200 hover:bg-blue-50 hover:text-blue-700"
          @click="
            $emit('update:policyFeedbackExpanded', !policyFeedbackExpanded)
          "
        >
          {{
            policyFeedbackExpanded
              ? '收起'
              : `查看更多 ${formatNumber(hiddenPolicyFeedbackCount)} 条`
          }}
        </button>
      </div>
    </div>
  </div>
</template>
