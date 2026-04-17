<script setup lang="ts">
/* eslint-disable vue/no-mutating-props */
import { computed } from 'vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import type { AiAuditReportHistoryItem } from '@/shared/types'

type FeedbackFilter =
  | 'all'
  | 'unreviewed'
  | 'confirmed'
  | 'false_positive'
  | 'follow_up'
type TriggerReasonFilter =
  | 'all'
  | 'auto'
  | 'manual'
  | 'pressure'
  | 'attack'
  | 'hotspot'
type FeedbackStatus = 'confirmed' | 'false_positive' | 'follow_up'
type AutoAuditTimelineItem = {
  id: number
  generated_at: number
  risk_level: string
  headline: string
  trigger_reason: string
  provider_used: string
  fallback_used: boolean
}

const props = defineProps<{
  feedbackFilter: FeedbackFilter
  triggerReasonFilter: TriggerReasonFilter
  historyTotal: number
  historyLoading: boolean
  filteredReportHistory: AiAuditReportHistoryItem[]
  autoAuditTimeline: AutoAuditTimelineItem[]
  compareReportId: number | null
  feedbackNotes: Record<number, string>
  updatingFeedbackId: number | null
  formatNumber: (value?: number) => string
  formatTimestamp: (value?: number) => string
  riskLevelLabel: (value: string | null | undefined) => string
  providerLabel: (value: string | null | undefined) => string
  feedbackStatusLabel: (value: string | null | undefined) => string
  describeAutoTriggerReason: (value: string | null | undefined) => string
  triggerReasonFilterLabel: (value: TriggerReasonFilter) => string
  useHistoryReport: (item: AiAuditReportHistoryItem) => unknown
  pinCompareReport: (item: AiAuditReportHistoryItem) => unknown
  updateFeedback: (reportId: number, status: FeedbackStatus) => unknown
}>()

const emit = defineEmits<{
  'update:feedbackFilter': [value: FeedbackFilter]
  'update:triggerReasonFilter': [value: TriggerReasonFilter]
}>()

const feedbackFilterModel = computed({
  get: () => props.feedbackFilter,
  set: (value) => emit('update:feedbackFilter', value),
})

const triggerReasonFilterModel = computed({
  get: () => props.triggerReasonFilter,
  set: (value) => emit('update:triggerReasonFilter', value),
})
</script>

<template>
  <section class="rounded-2xl border border-slate-200 bg-white p-4">
    <div
      class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
    >
      <div>
        <p class="text-sm font-semibold text-slate-900">审计历史与人工反馈</p>
        <p class="mt-1 text-xs leading-5 text-slate-500">
          最近的 AI
          审计报告会自动落库。你可以在这里把结论标成已确认、误报或待跟进，给后续调优留反馈样本。
        </p>
      </div>
      <div class="flex items-center gap-2">
        <select
          v-model="feedbackFilterModel"
          class="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
        >
          <option value="all">全部</option>
          <option value="unreviewed">未标记</option>
          <option value="confirmed">已确认</option>
          <option value="false_positive">误报</option>
          <option value="follow_up">待跟进</option>
        </select>
        <select
          v-model="triggerReasonFilterModel"
          class="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
        >
          <option value="all">全部触发</option>
          <option value="auto">自动触发</option>
          <option value="manual">手动执行</option>
          <option value="pressure">高压力</option>
          <option value="attack">攻击模式</option>
          <option value="hotspot">热点变化</option>
        </select>
        <StatusBadge
          type="muted"
          :text="`历史 ${formatNumber(filteredReportHistory.length)} / ${formatNumber(historyTotal)}`"
        />
      </div>
    </div>

    <div
      v-if="autoAuditTimeline.length"
      class="mt-4 rounded-2xl border border-cyan-200 bg-[linear-gradient(135deg,rgba(248,250,252,0.96),rgba(236,254,255,0.92))] px-4 py-4"
    >
      <div class="flex flex-wrap items-center gap-2">
        <StatusBadge type="info" text="自动审计时间线" />
        <StatusBadge
          type="muted"
          :text="`筛选 ${triggerReasonFilterLabel(triggerReasonFilterModel)}`"
        />
      </div>
      <div class="mt-4 space-y-3">
        <article
          v-for="item in autoAuditTimeline"
          :key="`timeline-${item.id}`"
          class="rounded-2xl border border-white/80 bg-white/85 px-4 py-3"
        >
          <div class="flex flex-wrap items-center gap-2">
            <StatusBadge
              :type="
                item.risk_level === 'high' || item.risk_level === 'critical'
                  ? 'error'
                  : item.risk_level === 'medium'
                    ? 'warning'
                    : 'success'
              "
              :text="riskLevelLabel(item.risk_level)"
            />
            <StatusBadge type="info" text="自动触发" />
            <StatusBadge
              type="muted"
              :text="providerLabel(item.provider_used)"
            />
            <StatusBadge
              v-if="item.fallback_used"
              type="warning"
              text="已回退执行"
            />
          </div>
          <p class="mt-2 text-sm font-semibold text-slate-900">
            {{ item.headline }}
          </p>
          <p class="mt-1 text-xs text-slate-500">
            {{ formatTimestamp(item.generated_at) }} ·
            {{ item.trigger_reason }}
          </p>
        </article>
      </div>
    </div>

    <div v-if="historyLoading" class="py-12 text-center text-sm text-slate-500">
      正在加载 AI 审计历史...
    </div>
    <div
      v-else-if="!filteredReportHistory.length"
      class="py-12 text-center text-sm text-slate-500"
    >
      当前筛选条件下没有历史审计报告
    </div>
    <div v-else class="mt-4 space-y-4">
      <article
        v-for="item in filteredReportHistory"
        :key="item.id"
        class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-4"
      >
        <div
          class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between"
        >
          <div class="space-y-2 min-w-0">
            <div class="flex flex-wrap items-center gap-2">
              <StatusBadge
                :type="
                  item.risk_level === 'high' || item.risk_level === 'critical'
                    ? 'error'
                    : item.risk_level === 'medium'
                      ? 'warning'
                      : 'success'
                "
                :text="riskLevelLabel(item.risk_level)"
              />
              <StatusBadge
                type="muted"
                :text="providerLabel(item.provider_used)"
              />
              <StatusBadge
                v-if="item.feedback_status"
                type="info"
                :text="`反馈 ${feedbackStatusLabel(item.feedback_status)}`"
              />
              <StatusBadge
                v-if="item.fallback_used"
                type="warning"
                text="已回退执行"
              />
              <StatusBadge
                v-if="compareReportId === item.id"
                type="info"
                text="当前对比基线"
              />
              <StatusBadge
                v-if="item.auto_generated"
                type="info"
                text="自动触发"
              />
              <StatusBadge
                v-if="item.auto_trigger_reason"
                type="warning"
                :text="describeAutoTriggerReason(item.auto_trigger_reason)"
              />
            </div>
            <p class="text-sm font-semibold text-slate-900">
              {{ item.headline }}
            </p>
            <p class="text-xs text-slate-500">
              生成于 {{ formatTimestamp(item.generated_at) }}
              <template v-if="item.feedback_updated_at">
                · 反馈更新时间
                {{ formatTimestamp(item.feedback_updated_at) }}
              </template>
            </p>
            <p
              v-if="item.report.executive_summary.length"
              class="text-sm leading-6 text-slate-700"
            >
              {{ item.report.executive_summary[0] }}
            </p>
          </div>
          <div
            class="grid grid-cols-3 gap-3 text-sm text-slate-600 lg:min-w-[18rem]"
          >
            <div>
              <div class="text-xs text-slate-400">发现问题</div>
              <div class="mt-1 font-semibold text-slate-900">
                {{ formatNumber(item.report.findings.length) }}
              </div>
            </div>
            <div>
              <div class="text-xs text-slate-400">建议动作</div>
              <div class="mt-1 font-semibold text-slate-900">
                {{ formatNumber(item.report.recommendations.length) }}
              </div>
            </div>
            <div>
              <div class="text-xs text-slate-400">采样事件</div>
              <div class="mt-1 font-semibold text-slate-900">
                {{ formatNumber(item.report.summary.sampled_events) }}
              </div>
            </div>
          </div>
        </div>

        <div class="mt-3 grid gap-3 xl:grid-cols-[minmax(0,1fr)_auto]">
          <textarea
            v-model="feedbackNotes[item.id]"
            class="min-h-[5.5rem] w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
            placeholder="给这次 AI 审计补一条人工备注，例如为什么确认、为什么认为是误报。"
          />
          <div class="flex flex-wrap items-start gap-2">
            <button
              type="button"
              class="rounded-full border border-cyan-200 bg-cyan-50 px-3 py-2 text-xs font-medium text-cyan-700 transition hover:bg-cyan-100"
              @click="useHistoryReport(item)"
            >
              查看这份报告
            </button>
            <button
              type="button"
              class="rounded-full border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700 transition hover:border-slate-300 hover:text-slate-900"
              @click="pinCompareReport(item)"
            >
              设为对比基线
            </button>
            <button
              type="button"
              class="rounded-full border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs font-medium text-emerald-700 transition hover:bg-emerald-100 disabled:opacity-60"
              :disabled="updatingFeedbackId === item.id"
              @click="updateFeedback(item.id, 'confirmed')"
            >
              标记已确认
            </button>
            <button
              type="button"
              class="rounded-full border border-amber-200 bg-amber-50 px-3 py-2 text-xs font-medium text-amber-700 transition hover:bg-amber-100 disabled:opacity-60"
              :disabled="updatingFeedbackId === item.id"
              @click="updateFeedback(item.id, 'follow_up')"
            >
              标记待跟进
            </button>
            <button
              type="button"
              class="rounded-full border border-rose-200 bg-rose-50 px-3 py-2 text-xs font-medium text-rose-700 transition hover:bg-rose-100 disabled:opacity-60"
              :disabled="updatingFeedbackId === item.id"
              @click="updateFeedback(item.id, 'false_positive')"
            >
              标记误报
            </button>
          </div>
        </div>
      </article>
    </div>
  </section>
</template>
