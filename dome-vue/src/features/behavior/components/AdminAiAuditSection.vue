<script setup lang="ts">
import { ref } from 'vue'
import {
  Download,
  RefreshCw,
  Save,
  Settings,
  Sparkles,
  X,
} from 'lucide-vue-next'
import CyberCard from '@/shared/ui/CyberCard.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import AiAuditSettingsPanel from '@/features/behavior/components/AiAuditSettingsPanel.vue'
import AiAuditReportDetails from '@/features/behavior/components/AiAuditReportDetails.vue'
import AiAuditHistoryPanel from '@/features/behavior/components/AiAuditHistoryPanel.vue'
import { useAdminAiAuditSection } from '@/features/behavior/composables/useAdminAiAuditSection'

const settingsDialogOpen = ref(false)

const {
  loading,
  refreshing,
  saving,
  copying,
  historyLoading,
  policiesLoading,
  updatingFeedbackId,
  revokingPolicyId,
  report,
  historyTotal,
  activePolicies,
  autoAuditStatus,
  compareReportId,
  form,
  windowSeconds,
  feedbackFilter,
  triggerReasonFilter,
  feedbackNotes,
  formatNumber,
  formatTimestamp,
  providerLabel,
  riskLevelLabel,
  priorityLabel,
  actionTypeLabel,
  feedbackStatusLabel,
  riskBadgeType,
  providerStatusText,
  cachedReportLabel,
  autoAuditStatusText,
  autoAuditTriggerFlags,
  filteredReportHistory,
  autoAuditTimeline,
  comparisonSummary,
  formatPolicyEffectMap,
  formatDelta,
  describeAutoTriggerReason,
  triggerReasonFilterLabel,
  loadSection,
  runAudit,
  saveAiAuditSettings,
  copyReportJson,
  downloadReportJson,
  useHistoryReport,
  pinCompareReport,
  updateFeedback,
  revokePolicy,
} = useAdminAiAuditSection()
</script>

<template>
  <CyberCard title="AI 审计">
    <template #header-action>
      <div class="flex flex-wrap items-center gap-2">
        <button
          type="button"
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:border-slate-300 hover:text-slate-900 disabled:opacity-60"
          :disabled="loading || refreshing"
          @click="runAudit"
        >
          <Sparkles :size="14" />
          {{ refreshing ? '执行中...' : '试跑一次' }}
        </button>
        <button
          type="button"
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:border-slate-300 hover:text-slate-900 disabled:opacity-60"
          :disabled="loading"
          @click="settingsDialogOpen = true"
        >
          <Settings :size="14" />
          模型配置
        </button>
        <button
          type="button"
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:border-slate-300 hover:text-slate-900 disabled:opacity-60"
          :disabled="loading || refreshing"
          @click="loadSection(false)"
        >
          <RefreshCw
            :size="14"
            :class="{ 'animate-spin': loading || refreshing }"
          />
          刷新配置
        </button>
        <button
          type="button"
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:border-slate-300 hover:text-slate-900 disabled:opacity-60"
          :disabled="!report || copying"
          @click="copyReportJson"
        >
          {{ copying ? '复制中...' : '复制 JSON' }}
        </button>
        <button
          type="button"
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:border-slate-300 hover:text-slate-900 disabled:opacity-60"
          :disabled="!report"
          @click="downloadReportJson"
        >
          <Download :size="14" />
          导出 JSON
        </button>
      </div>
    </template>

    <div v-if="loading" class="py-12 text-center text-sm text-slate-500">
      正在加载 AI 审计配置与历史...
    </div>

    <div v-else class="space-y-5">
      <section
        class="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(18rem,0.6fr)]"
      >
        <div class="rounded-md border border-slate-200 bg-white p-4">
          <div class="flex flex-wrap items-center gap-2">
            <StatusBadge
              :type="riskBadgeType"
              :text="
                report
                  ? `风险 ${riskLevelLabel(report.risk_level)}`
                  : '尚未执行'
              "
            />
            <StatusBadge type="muted" :text="providerStatusText" />
            <StatusBadge type="muted" :text="cachedReportLabel" />
            <StatusBadge
              v-if="comparisonSummary"
              type="info"
              :text="`对比 ${formatDelta(comparisonSummary.findingsDelta)}`"
            />
          </div>

          <div v-if="report" class="mt-4">
            <div
              class="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between"
            >
              <div class="min-w-0">
                <p class="text-base font-semibold text-slate-900">
                  {{ report.headline }}
                </p>
                <p class="mt-1 text-xs text-slate-500">
                  {{ formatTimestamp(report.generated_at) }} · 采样
                  {{ formatNumber(report.summary.sampled_events) }} /
                  {{ formatNumber(report.summary.total_events) }}
                </p>
              </div>
              <div
                class="grid grid-cols-3 gap-2 text-center text-xs text-slate-500 xl:min-w-[21rem]"
              >
                <div
                  class="rounded-md border border-slate-200 bg-slate-50 px-3 py-2"
                >
                  <p>身份压力</p>
                  <p class="mt-1 text-base font-semibold text-slate-900">
                    {{
                      formatNumber(
                        report.summary.current.identity_pressure_percent,
                      )
                    }}%
                  </p>
                </div>
                <div
                  class="rounded-md border border-slate-200 bg-slate-50 px-3 py-2"
                >
                  <p>L7 摩擦</p>
                  <p class="mt-1 text-base font-semibold text-slate-900">
                    {{
                      formatNumber(
                        report.summary.current.l7_friction_pressure_percent,
                      )
                    }}%
                  </p>
                </div>
                <div
                  class="rounded-md border border-slate-200 bg-slate-50 px-3 py-2"
                >
                  <p>慢速攻击</p>
                  <p class="mt-1 text-base font-semibold text-slate-900">
                    {{
                      formatNumber(
                        report.summary.current.slow_attack_pressure_percent,
                      )
                    }}%
                  </p>
                </div>
              </div>
            </div>

            <ul
              v-if="report.executive_summary.length"
              class="mt-3 grid gap-2 text-sm leading-6 text-slate-700 xl:grid-cols-2"
            >
              <li
                v-for="(item, index) in report.executive_summary.slice(0, 4)"
                :key="`${index}-${item}`"
                class="rounded-md border border-slate-200 bg-slate-50 px-3 py-2"
              >
                {{ item }}
              </li>
            </ul>
          </div>

          <div
            v-else
            class="mt-4 rounded-md border border-dashed border-slate-200 bg-slate-50 px-4 py-8 text-center text-sm text-slate-500"
          >
            暂无审计报告
          </div>
        </div>

        <div class="rounded-md border border-slate-200 bg-slate-50 p-4">
          <div class="flex flex-wrap items-center gap-2">
            <StatusBadge
              :type="autoAuditStatus?.enabled ? 'info' : 'muted'"
              :text="
                autoAuditStatus?.enabled ? '自动审计已启用' : '自动审计未启用'
              "
            />
            <StatusBadge
              v-if="autoAuditStatus?.last_trigger_reason"
              type="warning"
              :text="
                describeAutoTriggerReason(autoAuditStatus.last_trigger_reason)
              "
            />
          </div>
          <div class="mt-3 grid gap-3 text-sm text-slate-600">
            <div>
              <p class="text-xs text-slate-400">最近状态</p>
              <p class="mt-1 font-semibold text-slate-900">
                {{ autoAuditStatusText }}
              </p>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <p class="text-xs text-slate-400">触发条件</p>
                <p class="mt-1 font-semibold text-slate-900">
                  {{
                    autoAuditTriggerFlags.length
                      ? autoAuditTriggerFlags.join(' / ')
                      : '暂无'
                  }}
                </p>
              </div>
              <div>
                <p class="text-xs text-slate-400">报告</p>
                <p class="mt-1 font-semibold text-slate-900">
                  {{
                    autoAuditStatus?.last_report_id
                      ? `#${autoAuditStatus.last_report_id}`
                      : '暂无'
                  }}
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <details class="rounded-md border border-slate-200 bg-white">
        <summary
          class="cursor-pointer px-4 py-3 text-sm font-semibold text-slate-900"
        >
          审计详情与历史反馈
        </summary>
        <div class="space-y-4 border-t border-slate-200 p-4">
          <AiAuditReportDetails
            v-if="report"
            :report="report"
            :active-policies="activePolicies"
            :policies-loading="policiesLoading"
            :revoking-policy-id="revokingPolicyId"
            :format-number="formatNumber"
            :format-timestamp="formatTimestamp"
            :risk-level-label="riskLevelLabel"
            :priority-label="priorityLabel"
            :action-type-label="actionTypeLabel"
            :format-policy-effect-map="formatPolicyEffectMap"
            :format-delta="formatDelta"
            :revoke-policy="revokePolicy"
          />

          <AiAuditHistoryPanel
            v-model:feedback-filter="feedbackFilter"
            v-model:trigger-reason-filter="triggerReasonFilter"
            :history-total="historyTotal"
            :history-loading="historyLoading"
            :filtered-report-history="filteredReportHistory"
            :auto-audit-timeline="autoAuditTimeline"
            :compare-report-id="compareReportId"
            :feedback-notes="feedbackNotes"
            :updating-feedback-id="updatingFeedbackId"
            :format-number="formatNumber"
            :format-timestamp="formatTimestamp"
            :risk-level-label="riskLevelLabel"
            :provider-label="providerLabel"
            :feedback-status-label="feedbackStatusLabel"
            :describe-auto-trigger-reason="describeAutoTriggerReason"
            :trigger-reason-filter-label="triggerReasonFilterLabel"
            :use-history-report="useHistoryReport"
            :pin-compare-report="pinCompareReport"
            :update-feedback="updateFeedback"
          />
        </div>
      </details>
    </div>
  </CyberCard>

  <div
    v-if="settingsDialogOpen"
    class="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/30 px-4 py-8"
    @click.self="settingsDialogOpen = false"
  >
    <div
      class="max-h-full w-full max-w-5xl overflow-hidden rounded-md border border-slate-300 bg-white shadow-xl"
    >
      <div
        class="flex items-center justify-between border-b border-slate-200 px-4 py-3"
      >
        <div>
          <p class="text-sm font-semibold text-slate-900">AI 模型配置</p>
          <p class="mt-0.5 text-xs text-slate-500">保存后会更新全局审计设置</p>
        </div>
        <button
          type="button"
          class="inline-flex h-8 w-8 items-center justify-center rounded-md border border-slate-300 bg-white text-slate-600 hover:bg-slate-50"
          :disabled="saving"
          @click="settingsDialogOpen = false"
        >
          <X :size="16" />
        </button>
      </div>
      <div class="max-h-[calc(100vh-12rem)] overflow-y-auto p-4">
        <AiAuditSettingsPanel
          v-model:window-seconds="windowSeconds"
          :form="form"
        />
      </div>
      <div
        class="flex items-center justify-end gap-2 border-t border-slate-200 px-4 py-3"
      >
        <button
          type="button"
          class="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-60"
          :disabled="saving"
          @click="settingsDialogOpen = false"
        >
          取消
        </button>
        <button
          type="button"
          class="inline-flex items-center gap-2 rounded-md border border-cyan-300 bg-cyan-50 px-3 py-2 text-sm font-medium text-cyan-700 hover:bg-cyan-100 disabled:opacity-60"
          :disabled="loading || saving"
          @click="saveAiAuditSettings"
        >
          <Save :size="15" />
          {{ saving ? '保存中...' : '保存配置' }}
        </button>
      </div>
    </div>
  </div>
</template>
