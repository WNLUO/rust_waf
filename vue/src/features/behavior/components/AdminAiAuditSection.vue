<script setup lang="ts">
import { RefreshCw, Save, Sparkles } from 'lucide-vue-next'
import CyberCard from '@/shared/ui/CyberCard.vue'
import AiAuditSettingsPanel from '@/features/behavior/components/AiAuditSettingsPanel.vue'
import AiAuditReportOverview from '@/features/behavior/components/AiAuditReportOverview.vue'
import AiAuditReportDetails from '@/features/behavior/components/AiAuditReportDetails.vue'
import AiAuditHistoryPanel from '@/features/behavior/components/AiAuditHistoryPanel.vue'
import AiAuditAutoStatusPanel from '@/features/behavior/components/AiAuditAutoStatusPanel.vue'
import { useAdminAiAuditSection } from '@/features/behavior/composables/useAdminAiAuditSection'

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
  analysisModeLabel,
  inputSourceLabel,
  riskBadgeType,
  providerStatusText,
  cachedReportLabel,
  autoAuditStatusText,
  autoAuditTriggerFlags,
  filteredReportHistory,
  autoAuditTimeline,
  comparisonSummary,
  formatPolicyEffectMap,
  formatCountItems,
  formatDelta,
  truncateMiddle,
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
  <CyberCard
    title="AI 审计"
    sub-title="把模型配置、试跑结果和本地回退状态放在同一个入口里，方便直接验证你的审计链路有没有接通。"
  >
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
          :disabled="loading || saving"
          @click="saveAiAuditSettings"
        >
          <Save :size="14" />
          {{ saving ? '保存中...' : '保存配置' }}
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
          导出 JSON
        </button>
      </div>
    </template>

    <div v-if="loading" class="py-12 text-center text-sm text-slate-500">
      正在加载 AI 审计配置与历史...
    </div>

    <div v-else class="space-y-5">
      <section
        class="grid gap-4 xl:grid-cols-[minmax(0,1.05fr)_minmax(0,1.25fr)]"
      >
        <AiAuditSettingsPanel
          v-model:window-seconds="windowSeconds"
          :form="form"
        />

        <AiAuditReportOverview
          :report="report"
          :risk-badge-type="riskBadgeType"
          :provider-status-text="providerStatusText"
          :cached-report-label="cachedReportLabel"
          :comparison-summary="comparisonSummary"
          :format-number="formatNumber"
          :format-timestamp="formatTimestamp"
          :risk-level-label="riskLevelLabel"
          :analysis-mode-label="analysisModeLabel"
          :input-source-label="inputSourceLabel"
          :format-count-items="formatCountItems"
          :describe-auto-trigger-reason="describeAutoTriggerReason"
        />

        <AiAuditAutoStatusPanel
          :auto-audit-status="autoAuditStatus"
          :auto-audit-status-text="autoAuditStatusText"
          :auto-audit-trigger-flags="autoAuditTriggerFlags"
          :format-number="formatNumber"
          :format-timestamp="formatTimestamp"
          :truncate-middle="truncateMiddle"
          :describe-auto-trigger-reason="describeAutoTriggerReason"
        />
      </section>

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
  </CyberCard>
</template>
