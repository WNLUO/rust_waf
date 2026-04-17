import { computed, onMounted, reactive, ref, watch } from 'vue'
import {
  fetchAiAutoAuditStatus,
  deleteAiTempPolicy,
  fetchAiAuditReport,
  fetchAiAuditReports,
  fetchAiTempPolicies,
  runAiAuditReport,
  updateAiAuditReportFeedback,
} from '@/shared/api/dashboard'
import {
  fetchGlobalSettings,
  updateGlobalSettings,
} from '@/shared/api/settings'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import type {
  AiAuditReportResponse,
  AiAuditReportHistoryItem,
  AiAuditReportsResponse,
  AiAutoAuditStatus,
  GlobalSettingsPayload,
  AiAuditSettingsPayload,
  AiTempPolicyItem,
} from '@/shared/types'

function createDefaultAiAuditSettings(): AiAuditSettingsPayload {
  return {
    enabled: false,
    provider: 'local_rules',
    model: '',
    base_url: '',
    api_key: '',
    timeout_ms: 15000,
    fallback_to_rules: true,
    event_sample_limit: 120,
    recent_event_limit: 12,
    include_raw_event_samples: false,
    auto_apply_temp_policies: true,
    temp_policy_ttl_secs: 900,
    temp_block_ttl_secs: 1800,
    auto_apply_min_confidence: 70,
    max_active_temp_policies: 24,
    allow_auto_temp_block: false,
    allow_auto_extend_effective_policies: true,
    auto_revoke_warmup_secs: 300,
    auto_audit_enabled: false,
    auto_audit_interval_secs: 300,
    auto_audit_cooldown_secs: 600,
    auto_audit_on_pressure_high: true,
    auto_audit_on_attack_mode: true,
    auto_audit_on_hotspot_shift: true,
    auto_audit_force_local_rules_under_attack: true,
  }
}

export function useAdminAiAuditSection() {
  const loading = ref(true)
  const refreshing = ref(false)
  const saving = ref(false)
  const copying = ref(false)
  const historyLoading = ref(false)
  const policiesLoading = ref(false)
  const updatingFeedbackId = ref<number | null>(null)
  const revokingPolicyId = ref<number | null>(null)
  const error = ref('')
  const successMessage = ref('')
  const report = ref<AiAuditReportResponse | null>(null)
  const cachedReportAt = ref<number | null>(null)
  const reportHistory = ref<AiAuditReportHistoryItem[]>([])
  const historyTotal = ref(0)
  const activePolicies = ref<AiTempPolicyItem[]>([])
  const autoAuditStatus = ref<AiAutoAuditStatus | null>(null)
  const compareReportId = ref<number | null>(null)
  const form = reactive<AiAuditSettingsPayload>(createDefaultAiAuditSettings())
  const windowSeconds = ref(900)
  const feedbackFilter = ref<
    'all' | 'unreviewed' | 'confirmed' | 'false_positive' | 'follow_up'
  >('all')
  const triggerReasonFilter = ref<
    'all' | 'auto' | 'manual' | 'pressure' | 'attack' | 'hotspot'
  >('all')
  const feedbackNotes = reactive<Record<number, string>>({})

  const { formatNumber, formatTimestamp } = useFormatters()

  function providerLabel(value: string | null | undefined) {
    switch ((value ?? '').toLowerCase()) {
      case 'local_rules':
        return '本地规则'
      case 'stub_model':
        return '占位模型'
      case 'openai_compatible':
        return 'OpenAI 兼容接口'
      case 'xiaomi_mimo':
        return '小米 Mimo'
      default:
        return value || '暂无'
    }
  }

  function riskLevelLabel(value: string | null | undefined) {
    switch ((value ?? '').toLowerCase()) {
      case 'low':
        return '低'
      case 'medium':
        return '中'
      case 'high':
        return '高'
      case 'critical':
        return '紧急'
      default:
        return value || '未知'
    }
  }

  function priorityLabel(value: string | null | undefined) {
    switch ((value ?? '').toLowerCase()) {
      case 'low':
        return '低'
      case 'medium':
        return '中'
      case 'high':
        return '高'
      case 'urgent':
        return '紧急'
      default:
        return value || '未知'
    }
  }

  function actionTypeLabel(value: string | null | undefined) {
    switch ((value ?? '').toLowerCase()) {
      case 'observe':
        return '持续观察'
      case 'tune_threshold':
        return '调节阈值'
      case 'add_rule':
        return '添加规则'
      case 'investigate':
        return '人工排查'
      default:
        return value || '未知'
    }
  }

  function feedbackStatusLabel(value: string | null | undefined) {
    switch ((value ?? '').toLowerCase()) {
      case 'confirmed':
        return '已确认'
      case 'false_positive':
        return '误报'
      case 'follow_up':
        return '待跟进'
      case 'unreviewed':
        return '未标记'
      default:
        return value || '暂无'
    }
  }

  function analysisModeLabel(value: string | null | undefined) {
    switch ((value ?? '').toLowerCase()) {
      case 'analysis_only':
        return '仅分析'
      default:
        return value || '暂无'
    }
  }

  function inputSourceLabel(value: string | null | undefined) {
    switch ((value ?? '').toLowerCase()) {
      case 'cc_behavior_joint_summary':
        return 'CC 行为联合摘要'
      default:
        return value || '暂无'
    }
  }

  useFlashMessages({
    error,
    success: successMessage,
    errorTitle: 'AI 审计',
    successTitle: 'AI 审计',
    errorDuration: 5600,
    successDuration: 3200,
  })

  const riskBadgeType = computed(() => {
    switch (report.value?.risk_level) {
      case 'critical':
      case 'high':
        return 'error' as const
      case 'medium':
        return 'warning' as const
      case 'low':
        return 'success' as const
      default:
        return 'muted' as const
    }
  })

  const providerStatusText = computed(() => {
    if (!report.value) return '尚未执行'
    if (report.value.fallback_used) {
      return `已回退到 ${providerLabel(report.value.provider_used)}`
    }
    return `当前输出来自 ${providerLabel(report.value.provider_used)}`
  })

  const cachedReportLabel = computed(() => {
    if (!cachedReportAt.value) return '当前没有本地快照'
    return `本地快照 ${formatTimestamp(cachedReportAt.value)}`
  })

  const autoAuditStatusText = computed(() => {
    if (!autoAuditStatus.value?.enabled) return '自动审计未启用'
    if (autoAuditStatus.value.last_completed_at) {
      return `最近完成于 ${formatTimestamp(autoAuditStatus.value.last_completed_at)}`
    }
    if (autoAuditStatus.value.last_run_at) {
      return `最近触发于 ${formatTimestamp(autoAuditStatus.value.last_run_at)}`
    }
    return '自动审计已启用，尚未触发'
  })

  const autoAuditTriggerFlags = computed(() => {
    if (!autoAuditStatus.value) return []
    const flags: string[] = []
    if (autoAuditStatus.value.on_pressure_high) {
      flags.push('高压力')
    }
    if (autoAuditStatus.value.on_attack_mode) {
      flags.push('攻击模式')
    }
    if (autoAuditStatus.value.on_hotspot_shift) {
      flags.push('热点变化')
    }
    return flags
  })

  const filteredReportHistory = computed(() => {
    if (triggerReasonFilter.value === 'all') {
      return reportHistory.value
    }
    return reportHistory.value.filter((item) => {
      const reason = (item.auto_trigger_reason ?? '').toLowerCase()
      switch (triggerReasonFilter.value) {
        case 'auto':
          return item.auto_generated
        case 'manual':
          return !item.auto_generated
        case 'pressure':
          return reason.includes('pressure')
        case 'attack':
          return reason.includes('attack')
        case 'hotspot':
          return reason.includes('hotspot')
        default:
          return true
      }
    })
  })

  const autoAuditTimeline = computed(() => {
    return filteredReportHistory.value
      .filter((item) => item.auto_generated)
      .slice(0, 6)
      .map((item) => ({
        id: item.id,
        generated_at: item.generated_at,
        risk_level: item.risk_level,
        headline: item.headline,
        trigger_reason: describeAutoTriggerReason(item.auto_trigger_reason),
        provider_used: item.provider_used,
        fallback_used: item.fallback_used,
      }))
  })

  const compareReport = computed(() => {
    if (!filteredReportHistory.value.length) return null
    if (compareReportId.value != null) {
      return (
        filteredReportHistory.value.find(
          (item) => item.id === compareReportId.value,
        ) ?? null
      )
    }
    return (
      filteredReportHistory.value.find((item) => {
        if (report.value?.report_id != null) {
          return item.id !== report.value.report_id
        }
        return item.generated_at !== report.value?.generated_at
      }) ?? null
    )
  })

  const comparisonSummary = computed(() => {
    if (!report.value || !compareReport.value) return null

    const riskOrder: Record<string, number> = {
      low: 0,
      medium: 1,
      high: 2,
      critical: 3,
    }
    const currentRisk = riskOrder[report.value.risk_level] ?? 1
    const baselineRisk = riskOrder[compareReport.value.risk_level] ?? 1
    const riskDelta = currentRisk - baselineRisk
    const findingsDelta =
      report.value.findings.length - compareReport.value.report.findings.length
    const recommendationsDelta =
      report.value.recommendations.length -
      compareReport.value.report.recommendations.length
    const sampledEventsDelta =
      report.value.summary.sampled_events -
      compareReport.value.report.summary.sampled_events

    const currentKeys = new Set(report.value.findings.map((item) => item.key))
    const baselineKeys = new Set(
      compareReport.value.report.findings.map((item) => item.key),
    )
    const newFindingTitles = report.value.findings
      .filter((item) => !baselineKeys.has(item.key))
      .map((item) => item.title)
      .slice(0, 3)
    const clearedFindingTitles = compareReport.value.report.findings
      .filter((item) => !currentKeys.has(item.key))
      .map((item) => item.title)
      .slice(0, 3)

    return {
      baseline: compareReport.value,
      riskDirection: riskDelta > 0 ? 'up' : riskDelta < 0 ? 'down' : 'flat',
      findingsDelta,
      recommendationsDelta,
      sampledEventsDelta,
      identityPressureDelta:
        report.value.summary.current.identity_pressure_percent -
        compareReport.value.report.summary.current.identity_pressure_percent,
      l7FrictionDelta:
        report.value.summary.current.l7_friction_pressure_percent -
        compareReport.value.report.summary.current.l7_friction_pressure_percent,
      slowAttackDelta:
        report.value.summary.current.slow_attack_pressure_percent -
        compareReport.value.report.summary.current.slow_attack_pressure_percent,
      newFindingTitles,
      clearedFindingTitles,
    }
  })

  function persistReportSnapshot(next: AiAuditReportResponse) {
    report.value = next
    if (typeof window === 'undefined') return
    window.localStorage.setItem(
      'waf-ai-audit-last-report',
      JSON.stringify({
        cached_at: Date.now(),
        report: next,
      }),
    )
    cachedReportAt.value = Date.now()
  }

  function loadCachedReportSnapshot() {
    if (typeof window === 'undefined') return
    const raw = window.localStorage.getItem('waf-ai-audit-last-report')
    if (!raw) return
    try {
      const payload = JSON.parse(raw) as {
        cached_at?: number
        report?: AiAuditReportResponse
      }
      if (payload.report) {
        report.value = payload.report
        cachedReportAt.value = payload.cached_at ?? null
      }
    } catch {
      window.localStorage.removeItem('waf-ai-audit-last-report')
    }
  }

  function assignAiAudit(payload: GlobalSettingsPayload) {
    Object.assign(form, payload.ai_audit)
  }

  function assignHistory(payload: AiAuditReportsResponse) {
    reportHistory.value = payload.reports
    historyTotal.value = payload.total
    for (const item of payload.reports) {
      feedbackNotes[item.id] = item.feedback_notes ?? ''
    }
    if (
      compareReportId.value != null &&
      !payload.reports.some((item) => item.id === compareReportId.value)
    ) {
      compareReportId.value = null
    }
  }

  function formatPolicyEffectMap(values: Record<string, number>, limit = 3) {
    const entries = Object.entries(values)
      .sort((left, right) => right[1] - left[1])
      .slice(0, limit)
    if (!entries.length) return '暂无'
    return entries
      .map(([key, value]) => `${key}:${formatNumber(value)}`)
      .join(' · ')
  }

  function formatCountItems(
    items: Array<{ key: string; count: number }>,
    limit = 3,
  ) {
    if (!items.length) return '暂无'
    return items
      .slice(0, limit)
      .map((item) => `${item.key}:${formatNumber(item.count)}`)
      .join(' · ')
  }

  function formatDelta(value: number | null, suffix = '%') {
    if (value == null) return '暂无基线'
    const sign = value > 0 ? '+' : ''
    return `${sign}${formatNumber(value)}${suffix}`
  }

  function truncateMiddle(
    value: string | null | undefined,
    head = 16,
    tail = 10,
  ) {
    if (!value) return '暂无'
    if (value.length <= head + tail + 3) return value
    return `${value.slice(0, head)}...${value.slice(-tail)}`
  }

  function describeAutoTriggerReason(value: string | null | undefined) {
    if (!value) return '暂无'
    return value
      .split('+')
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean)
      .map((item) => {
        switch (item) {
          case 'pressure':
            return '高压力'
          case 'attack':
            return '攻击模式'
          case 'hotspot':
            return '热点变化'
          case 'auto':
            return '自动触发'
          case 'manual':
            return '手动执行'
          default:
            return item
        }
      })
      .join(' / ')
  }

  function triggerReasonFilterLabel(value: typeof triggerReasonFilter.value) {
    switch (value) {
      case 'auto':
        return '自动触发'
      case 'manual':
        return '手动执行'
      case 'pressure':
        return '高压力'
      case 'attack':
        return '攻击模式'
      case 'hotspot':
        return '热点变化'
      default:
        return '全部'
    }
  }

  watch(
    () => form.provider,
    (provider, previous) => {
      if (provider === previous) return
      if (provider === 'xiaomi_mimo') {
        if (!form.base_url.trim()) {
          form.base_url = 'https://api.xiaomimimo.com/v1'
        }
        if (!form.model.trim() || form.model === 'gpt-5.4-mini') {
          form.model = 'mimo-v2-flash'
        }
      }
    },
  )

  watch(feedbackFilter, () => {
    void loadHistory()
  })

  async function loadSection(runReport = true) {
    loading.value = true
    error.value = ''
    try {
      const settings = await fetchGlobalSettings()
      assignAiAudit(settings)
      if (runReport) {
        persistReportSnapshot(
          await runAiAuditReport({
            window_seconds: windowSeconds.value,
          }),
        )
      } else {
        persistReportSnapshot(await fetchAiAuditReport())
      }
      await loadHistory()
      await loadPolicies()
      await loadAutoAuditStatus()
    } catch (err) {
      error.value = err instanceof Error ? err.message : '加载 AI 审计失败'
    } finally {
      loading.value = false
    }
  }

  async function runAudit() {
    refreshing.value = true
    error.value = ''
    try {
      persistReportSnapshot(
        await runAiAuditReport({
          window_seconds: windowSeconds.value,
          provider: form.provider,
          fallback_to_rules: form.fallback_to_rules,
        }),
      )
      await loadHistory()
      await loadPolicies()
      await loadAutoAuditStatus()
    } catch (err) {
      error.value = err instanceof Error ? err.message : '执行 AI 审计失败'
    } finally {
      refreshing.value = false
    }
  }

  async function loadHistory() {
    historyLoading.value = true
    try {
      assignHistory(
        await fetchAiAuditReports({
          limit: 10,
          feedback_status: feedbackFilter.value,
        }),
      )
    } finally {
      historyLoading.value = false
    }
  }

  async function loadAutoAuditStatus() {
    autoAuditStatus.value = await fetchAiAutoAuditStatus()
  }

  async function loadPolicies() {
    policiesLoading.value = true
    try {
      activePolicies.value = (await fetchAiTempPolicies()).policies
    } finally {
      policiesLoading.value = false
    }
  }

  async function saveAiAuditSettings() {
    saving.value = true
    error.value = ''
    successMessage.value = ''
    try {
      const latest = await fetchGlobalSettings()
      const payload: GlobalSettingsPayload = {
        ...latest,
        ai_audit: {
          ...form,
          model: form.model.trim(),
          base_url: form.base_url.trim(),
          api_key: form.api_key.trim(),
        },
      }
      const response = await updateGlobalSettings(payload)
      successMessage.value = response.message
      assignAiAudit(await fetchGlobalSettings())
    } catch (err) {
      error.value = err instanceof Error ? err.message : '保存 AI 审计配置失败'
    } finally {
      saving.value = false
    }
  }

  async function copyReportJson() {
    if (!report.value) return
    copying.value = true
    error.value = ''
    successMessage.value = ''
    try {
      await navigator.clipboard.writeText(JSON.stringify(report.value, null, 2))
      successMessage.value = 'AI 审计 JSON 已复制到剪贴板'
    } catch (err) {
      error.value =
        err instanceof Error ? err.message : '复制 AI 审计 JSON 失败'
    } finally {
      copying.value = false
    }
  }

  function downloadReportJson() {
    if (!report.value || typeof window === 'undefined') return
    const blob = new Blob([JSON.stringify(report.value, null, 2)], {
      type: 'application/json',
    })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `ai-audit-report-${report.value.generated_at}.json`
    link.click()
    window.URL.revokeObjectURL(url)
    successMessage.value = 'AI 审计 JSON 已导出'
  }

  function useHistoryReport(item: AiAuditReportHistoryItem) {
    persistReportSnapshot(item.report)
    compareReportId.value =
      reportHistory.value.find((entry) => entry.id !== item.id)?.id ?? null
    successMessage.value = `已切换到 ${formatTimestamp(item.generated_at)} 的审计报告`
  }

  function pinCompareReport(item: AiAuditReportHistoryItem) {
    compareReportId.value = item.id
    successMessage.value = `已将 ${formatTimestamp(item.generated_at)} 设为对比基线`
  }

  async function updateFeedback(
    reportId: number,
    feedbackStatus: 'confirmed' | 'false_positive' | 'follow_up',
  ) {
    updatingFeedbackId.value = reportId
    error.value = ''
    successMessage.value = ''
    try {
      const response = await updateAiAuditReportFeedback(reportId, {
        feedback_status: feedbackStatus,
        feedback_notes: feedbackNotes[reportId]?.trim() || null,
      })
      successMessage.value = response.message
      await loadHistory()
    } catch (err) {
      error.value = err instanceof Error ? err.message : '更新 AI 审计反馈失败'
    } finally {
      updatingFeedbackId.value = null
    }
  }

  async function revokePolicy(id: number) {
    revokingPolicyId.value = id
    error.value = ''
    successMessage.value = ''
    try {
      const response = await deleteAiTempPolicy(id)
      successMessage.value = response.message
      await loadPolicies()
    } catch (err) {
      error.value = err instanceof Error ? err.message : '撤销 AI 临时策略失败'
    } finally {
      revokingPolicyId.value = null
    }
  }

  onMounted(() => {
    loadCachedReportSnapshot()
    void loadSection(false)
    void loadPolicies()
  })

  return {
    loading,
    refreshing,
    saving,
    copying,
    historyLoading,
    policiesLoading,
    updatingFeedbackId,
    revokingPolicyId,
    error,
    successMessage,
    report,
    cachedReportAt,
    reportHistory,
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
    compareReport,
    comparisonSummary,
    formatPolicyEffectMap,
    formatCountItems,
    formatDelta,
    truncateMiddle,
    describeAutoTriggerReason,
    triggerReasonFilterLabel,
    loadSection,
    runAudit,
    loadHistory,
    loadAutoAuditStatus,
    loadPolicies,
    saveAiAuditSettings,
    copyReportJson,
    downloadReportJson,
    useHistoryReport,
    pinCompareReport,
    updateFeedback,
    revokePolicy,
  }
}
