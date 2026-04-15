<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { BrainCircuit, RefreshCw, Save, Sparkles } from 'lucide-vue-next'
import CyberCard from '@/shared/ui/CyberCard.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import {
  fetchAiAuditReport,
  fetchAiAuditReports,
  updateAiAuditReportFeedback,
} from '@/shared/api/dashboard'
import { fetchGlobalSettings, updateGlobalSettings } from '@/shared/api/settings'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import type {
  AiAuditReportResponse,
  AiAuditReportHistoryItem,
  AiAuditReportsResponse,
  GlobalSettingsPayload,
  AiAuditSettingsPayload,
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
  }
}

const loading = ref(true)
const refreshing = ref(false)
const saving = ref(false)
const copying = ref(false)
const historyLoading = ref(false)
const updatingFeedbackId = ref<number | null>(null)
const error = ref('')
const successMessage = ref('')
const report = ref<AiAuditReportResponse | null>(null)
const cachedReportAt = ref<number | null>(null)
const reportHistory = ref<AiAuditReportHistoryItem[]>([])
const historyTotal = ref(0)
const form = reactive<AiAuditSettingsPayload>(createDefaultAiAuditSettings())
const windowSeconds = ref(900)
const feedbackFilter = ref<
  'all' | 'unreviewed' | 'confirmed' | 'false_positive' | 'follow_up'
>('all')
const feedbackNotes = reactive<Record<number, string>>({})

const { formatNumber, formatTimestamp } = useFormatters()

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
    return `已回退到 ${report.value.provider_used}`
  }
  return `当前输出来自 ${report.value.provider_used}`
})

const cachedReportLabel = computed(() => {
  if (!cachedReportAt.value) return '当前没有本地快照'
  return `本地快照 ${formatTimestamp(cachedReportAt.value)}`
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
        await fetchAiAuditReport({
          window_seconds: windowSeconds.value,
        }),
      )
    }
    await loadHistory()
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
      await fetchAiAuditReport({
        window_seconds: windowSeconds.value,
        provider: form.provider,
        fallback_to_rules: form.fallback_to_rules,
      }),
    )
    await loadHistory()
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
    error.value = err instanceof Error ? err.message : '复制 AI 审计 JSON 失败'
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

onMounted(() => {
  loadCachedReportSnapshot()
  void loadSection(true)
})
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
          @click="loadSection(true)"
        >
          <RefreshCw :size="14" :class="{ 'animate-spin': loading || refreshing }" />
          刷新
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
      正在加载 AI 审计配置与报告...
    </div>

    <div v-else class="space-y-5">
      <section class="grid gap-4 xl:grid-cols-[minmax(0,1.05fr)_minmax(0,1.25fr)]">
        <div class="rounded-2xl border border-slate-200 bg-slate-50/80 p-4">
          <div class="flex items-start justify-between gap-3">
            <div>
              <p class="text-sm font-semibold text-slate-900">模型与 Provider 配置</p>
              <p class="mt-1 text-xs leading-5 text-slate-500">
                这里改的是全局 AI 审计默认配置。保存后，后端会优先按这里的 provider 走，再决定是否回退到本地规则。
              </p>
            </div>
            <div class="rounded-2xl bg-white p-3 text-cyan-700 shadow-sm">
              <BrainCircuit :size="18" />
            </div>
          </div>

          <div class="mt-4 grid gap-3 md:grid-cols-2">
            <label
              class="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700"
            >
              <input
                v-model="form.enabled"
                type="checkbox"
                class="h-4 w-4 accent-cyan-600"
              />
              启用外部 AI 审计
            </label>
            <label class="space-y-1">
              <span class="text-xs font-medium text-slate-500">默认 provider</span>
              <select
                v-model="form.provider"
                class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
                >
                  <option value="local_rules">local_rules</option>
                  <option value="stub_model">stub_model</option>
                  <option value="openai_compatible">openai_compatible</option>
                  <option value="xiaomi_mimo">xiaomi_mimo</option>
                </select>
              </label>
            <label class="space-y-1">
              <span class="text-xs font-medium text-slate-500">模型名称</span>
              <input
                v-model="form.model"
                class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
                type="text"
                :placeholder="form.provider === 'xiaomi_mimo' ? '例如 mimo-v2-flash' : '例如 gpt-5.4-mini'"
              />
            </label>
            <label class="space-y-1">
              <span class="text-xs font-medium text-slate-500">Base URL</span>
              <input
                v-model="form.base_url"
                class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
                type="text"
                :placeholder="form.provider === 'xiaomi_mimo' ? '例如 https://api.xiaomimimo.com/v1' : '例如 https://api.example.com/v1'"
              />
            </label>
            <label class="space-y-1">
              <span class="text-xs font-medium text-slate-500">API Key</span>
              <input
                v-model="form.api_key"
                class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
                type="password"
                placeholder="留空时外部 provider 无法真正执行"
              />
            </label>
            <label class="space-y-1">
              <span class="text-xs font-medium text-slate-500">超时预算（毫秒）</span>
              <input
                v-model.number="form.timeout_ms"
                class="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
                type="number"
                min="1000"
                step="500"
              />
            </label>
          </div>

          <div class="mt-3 flex flex-wrap gap-3">
            <label
              class="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700"
            >
              <input
                v-model="form.fallback_to_rules"
                type="checkbox"
                class="h-4 w-4 accent-cyan-600"
              />
              provider 失败时自动回退到 local_rules
            </label>
            <div
              v-if="form.provider === 'xiaomi_mimo'"
              class="rounded-xl border border-cyan-200 bg-cyan-50 px-3 py-2 text-xs leading-5 text-cyan-800"
            >
              小米 MIMO 预设会优先使用 `api-key` 请求头，并在未填写地址时默认走 `https://api.xiaomimimo.com/v1`。
            </div>
            <label class="space-y-1">
              <span class="text-xs font-medium text-slate-500">观察窗口（秒）</span>
              <input
                v-model.number="windowSeconds"
                class="w-32 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
                type="number"
                min="60"
                step="60"
              />
            </label>
          </div>
        </div>

        <div class="rounded-2xl border border-slate-200 bg-white p-4">
          <div class="flex flex-wrap items-center gap-2">
            <StatusBadge
              :type="riskBadgeType"
              :text="report ? `风险 ${report.risk_level}` : '尚未执行'"
            />
            <StatusBadge
              type="muted"
              :text="providerStatusText"
            />
            <StatusBadge
              type="muted"
              :text="cachedReportLabel"
            />
            <StatusBadge
              v-if="report?.summary.current.auto_tuning_last_adjust_reason"
              type="info"
              :text="`最近调优 ${report.summary.current.auto_tuning_last_adjust_reason}`"
            />
          </div>

          <div v-if="report" class="mt-4 space-y-4">
            <div>
              <p class="text-sm font-semibold text-slate-900">{{ report.headline }}</p>
              <p class="mt-1 text-xs text-slate-500">
                生成时间 {{ formatTimestamp(report.generated_at) }} · 采样事件
                {{ formatNumber(report.summary.sampled_events) }} / 总事件
                {{ formatNumber(report.summary.total_events) }}
              </p>
            </div>

            <div
              v-if="report.executive_summary.length"
              class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
            >
              <p class="text-xs font-medium uppercase tracking-[0.18em] text-slate-400">
                Executive Summary
              </p>
              <ul class="mt-2 space-y-2 text-sm leading-6 text-slate-700">
                <li
                  v-for="(item, index) in report.executive_summary"
                  :key="`${index}-${item}`"
                >
                  {{ item }}
                </li>
              </ul>
            </div>

            <div class="grid gap-3 md:grid-cols-3">
              <div class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                <p class="text-xs text-slate-400">身份解析压力</p>
                <p class="mt-1 text-lg font-semibold text-slate-900">
                  {{ formatNumber(report.summary.current.identity_pressure_percent) }}%
                </p>
              </div>
              <div class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                <p class="text-xs text-slate-400">L7 摩擦压力</p>
                <p class="mt-1 text-lg font-semibold text-slate-900">
                  {{ formatNumber(report.summary.current.l7_friction_pressure_percent) }}%
                </p>
              </div>
              <div class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                <p class="text-xs text-slate-400">慢速攻击压力</p>
                <p class="mt-1 text-lg font-semibold text-slate-900">
                  {{ formatNumber(report.summary.current.slow_attack_pressure_percent) }}%
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section
        v-if="report"
        class="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]"
      >
        <div class="space-y-4">
          <div class="rounded-2xl border border-slate-200 bg-white p-4">
            <p class="text-sm font-semibold text-slate-900">发现的问题</p>
            <div v-if="!report.findings.length" class="mt-3 text-sm text-slate-500">
              当前没有新增 findings。
            </div>
            <div v-else class="mt-3 space-y-3">
              <article
                v-for="finding in report.findings"
                :key="finding.key"
                class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
              >
                <div class="flex flex-wrap items-center gap-2">
                  <StatusBadge
                    :type="finding.severity === 'high' || finding.severity === 'critical' ? 'error' : finding.severity === 'medium' ? 'warning' : 'muted'"
                    :text="finding.severity"
                  />
                  <span class="text-sm font-semibold text-slate-900">{{ finding.title }}</span>
                </div>
                <p class="mt-2 text-sm leading-6 text-slate-700">{{ finding.detail }}</p>
                <ul
                  v-if="finding.evidence.length"
                  class="mt-2 space-y-1 text-xs leading-5 text-slate-500"
                >
                  <li v-for="(item, index) in finding.evidence" :key="`${finding.key}-${index}`">
                    {{ item }}
                  </li>
                </ul>
              </article>
            </div>
          </div>

          <div class="rounded-2xl border border-slate-200 bg-white p-4">
            <p class="text-sm font-semibold text-slate-900">建议动作</p>
            <div v-if="!report.recommendations.length" class="mt-3 text-sm text-slate-500">
              当前没有新增建议。
            </div>
            <div v-else class="mt-3 space-y-3">
              <article
                v-for="recommendation in report.recommendations"
                :key="recommendation.key"
                class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
              >
                <div class="flex flex-wrap items-center gap-2">
                  <StatusBadge
                    :type="recommendation.priority === 'high' || recommendation.priority === 'urgent' ? 'warning' : 'info'"
                    :text="recommendation.priority"
                  />
                  <span class="text-sm font-semibold text-slate-900">{{ recommendation.title }}</span>
                </div>
                <p class="mt-2 text-sm leading-6 text-slate-700">{{ recommendation.action }}</p>
                <p class="mt-1 text-xs leading-5 text-slate-500">{{ recommendation.rationale }}</p>
              </article>
            </div>
          </div>
        </div>

        <div class="space-y-4">
          <div class="rounded-2xl border border-slate-200 bg-white p-4">
            <p class="text-sm font-semibold text-slate-900">执行说明</p>
            <div v-if="!report.execution_notes.length" class="mt-3 text-sm text-slate-500">
              当前没有额外执行说明。
            </div>
            <ul v-else class="mt-3 space-y-2 text-sm leading-6 text-slate-700">
              <li
                v-for="(note, index) in report.execution_notes"
                :key="`${index}-${note}`"
                class="rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2"
              >
                {{ note }}
              </li>
            </ul>
          </div>

          <div class="rounded-2xl border border-slate-200 bg-white p-4">
            <p class="text-sm font-semibold text-slate-900">近期审计样本</p>
            <div
              v-if="!report.summary.recent_events.length"
              class="mt-3 text-sm text-slate-500"
            >
              当前窗口没有近期样本。
            </div>
            <div v-else class="mt-3 space-y-3">
              <article
                v-for="event in report.summary.recent_events.slice(0, 5)"
                :key="event.id"
                class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
              >
                <div class="flex flex-wrap items-center gap-2">
                  <StatusBadge type="muted" :text="event.layer" />
                  <StatusBadge
                    v-if="event.decision_summary?.primary_signal"
                    type="info"
                    :text="event.decision_summary.primary_signal"
                  />
                </div>
                <p class="mt-2 text-sm font-medium text-slate-900">{{ event.reason }}</p>
                <p class="mt-1 text-xs text-slate-500">
                  {{ event.source_ip }} · {{ event.uri || '-' }} ·
                  {{ formatTimestamp(event.created_at) }}
                </p>
              </article>
            </div>
          </div>
        </div>
      </section>

      <section class="rounded-2xl border border-slate-200 bg-white p-4">
        <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <p class="text-sm font-semibold text-slate-900">审计历史与人工反馈</p>
            <p class="mt-1 text-xs leading-5 text-slate-500">
              最近的 AI 审计报告会自动落库。你可以在这里把结论标成已确认、误报或待跟进，给后续调优留反馈样本。
            </p>
          </div>
          <div class="flex items-center gap-2">
            <select
              v-model="feedbackFilter"
              class="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm outline-none transition focus:border-cyan-500"
            >
              <option value="all">全部</option>
              <option value="unreviewed">未标记</option>
              <option value="confirmed">已确认</option>
              <option value="false_positive">误报</option>
              <option value="follow_up">待跟进</option>
            </select>
            <StatusBadge type="muted" :text="`历史 ${formatNumber(historyTotal)}`" />
          </div>
        </div>

        <div v-if="historyLoading" class="py-12 text-center text-sm text-slate-500">
          正在加载 AI 审计历史...
        </div>
        <div
          v-else-if="!reportHistory.length"
          class="py-12 text-center text-sm text-slate-500"
        >
          还没有历史审计报告
        </div>
        <div v-else class="mt-4 space-y-4">
          <article
            v-for="item in reportHistory"
            :key="item.id"
            class="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-4"
          >
            <div class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div class="space-y-2 min-w-0">
                <div class="flex flex-wrap items-center gap-2">
                  <StatusBadge
                    :type="item.risk_level === 'high' || item.risk_level === 'critical' ? 'error' : item.risk_level === 'medium' ? 'warning' : 'success'"
                    :text="item.risk_level"
                  />
                  <StatusBadge type="muted" :text="item.provider_used" />
                  <StatusBadge
                    v-if="item.feedback_status"
                    type="info"
                    :text="`反馈 ${item.feedback_status}`"
                  />
                  <StatusBadge
                    v-if="item.fallback_used"
                    type="warning"
                    text="已走 fallback"
                  />
                </div>
                <p class="text-sm font-semibold text-slate-900">{{ item.headline }}</p>
                <p class="text-xs text-slate-500">
                  生成于 {{ formatTimestamp(item.generated_at) }}
                  <template v-if="item.feedback_updated_at">
                    · 反馈更新时间 {{ formatTimestamp(item.feedback_updated_at) }}
                  </template>
                </p>
                <p
                  v-if="item.report.executive_summary.length"
                  class="text-sm leading-6 text-slate-700"
                >
                  {{ item.report.executive_summary[0] }}
                </p>
              </div>
              <div class="grid grid-cols-3 gap-3 text-sm text-slate-600 lg:min-w-[18rem]">
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
    </div>
  </CyberCard>
</template>
