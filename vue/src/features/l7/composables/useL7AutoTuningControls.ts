import { computed, ref } from 'vue'
import type { AutoTuningRuntimePayload } from '@/features/l7/types/l7'
import type { L7ConfigForm } from '@/features/l7/utils/adminL7'

interface L7AutoTuningProps {
  form: L7ConfigForm
  autoTuningRuntime?: AutoTuningRuntimePayload | null
}

export function useL7AutoTuningControls(
  props: L7AutoTuningProps,
  updateForm: <K extends keyof L7ConfigForm>(key: K, value: L7ConfigForm[K]) => void,
) {
  function updateAutoTuning(patch: Partial<L7ConfigForm['auto_tuning']>) {
    updateForm('auto_tuning', {
      ...props.form.auto_tuning,
      ...patch,
    })
  }

  function updateAutoTuningSlo(
    patch: Partial<L7ConfigForm['auto_tuning']['slo']>,
  ) {
    updateAutoTuning({
      slo: {
        ...props.form.auto_tuning.slo,
        ...patch,
      },
    })
  }

  const autoTuningMode = computed({
    get: () => props.form.auto_tuning.mode,
    set: (value: string) => updateAutoTuning({ mode: value }),
  })

  const autoTuningIntent = computed({
    get: () => props.form.auto_tuning.intent,
    set: (value: string) => updateAutoTuning({ intent: value }),
  })

  const autoRuntimeAdjustEnabled = computed({
    get: () => props.form.auto_tuning.runtime_adjust_enabled,
    set: (value: boolean) =>
      updateAutoTuning({ runtime_adjust_enabled: value }),
  })

  const autoBootstrapSecs = computed({
    get: () => props.form.auto_tuning.bootstrap_secs,
    set: (value: number) => updateAutoTuning({ bootstrap_secs: value }),
  })

  const autoControlIntervalSecs = computed({
    get: () => props.form.auto_tuning.control_interval_secs,
    set: (value: number) => updateAutoTuning({ control_interval_secs: value }),
  })

  const autoCooldownSecs = computed({
    get: () => props.form.auto_tuning.cooldown_secs,
    set: (value: number) => updateAutoTuning({ cooldown_secs: value }),
  })

  const autoMaxStepPercent = computed({
    get: () => props.form.auto_tuning.max_step_percent,
    set: (value: number) => updateAutoTuning({ max_step_percent: value }),
  })

  const autoRollbackWindowMinutes = computed({
    get: () => props.form.auto_tuning.rollback_window_minutes,
    set: (value: number) =>
      updateAutoTuning({ rollback_window_minutes: value }),
  })

  const autoTlsHandshakeTimeoutRatePercent = computed({
    get: () => props.form.auto_tuning.slo.tls_handshake_timeout_rate_percent,
    set: (value: number) =>
      updateAutoTuningSlo({ tls_handshake_timeout_rate_percent: value }),
  })

  const autoBucketRejectRatePercent = computed({
    get: () => props.form.auto_tuning.slo.bucket_reject_rate_percent,
    set: (value: number) =>
      updateAutoTuningSlo({ bucket_reject_rate_percent: value }),
  })

  const autoP95ProxyLatencyMs = computed({
    get: () => props.form.auto_tuning.slo.p95_proxy_latency_ms,
    set: (value: number) =>
      updateAutoTuningSlo({ p95_proxy_latency_ms: value }),
  })

  const autoPinnedFieldsText = computed({
    get: () => props.form.auto_tuning.pinned_fields.join('\n'),
    set: (value: string) => {
      updateAutoTuning({
        pinned_fields: value
          .split('\n')
          .map((item) => item.trim())
          .filter(Boolean),
      })
    },
  })

  const autoEffectEvaluation = computed(
    () => props.autoTuningRuntime?.last_effect_evaluation ?? null,
  )
  const hotspotView = ref<'host' | 'route'>('host')

  const autoRiskLeaderboard = computed(() => {
    const segments = autoEffectEvaluation.value?.segments ?? []
    return [...segments]
      .filter((segment) => segment.status !== 'low_sample')
      .sort((left, right) => {
        const leftScore =
          (left.status === 'regressed'
            ? 1000
            : left.status === 'stable'
              ? 300
              : 0) +
          left.sample_requests * 10 +
          Math.max(left.avg_proxy_latency_delta_ms, 0) +
          Math.max(left.failure_rate_delta_percent, 0) * 20
        const rightScore =
          (right.status === 'regressed'
            ? 1000
            : right.status === 'stable'
              ? 300
              : 0) +
          right.sample_requests * 10 +
          Math.max(right.avg_proxy_latency_delta_ms, 0) +
          Math.max(right.failure_rate_delta_percent, 0) * 20
        return rightScore - leftScore
      })
      .slice(0, 5)
  })

  const autoRiskByHost = computed(() => {
    const buckets = new Map<
      string,
      {
        host: string
        sample_requests: number
        regressed_count: number
        stable_count: number
        max_latency_delta_ms: number
        max_failure_rate_delta_percent: number
        top_label: string
      }
    >()

    for (const segment of autoEffectEvaluation.value?.segments ?? []) {
      const host =
        segment.host ||
        (segment.scope_type === 'host_route'
          ? segment.scope_key.split(' ')[0] || segment.scope_key
          : '')
      if (!host) continue
      const entry = buckets.get(host) ?? {
        host,
        sample_requests: 0,
        regressed_count: 0,
        stable_count: 0,
        max_latency_delta_ms: 0,
        max_failure_rate_delta_percent: 0,
        top_label: segmentLabel(segment),
      }
      entry.sample_requests += segment.sample_requests
      if (segment.status === 'regressed') entry.regressed_count += 1
      if (segment.status === 'stable') entry.stable_count += 1
      entry.max_latency_delta_ms = Math.max(
        entry.max_latency_delta_ms,
        Math.max(segment.avg_proxy_latency_delta_ms, 0),
      )
      entry.max_failure_rate_delta_percent = Math.max(
        entry.max_failure_rate_delta_percent,
        Math.max(segment.failure_rate_delta_percent, 0),
      )
      if (segment.status === 'regressed' && entry.top_label === host) {
        entry.top_label = segmentLabel(segment)
      }
      buckets.set(host, entry)
    }

    return [...buckets.values()]
      .sort((left, right) => {
        const leftScore =
          left.regressed_count * 1000 +
          left.sample_requests * 10 +
          left.max_latency_delta_ms +
          left.max_failure_rate_delta_percent * 20
        const rightScore =
          right.regressed_count * 1000 +
          right.sample_requests * 10 +
          right.max_latency_delta_ms +
          right.max_failure_rate_delta_percent * 20
        return rightScore - leftScore
      })
      .slice(0, 4)
  })

  const autoRiskByRoute = computed(() => {
    const buckets = new Map<
      string,
      {
        route: string
        sample_requests: number
        regressed_count: number
        stable_count: number
        max_latency_delta_ms: number
        max_failure_rate_delta_percent: number
        top_label: string
      }
    >()

    for (const segment of autoEffectEvaluation.value?.segments ?? []) {
      const route =
        segment.route ||
        (segment.scope_type === 'route' ? segment.scope_key : '')
      if (!route) continue
      const entry = buckets.get(route) ?? {
        route,
        sample_requests: 0,
        regressed_count: 0,
        stable_count: 0,
        max_latency_delta_ms: 0,
        max_failure_rate_delta_percent: 0,
        top_label: segmentLabel(segment),
      }
      entry.sample_requests += segment.sample_requests
      if (segment.status === 'regressed') entry.regressed_count += 1
      if (segment.status === 'stable') entry.stable_count += 1
      entry.max_latency_delta_ms = Math.max(
        entry.max_latency_delta_ms,
        Math.max(segment.avg_proxy_latency_delta_ms, 0),
      )
      entry.max_failure_rate_delta_percent = Math.max(
        entry.max_failure_rate_delta_percent,
        Math.max(segment.failure_rate_delta_percent, 0),
      )
      if (segment.status === 'regressed' && entry.top_label === route) {
        entry.top_label = segmentLabel(segment)
      }
      buckets.set(route, entry)
    }

    return [...buckets.values()]
      .sort((left, right) => {
        const leftScore =
          left.regressed_count * 1000 +
          left.sample_requests * 10 +
          left.max_latency_delta_ms +
          left.max_failure_rate_delta_percent * 20
        const rightScore =
          right.regressed_count * 1000 +
          right.sample_requests * 10 +
          right.max_latency_delta_ms +
          right.max_failure_rate_delta_percent * 20
        return rightScore - leftScore
      })
      .slice(0, 6)
  })

  const hotspotHeatmapCards = computed(() =>
    hotspotView.value === 'host' ? autoRiskByHost.value : autoRiskByRoute.value,
  )

  const autoEffectStatusLabel = computed(() => {
    switch (autoEffectEvaluation.value?.status) {
      case 'pending':
        return '观察中'
      case 'improved':
        return '已改善'
      case 'regressed':
        return '已恶化'
      case 'mixed':
        return '结果混合'
      case 'inconclusive':
        return '证据不足'
      default:
        return autoEffectEvaluation.value?.status || '未知'
    }
  })

  const autoEffectStatusClass = computed(() => {
    switch (autoEffectEvaluation.value?.status) {
      case 'improved':
        return 'text-emerald-700'
      case 'regressed':
        return 'text-rose-700'
      case 'mixed':
        return 'text-amber-700'
      case 'pending':
        return 'text-blue-700'
      default:
        return 'text-stone-700'
    }
  })

  function formatSignedNumber(value: number, digits = 2) {
    const normalized = Number.isFinite(value) ? value : 0
    const fixed = normalized.toFixed(digits)
    return normalized > 0 ? `+${fixed}` : fixed
  }

  function formatSignedInteger(value: number) {
    const normalized = Number.isFinite(value) ? Math.round(value) : 0
    return normalized > 0 ? `+${normalized}` : `${normalized}`
  }

  function requestKindLabel(kind: string) {
    switch (kind) {
      case 'document':
        return '页面'
      case 'api':
        return 'API'
      case 'static':
        return '静态资源'
      default:
        return kind
    }
  }

  function segmentLabel(segment: {
    scope_type: string
    host: string | null
    route: string | null
    request_kind: string
    scope_key: string
  }) {
    switch (segment.scope_type) {
      case 'request_kind':
        return `流量 ${requestKindLabel(segment.request_kind)}`
      case 'host':
        return `Host ${segment.host || segment.scope_key}`
      case 'route':
        return `Route ${segment.route || segment.scope_key}`
      case 'host_route':
        return `${segment.host || 'unknown-host'} ${segment.route || 'unknown-route'}`
      default:
        return segment.scope_key
    }
  }

  function segmentStatusLabel(status: string) {
    switch (status) {
      case 'improved':
        return '改善'
      case 'regressed':
        return '恶化'
      case 'stable':
        return '基本稳定'
      case 'low_sample':
        return '样本偏少'
      default:
        return status
    }
  }

  function adjustReasonLabel(reason: string | null) {
    switch (reason) {
      case 'phase1_bootstrap_estimate':
        return '启动估算'
      case 'bootstrap_recommendation_apply':
        return '应用启动建议'
      case 'adjust_for_handshake_global':
        return '全局握手压力调节'
      case 'adjust_for_budget_global':
        return '全局预算压力调节'
      case 'adjust_for_latency_global':
        return '全局延迟压力调节'
      case 'adjust_for_budget_hot_host':
        return '热点 Host 预算压力调节'
      case 'adjust_for_budget_hot_route':
        return '热点 Route 预算压力调节'
      case 'adjust_for_budget_hot_host_route':
        return '热点 Host/Route 预算压力调节'
      case 'adjust_for_latency_hot_host':
        return '热点 Host 延迟压力调节'
      case 'adjust_for_latency_hot_route':
        return '热点 Route 延迟压力调节'
      case 'adjust_for_latency_hot_host_route':
        return '热点 Host/Route 延迟压力调节'
      case 'rollback_due_to_handshake_global_regression':
        return '全局握手回滚'
      case 'rollback_due_to_budget_global_regression':
        return '全局预算回滚'
      case 'rollback_due_to_hot_host_regression':
        return '热点 Host 回滚'
      case 'rollback_due_to_hot_route_regression':
        return '热点 Route 回滚'
      case 'rollback_due_to_hot_host_route_regression':
        return '热点 Host/Route 回滚'
      default:
        return reason || 'none'
    }
  }

  function riskSeverityClass(status: string) {
    switch (status) {
      case 'regressed':
        return 'border-rose-200 bg-rose-50 text-rose-700'
      case 'stable':
        return 'border-amber-200 bg-amber-50 text-amber-700'
      case 'improved':
        return 'border-emerald-200 bg-emerald-50 text-emerald-700'
      default:
        return 'border-slate-200 bg-slate-50 text-slate-600'
    }
  }

  function hostRiskSeverityClass(item: {
    regressed_count: number
    stable_count: number
  }) {
    if (item.regressed_count > 0)
      return 'border-rose-200 bg-rose-50 text-rose-700'
    if (item.stable_count > 0)
      return 'border-amber-200 bg-amber-50 text-amber-700'
    return 'border-emerald-200 bg-emerald-50 text-emerald-700'
  }

  function hotspotViewButtonClass(view: 'host' | 'route') {
    return hotspotView.value === view
      ? 'border-blue-500 bg-blue-50 text-blue-700'
      : 'border-slate-200 bg-white text-slate-600 hover:border-slate-300'
  }

  return {
    autoTuningMode,
    autoTuningIntent,
    autoRuntimeAdjustEnabled,
    autoBootstrapSecs,
    autoControlIntervalSecs,
    autoCooldownSecs,
    autoMaxStepPercent,
    autoRollbackWindowMinutes,
    autoTlsHandshakeTimeoutRatePercent,
    autoBucketRejectRatePercent,
    autoP95ProxyLatencyMs,
    autoPinnedFieldsText,
    autoEffectEvaluation,
    hotspotView,
    autoRiskLeaderboard,
    autoRiskByHost,
    autoRiskByRoute,
    hotspotHeatmapCards,
    autoEffectStatusLabel,
    autoEffectStatusClass,
    formatSignedNumber,
    formatSignedInteger,
    segmentLabel,
    segmentStatusLabel,
    adjustReasonLabel,
    riskSeverityClass,
    hostRiskSeverityClass,
    hotspotViewButtonClass,
  }
}
