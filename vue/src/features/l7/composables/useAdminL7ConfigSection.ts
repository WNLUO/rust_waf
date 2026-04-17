import { computed, onMounted, ref } from 'vue'
import {
  fetchGlobalSettings,
  updateGlobalSettings,
} from '@/shared/api/settings'
import type { AutoTuningRuntimePayload } from '@/features/l7/types/l7'
import type { L7ConfigForm } from '@/features/l7/utils/adminL7'

export interface AdminL7ConfigSectionProps {
  form: L7ConfigForm
  trustedProxyCidrsText: string
  autoTuningRuntime?: AutoTuningRuntimePayload | null
  dropUnmatchedRequests: boolean
  dropUnmatchedRequestsDisabled?: boolean
  compatibilityMode?: boolean
  hideAdaptiveManagedSections?: boolean
}

export type AdminL7ConfigSectionEmit = {
  (event: 'update:form', value: L7ConfigForm): void
  (event: 'update:trustedProxyCidrsText', value: string): void
  (event: 'update:dropUnmatchedRequests', value: boolean): void
}

export function useAdminL7ConfigSection(
  props: AdminL7ConfigSectionProps,
  emit: AdminL7ConfigSectionEmit,
) {
  function updateForm<K extends keyof L7ConfigForm>(
    key: K,
    value: L7ConfigForm[K],
  ) {
    emit('update:form', { ...props.form, [key]: value })
  }

  function fieldModel<K extends keyof L7ConfigForm>(key: K) {
    return computed({
      get: () => props.form[key],
      set: (value) => updateForm(key, value),
    })
  }

  const http2Enabled = fieldModel('http2_enabled')
  const http10Enabled = ref(false)
  const http10Saving = ref(false)
  const bloomEnabled = fieldModel('bloom_enabled')
  const bloomVerifyEnabled = fieldModel('bloom_false_positive_verification')
  const healthcheckEnabled = fieldModel('upstream_healthcheck_enabled')
  const http3Enabled = fieldModel('http3_enabled')
  const runtimeProfile = fieldModel('runtime_profile')
  const failureMode = fieldModel('upstream_failure_mode')
  const upstreamProtocolPolicy = fieldModel('upstream_protocol_policy')
  const upstreamHttp1StrictMode = fieldModel('upstream_http1_strict_mode')
  const upstreamHttp1AllowConnectionReuse = fieldModel(
    'upstream_http1_allow_connection_reuse',
  )
  const rejectAmbiguousHttp1Requests = fieldModel(
    'reject_ambiguous_http1_requests',
  )
  const rejectHttp1TransferEncodingRequests = fieldModel(
    'reject_http1_transfer_encoding_requests',
  )
  const rejectBodyOnSafeHttpMethods = fieldModel(
    'reject_body_on_safe_http_methods',
  )
  const rejectExpect100Continue = fieldModel('reject_expect_100_continue')
  const maxRequestSize = fieldModel('max_request_size')
  const firstByteTimeout = fieldModel('first_byte_timeout_ms')
  const readIdleTimeout = fieldModel('read_idle_timeout_ms')
  const tlsHandshakeTimeout = fieldModel('tls_handshake_timeout_ms')
  const proxyConnectTimeout = fieldModel('proxy_connect_timeout_ms')
  const proxyWriteTimeout = fieldModel('proxy_write_timeout_ms')
  const proxyReadTimeout = fieldModel('proxy_read_timeout_ms')
  const bloomFilterScale = fieldModel('bloom_filter_scale')
  const healthcheckInterval = fieldModel('upstream_healthcheck_interval_secs')
  const healthcheckTimeout = fieldModel('upstream_healthcheck_timeout_ms')
  const http2MaxStreams = fieldModel('http2_max_concurrent_streams')
  const http2MaxFrameSize = fieldModel('http2_max_frame_size')
  const http2InitialWindowSize = fieldModel('http2_initial_window_size')
  const http2EnablePriorities = fieldModel('http2_enable_priorities')
  const http3MaxStreams = fieldModel('http3_max_concurrent_streams')
  const http3IdleTimeout = fieldModel('http3_idle_timeout_secs')
  const http3Mtu = fieldModel('http3_mtu')
  const http3MaxFrameSize = fieldModel('http3_max_frame_size')
  const http3QpackTableSize = fieldModel('http3_qpack_table_size')
  const http3CertificatePath = fieldModel('http3_certificate_path')
  const http3PrivateKeyPath = fieldModel('http3_private_key_path')
  const http3ConnectionMigration = fieldModel(
    'http3_enable_connection_migration',
  )
  const http3Tls13Enabled = fieldModel('http3_enable_tls13')

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

  function updateCcDefense(patch: Partial<L7ConfigForm['cc_defense']>) {
    updateForm('cc_defense', {
      ...props.form.cc_defense,
      ...patch,
    })
  }

  const ccDefenseEnabled = computed({
    get: () => props.form.cc_defense.enabled,
    set: (value: boolean) => updateCcDefense({ enabled: value }),
  })

  const ccRequestWindow = computed({
    get: () => props.form.cc_defense.request_window_secs,
    set: (value: number) => updateCcDefense({ request_window_secs: value }),
  })

  const ccIpChallengeThreshold = computed({
    get: () => props.form.cc_defense.ip_challenge_threshold,
    set: (value: number) => updateCcDefense({ ip_challenge_threshold: value }),
  })

  const ccIpBlockThreshold = computed({
    get: () => props.form.cc_defense.ip_block_threshold,
    set: (value: number) => updateCcDefense({ ip_block_threshold: value }),
  })

  const ccHostChallengeThreshold = computed({
    get: () => props.form.cc_defense.host_challenge_threshold,
    set: (value: number) =>
      updateCcDefense({ host_challenge_threshold: value }),
  })

  const ccHostBlockThreshold = computed({
    get: () => props.form.cc_defense.host_block_threshold,
    set: (value: number) => updateCcDefense({ host_block_threshold: value }),
  })

  const ccRouteChallengeThreshold = computed({
    get: () => props.form.cc_defense.route_challenge_threshold,
    set: (value: number) =>
      updateCcDefense({ route_challenge_threshold: value }),
  })

  const ccRouteBlockThreshold = computed({
    get: () => props.form.cc_defense.route_block_threshold,
    set: (value: number) => updateCcDefense({ route_block_threshold: value }),
  })

  const ccHotPathChallengeThreshold = computed({
    get: () => props.form.cc_defense.hot_path_challenge_threshold,
    set: (value: number) =>
      updateCcDefense({ hot_path_challenge_threshold: value }),
  })

  const ccHotPathBlockThreshold = computed({
    get: () => props.form.cc_defense.hot_path_block_threshold,
    set: (value: number) =>
      updateCcDefense({ hot_path_block_threshold: value }),
  })

  const ccDelayThresholdPercent = computed({
    get: () => props.form.cc_defense.delay_threshold_percent,
    set: (value: number) => updateCcDefense({ delay_threshold_percent: value }),
  })

  const ccDelayMs = computed({
    get: () => props.form.cc_defense.delay_ms,
    set: (value: number) => updateCcDefense({ delay_ms: value }),
  })

  const ccChallengeTtl = computed({
    get: () => props.form.cc_defense.challenge_ttl_secs,
    set: (value: number) => updateCcDefense({ challenge_ttl_secs: value }),
  })

  const ccChallengeCookieName = computed({
    get: () => props.form.cc_defense.challenge_cookie_name,
    set: (value: string) => updateCcDefense({ challenge_cookie_name: value }),
  })

  const ccHardRouteBlockMultiplier = computed({
    get: () => props.form.cc_defense.hard_route_block_multiplier,
    set: (value: number) =>
      updateCcDefense({ hard_route_block_multiplier: value }),
  })

  const ccHardHostBlockMultiplier = computed({
    get: () => props.form.cc_defense.hard_host_block_multiplier,
    set: (value: number) =>
      updateCcDefense({ hard_host_block_multiplier: value }),
  })

  const ccHardIpBlockMultiplier = computed({
    get: () => props.form.cc_defense.hard_ip_block_multiplier,
    set: (value: number) =>
      updateCcDefense({ hard_ip_block_multiplier: value }),
  })

  const ccHardHotPathBlockMultiplier = computed({
    get: () => props.form.cc_defense.hard_hot_path_block_multiplier,
    set: (value: number) =>
      updateCcDefense({ hard_hot_path_block_multiplier: value }),
  })

  function updateSlowAttackDefense(
    patch: Partial<L7ConfigForm['slow_attack_defense']>,
  ) {
    updateForm('slow_attack_defense', {
      ...props.form.slow_attack_defense,
      ...patch,
    })
  }

  const slowAttackDefenseEnabled = computed({
    get: () => props.form.slow_attack_defense.enabled,
    set: (value: boolean) => updateSlowAttackDefense({ enabled: value }),
  })

  const slowAttackHeaderMinRate = computed({
    get: () => props.form.slow_attack_defense.header_min_bytes_per_sec,
    set: (value: number) =>
      updateSlowAttackDefense({ header_min_bytes_per_sec: value }),
  })

  const slowAttackBodyMinRate = computed({
    get: () => props.form.slow_attack_defense.body_min_bytes_per_sec,
    set: (value: number) =>
      updateSlowAttackDefense({ body_min_bytes_per_sec: value }),
  })

  const slowAttackIdleKeepaliveTimeout = computed({
    get: () => props.form.slow_attack_defense.idle_keepalive_timeout_ms,
    set: (value: number) =>
      updateSlowAttackDefense({ idle_keepalive_timeout_ms: value }),
  })

  const slowAttackEventWindow = computed({
    get: () => props.form.slow_attack_defense.event_window_secs,
    set: (value: number) =>
      updateSlowAttackDefense({ event_window_secs: value }),
  })

  const slowAttackMaxEvents = computed({
    get: () => props.form.slow_attack_defense.max_events_per_window,
    set: (value: number) =>
      updateSlowAttackDefense({ max_events_per_window: value }),
  })

  const slowAttackBlockDuration = computed({
    get: () => props.form.slow_attack_defense.block_duration_secs,
    set: (value: number) =>
      updateSlowAttackDefense({ block_duration_secs: value }),
  })

  function updateSafelineIntercept(
    patch: Partial<L7ConfigForm['safeline_intercept']>,
  ) {
    updateForm('safeline_intercept', {
      ...props.form.safeline_intercept,
      ...patch,
    })
  }

  function updateSafelineResponseTemplate(
    patch: Partial<L7ConfigForm['safeline_intercept']['response_template']>,
  ) {
    updateSafelineIntercept({
      response_template: {
        ...props.form.safeline_intercept.response_template,
        ...patch,
      },
    })
  }

  const safelineInterceptEnabled = computed({
    get: () => props.form.safeline_intercept.enabled,
    set: (value: boolean) => updateSafelineIntercept({ enabled: value }),
  })

  const safelineInterceptAction = computed({
    get: () => props.form.safeline_intercept.action,
    set: (value: string) => updateSafelineIntercept({ action: value }),
  })

  const safelineInterceptMatchMode = computed({
    get: () => props.form.safeline_intercept.match_mode,
    set: (value: string) => updateSafelineIntercept({ match_mode: value }),
  })

  const safelineInterceptMaxBodyBytes = computed({
    get: () => props.form.safeline_intercept.max_body_bytes,
    set: (value: number) => updateSafelineIntercept({ max_body_bytes: value }),
  })

  const safelineInterceptBlockDuration = computed({
    get: () => props.form.safeline_intercept.block_duration_secs,
    set: (value: number) =>
      updateSafelineIntercept({ block_duration_secs: value }),
  })

  const safelineResponseStatusCode = computed({
    get: () => props.form.safeline_intercept.response_template.status_code,
    set: (value: number) =>
      updateSafelineResponseTemplate({ status_code: value }),
  })

  const safelineResponseContentType = computed({
    get: () => props.form.safeline_intercept.response_template.content_type,
    set: (value: string) =>
      updateSafelineResponseTemplate({ content_type: value }),
  })

  const contentTypeDialogOpen = ref(false)
  const contentTypeDraft = ref('')
  const contentTypeOptions = [
    'text/html; charset=utf-8',
    'text/plain; charset=utf-8',
    'application/json; charset=utf-8',
    'text/xml; charset=utf-8',
  ]

  async function loadHttp10Setting() {
    try {
      const settings = await fetchGlobalSettings()
      http10Enabled.value = settings.enable_http1_0
    } catch {
      // Keep the UI usable even if the global setting request fails.
    }
  }

  async function handleHttp10Toggle(nextValue: boolean) {
    const previous = http10Enabled.value
    http10Enabled.value = nextValue
    http10Saving.value = true
    try {
      const latest = await fetchGlobalSettings()
      await updateGlobalSettings({
        ...latest,
        enable_http1_0: nextValue,
      })
    } catch {
      http10Enabled.value = previous
    } finally {
      http10Saving.value = false
    }
  }

  function openContentTypeDialog() {
    contentTypeDraft.value = safelineResponseContentType.value
    contentTypeDialogOpen.value = true
  }

  function selectContentTypeOption(value: string) {
    contentTypeDraft.value = value
  }

  function confirmContentTypeDialog() {
    safelineResponseContentType.value = contentTypeDraft.value.trim()
    contentTypeDialogOpen.value = false
  }

  function closeContentTypeDialog() {
    contentTypeDialogOpen.value = false
  }

  onMounted(() => {
    void loadHttp10Setting()
  })

  const safelineResponseBodySource = computed({
    get: () => props.form.safeline_intercept.response_template.body_source,
    set: (value: string) =>
      updateSafelineResponseTemplate({ body_source: value }),
  })

  return {
    http2Enabled,
    http10Enabled,
    http10Saving,
    bloomEnabled,
    bloomVerifyEnabled,
    healthcheckEnabled,
    http3Enabled,
    runtimeProfile,
    failureMode,
    upstreamProtocolPolicy,
    upstreamHttp1StrictMode,
    upstreamHttp1AllowConnectionReuse,
    rejectAmbiguousHttp1Requests,
    rejectHttp1TransferEncodingRequests,
    rejectBodyOnSafeHttpMethods,
    rejectExpect100Continue,
    maxRequestSize,
    firstByteTimeout,
    readIdleTimeout,
    tlsHandshakeTimeout,
    proxyConnectTimeout,
    proxyWriteTimeout,
    proxyReadTimeout,
    bloomFilterScale,
    healthcheckInterval,
    healthcheckTimeout,
    http2MaxStreams,
    http2MaxFrameSize,
    http2InitialWindowSize,
    http2EnablePriorities,
    http3MaxStreams,
    http3IdleTimeout,
    http3Mtu,
    http3MaxFrameSize,
    http3QpackTableSize,
    http3CertificatePath,
    http3PrivateKeyPath,
    http3ConnectionMigration,
    http3Tls13Enabled,
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
    ccDefenseEnabled,
    ccRequestWindow,
    ccIpChallengeThreshold,
    ccIpBlockThreshold,
    ccHostChallengeThreshold,
    ccHostBlockThreshold,
    ccRouteChallengeThreshold,
    ccRouteBlockThreshold,
    ccHotPathChallengeThreshold,
    ccHotPathBlockThreshold,
    ccDelayThresholdPercent,
    ccDelayMs,
    ccChallengeTtl,
    ccChallengeCookieName,
    ccHardRouteBlockMultiplier,
    ccHardHostBlockMultiplier,
    ccHardIpBlockMultiplier,
    ccHardHotPathBlockMultiplier,
    slowAttackDefenseEnabled,
    slowAttackHeaderMinRate,
    slowAttackBodyMinRate,
    slowAttackIdleKeepaliveTimeout,
    slowAttackEventWindow,
    slowAttackMaxEvents,
    slowAttackBlockDuration,
    safelineInterceptEnabled,
    safelineInterceptAction,
    safelineInterceptMatchMode,
    safelineInterceptMaxBodyBytes,
    safelineInterceptBlockDuration,
    safelineResponseStatusCode,
    safelineResponseContentType,
    contentTypeDialogOpen,
    contentTypeDraft,
    contentTypeOptions,
    handleHttp10Toggle,
    openContentTypeDialog,
    selectContentTypeOption,
    confirmContentTypeDialog,
    closeContentTypeDialog,
    safelineResponseBodySource,
  }
}
