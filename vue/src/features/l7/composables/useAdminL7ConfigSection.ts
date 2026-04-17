import { computed, onMounted, ref } from 'vue'
import {
  fetchGlobalSettings,
  updateGlobalSettings,
} from '@/shared/api/settings'
import type { AutoTuningRuntimePayload } from '@/features/l7/types/l7'
import { useL7AutoTuningControls } from '@/features/l7/composables/useL7AutoTuningControls'
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

  const {
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
  } = useL7AutoTuningControls(props, updateForm)

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
