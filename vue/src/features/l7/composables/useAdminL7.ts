import { computed, onMounted, reactive, ref } from 'vue'
import {
  fetchL7Config,
  fetchL7Stats,
  updateL7Config,
} from '@/shared/api/l7'
import { fetchRulesList } from '@/shared/api/rules'
import { fetchSecurityEvents } from '@/shared/api/events'
import { createDefaultL7ConfigForm, type L7ConfigForm } from '@/features/l7/utils/adminL7'
import { useAdminRealtimeTopic } from '@/shared/realtime/adminRealtime'
import type {
  AdaptiveProtectionRuntimePayload,
  L7ConfigPayload,
  L7StatsPayload,
  SecurityEventsResponse,
  RuleItem,
  SecurityEventItem,
} from '@/shared/types'

const clampInteger = (
  value: number,
  min: number,
  max: number,
  fallback: number,
) => {
  const normalized = Number.isFinite(value) ? Math.round(value) : fallback
  return Math.min(Math.max(normalized, min), max)
}

const clampFloat = (
  value: number,
  min: number,
  max: number,
  fallback: number,
) => {
  const normalized = Number.isFinite(value) ? value : fallback
  return Math.min(Math.max(Number(normalized.toFixed(2)), min), max)
}

function splitTextareaList(value: string) {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean)
}

export function useAdminL7() {
  const loading = ref(true)
  const refreshing = ref(false)
  const saving = ref(false)
  const error = ref('')
  const successMessage = ref('')
  const stats = ref<L7StatsPayload | null>(null)
  const rules = ref<RuleItem[]>([])
  const events = ref<SecurityEventItem[]>([])
  const lastUpdated = ref<number | null>(null)
  const meta = ref({
    runtime_enabled: false,
    adaptive_managed_fields: false,
    adaptive_runtime: null as AdaptiveProtectionRuntimePayload | null,
  })

  const configForm = reactive<L7ConfigForm>(createDefaultL7ConfigForm())

  const applyConfig = (payload: L7ConfigPayload) => {
    Object.assign(configForm, {
      ...payload,
      trusted_proxy_cidrs: [...payload.trusted_proxy_cidrs],
      listen_addrs: [...payload.listen_addrs],
      cc_defense: {
        ...payload.cc_defense,
      },
      safeline_intercept: {
        ...payload.safeline_intercept,
        response_template: {
          ...payload.safeline_intercept.response_template,
          headers: [...payload.safeline_intercept.response_template.headers],
        },
      },
      auto_tuning: {
        ...payload.auto_tuning,
        pinned_fields: [...payload.auto_tuning.pinned_fields],
        slo: {
          ...payload.auto_tuning.slo,
        },
      },
    })

    meta.value = {
      runtime_enabled: payload.runtime_enabled,
      adaptive_managed_fields: payload.adaptive_managed_fields,
      adaptive_runtime: payload.adaptive_runtime,
    }
  }

  const refreshAll = async (showLoader = false) => {
    if (showLoader) loading.value = true
    refreshing.value = true

    try {
      const [configPayload, statsPayload, rulesPayload, eventsPayload] =
        await Promise.all([
          fetchL7Config(),
          fetchL7Stats(),
          fetchRulesList(),
          fetchSecurityEvents({
            layer: 'l7',
            limit: 6,
            sort_by: 'created_at',
            sort_direction: 'desc',
          }),
        ])

      applyConfig(configPayload)
      stats.value = statsPayload
      rules.value = rulesPayload.rules
      events.value = eventsPayload.events
      lastUpdated.value = Date.now()
      error.value = ''
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取 HTTP 接入管理信息失败'
    } finally {
      if (showLoader) loading.value = false
      refreshing.value = false
    }
  }

  const saveConfig = async () => {
    saving.value = true
    error.value = ''
    successMessage.value = ''

    try {
      configForm.max_request_size = clampInteger(
        configForm.max_request_size,
        1024,
        16_777_216,
        8192,
      )
      configForm.first_byte_timeout_ms = clampInteger(
        configForm.first_byte_timeout_ms,
        100,
        60_000,
        2000,
      )
      configForm.read_idle_timeout_ms = clampInteger(
        configForm.read_idle_timeout_ms,
        100,
        300_000,
        5000,
      )
      configForm.tls_handshake_timeout_ms = clampInteger(
        configForm.tls_handshake_timeout_ms,
        500,
        60_000,
        3000,
      )
      configForm.proxy_connect_timeout_ms = clampInteger(
        configForm.proxy_connect_timeout_ms,
        100,
        60_000,
        1500,
      )
      configForm.proxy_write_timeout_ms = clampInteger(
        configForm.proxy_write_timeout_ms,
        100,
        300_000,
        3000,
      )
      configForm.proxy_read_timeout_ms = clampInteger(
        configForm.proxy_read_timeout_ms,
        100,
        300_000,
        10000,
      )
      configForm.upstream_healthcheck_interval_secs = clampInteger(
        configForm.upstream_healthcheck_interval_secs,
        1,
        86_400,
        5,
      )
      configForm.upstream_healthcheck_timeout_ms = clampInteger(
        configForm.upstream_healthcheck_timeout_ms,
        100,
        60_000,
        1000,
      )
      configForm.bloom_filter_scale = clampFloat(
        configForm.bloom_filter_scale,
        0.1,
        4,
        1,
      )
      configForm.http2_max_concurrent_streams = clampInteger(
        configForm.http2_max_concurrent_streams,
        1,
        10_000,
        100,
      )
      configForm.http2_max_frame_size = clampInteger(
        configForm.http2_max_frame_size,
        1024,
        16_777_216,
        16384,
      )
      configForm.http2_initial_window_size = clampInteger(
        configForm.http2_initial_window_size,
        1024,
        16_777_216,
        65535,
      )
      configForm.http3_max_concurrent_streams = clampInteger(
        configForm.http3_max_concurrent_streams,
        1,
        1000,
        100,
      )
      configForm.http3_idle_timeout_secs = clampInteger(
        configForm.http3_idle_timeout_secs,
        1,
        86_400,
        300,
      )
      configForm.http3_mtu = clampInteger(
        configForm.http3_mtu,
        1200,
        1500,
        1350,
      )
      configForm.http3_max_frame_size = clampInteger(
        configForm.http3_max_frame_size,
        65536,
        16_777_215,
        65536,
      )
      configForm.http3_qpack_table_size = clampInteger(
        configForm.http3_qpack_table_size,
        1024,
        65536,
        4096,
      )
      configForm.cc_defense.request_window_secs = clampInteger(
        configForm.cc_defense.request_window_secs,
        3,
        120,
        10,
      )
      configForm.cc_defense.ip_challenge_threshold = clampInteger(
        configForm.cc_defense.ip_challenge_threshold,
        10,
        10000,
        60,
      )
      configForm.cc_defense.ip_block_threshold = clampInteger(
        configForm.cc_defense.ip_block_threshold,
        configForm.cc_defense.ip_challenge_threshold,
        20000,
        120,
      )
      configForm.cc_defense.host_challenge_threshold = clampInteger(
        configForm.cc_defense.host_challenge_threshold,
        5,
        configForm.cc_defense.ip_challenge_threshold,
        48,
      )
      configForm.cc_defense.host_block_threshold = clampInteger(
        configForm.cc_defense.host_block_threshold,
        configForm.cc_defense.host_challenge_threshold,
        configForm.cc_defense.ip_block_threshold,
        96,
      )
      configForm.cc_defense.route_challenge_threshold = clampInteger(
        configForm.cc_defense.route_challenge_threshold,
        3,
        configForm.cc_defense.host_challenge_threshold,
        24,
      )
      configForm.cc_defense.route_block_threshold = clampInteger(
        configForm.cc_defense.route_block_threshold,
        configForm.cc_defense.route_challenge_threshold,
        configForm.cc_defense.host_block_threshold,
        48,
      )
      configForm.cc_defense.hot_path_challenge_threshold = clampInteger(
        configForm.cc_defense.hot_path_challenge_threshold,
        32,
        200000,
        800,
      )
      configForm.cc_defense.hot_path_block_threshold = clampInteger(
        configForm.cc_defense.hot_path_block_threshold,
        configForm.cc_defense.hot_path_challenge_threshold,
        400000,
        1600,
      )
      configForm.cc_defense.delay_threshold_percent = clampInteger(
        configForm.cc_defense.delay_threshold_percent,
        25,
        95,
        70,
      )
      configForm.cc_defense.delay_ms = clampInteger(
        configForm.cc_defense.delay_ms,
        0,
        5000,
        150,
      )
      configForm.cc_defense.challenge_ttl_secs = clampInteger(
        configForm.cc_defense.challenge_ttl_secs,
        30,
        86400,
        1800,
      )
      configForm.cc_defense.challenge_cookie_name =
        configForm.cc_defense.challenge_cookie_name.trim().toLowerCase() || 'rwaf_cc'
      configForm.cc_defense.hard_route_block_multiplier = clampInteger(
        configForm.cc_defense.hard_route_block_multiplier,
        1,
        20,
        4,
      )
      configForm.cc_defense.hard_host_block_multiplier = clampInteger(
        configForm.cc_defense.hard_host_block_multiplier,
        1,
        20,
        4,
      )
      configForm.cc_defense.hard_ip_block_multiplier = clampInteger(
        configForm.cc_defense.hard_ip_block_multiplier,
        1,
        20,
        4,
      )
      configForm.cc_defense.hard_hot_path_block_multiplier = clampInteger(
        configForm.cc_defense.hard_hot_path_block_multiplier,
        1,
        20,
        3,
      )
      configForm.safeline_intercept.max_body_bytes = clampInteger(
        configForm.safeline_intercept.max_body_bytes,
        256,
        524288,
        32768,
      )
      configForm.safeline_intercept.block_duration_secs = clampInteger(
        configForm.safeline_intercept.block_duration_secs,
        30,
        86400,
        600,
      )
      configForm.safeline_intercept.response_template.status_code = clampInteger(
        configForm.safeline_intercept.response_template.status_code,
        100,
        599,
        403,
      )
      configForm.safeline_intercept.response_template.headers =
        configForm.safeline_intercept.response_template.headers
          .map((header) => ({
            key: header.key.trim(),
            value: header.value.trim(),
          }))
          .filter((header) => header.key)
      configForm.auto_tuning.bootstrap_secs = clampInteger(
        configForm.auto_tuning.bootstrap_secs,
        10,
        300,
        60,
      )
      configForm.auto_tuning.control_interval_secs = clampInteger(
        configForm.auto_tuning.control_interval_secs,
        10,
        300,
        30,
      )
      configForm.auto_tuning.cooldown_secs = clampInteger(
        configForm.auto_tuning.cooldown_secs,
        30,
        900,
        120,
      )
      configForm.auto_tuning.max_step_percent = clampInteger(
        configForm.auto_tuning.max_step_percent,
        1,
        25,
        8,
      )
      configForm.auto_tuning.rollback_window_minutes = clampInteger(
        configForm.auto_tuning.rollback_window_minutes,
        5,
        120,
        10,
      )
      configForm.auto_tuning.slo.tls_handshake_timeout_rate_percent = clampFloat(
        configForm.auto_tuning.slo.tls_handshake_timeout_rate_percent,
        0.1,
        20,
        0.3,
      )
      configForm.auto_tuning.slo.bucket_reject_rate_percent = clampFloat(
        configForm.auto_tuning.slo.bucket_reject_rate_percent,
        0.1,
        25,
        0.5,
      )
      configForm.auto_tuning.slo.p95_proxy_latency_ms = clampInteger(
        configForm.auto_tuning.slo.p95_proxy_latency_ms,
        50,
        30_000,
        800,
      )
      configForm.auto_tuning.pinned_fields = [
        ...new Set(
          configForm.auto_tuning.pinned_fields
            .map((item) => item.trim().toLowerCase())
            .filter(Boolean),
        ),
      ].slice(0, 64)
      if (
        configForm.auto_tuning.mode === 'off' ||
        configForm.auto_tuning.mode === 'observe'
      ) {
        configForm.auto_tuning.runtime_adjust_enabled = false
      }

      if (!configForm.bloom_enabled) {
        configForm.bloom_false_positive_verification = false
      }

      const response = await updateL7Config({ ...configForm })
      successMessage.value = response.message
      await refreshAll()
      return true
    } catch (e) {
      error.value = e instanceof Error ? e.message : '保存 HTTP 接入配置失败'
      return false
    } finally {
      saving.value = false
    }
  }

  const trustedProxyCidrsText = computed({
    get: () => configForm.trusted_proxy_cidrs.join('\n'),
    set: (value: string) => {
      configForm.trusted_proxy_cidrs = splitTextareaList(value)
    },
  })

  const listenAddrsText = computed({
    get: () => configForm.listen_addrs.join('\n'),
    set: (value: string) => {
      configForm.listen_addrs = splitTextareaList(value)
    },
  })

  const l7Rules = computed(() =>
    rules.value.filter((rule) => rule.layer === 'l7'),
  )
  const enabledL7Rules = computed(
    () => l7Rules.value.filter((rule) => rule.enabled).length,
  )
  const blockL7Rules = computed(
    () => l7Rules.value.filter((rule) => rule.action === 'block').length,
  )
  const proxySuccessRate = computed(() => {
    const total =
      (stats.value?.proxy_successes ?? 0) + (stats.value?.proxy_failures ?? 0)
    if (!total) return '暂无'
    return `${(((stats.value?.proxy_successes ?? 0) / total) * 100).toFixed(1)}%`
  })
  const runtimeStatus = computed(
    () => stats.value?.enabled ?? meta.value.runtime_enabled,
  )
  const runtimeProfileLabel = computed(() =>
    configForm.runtime_profile === 'standard' ? 'standard' : 'minimal',
  )
  const upstreamStatusText = computed(() =>
    stats.value?.upstream_healthy ? '健康' : '异常',
  )
  const upstreamStatusType = computed(() =>
    stats.value?.upstream_healthy ? 'success' : 'error',
  )
  const failureModeLabel = computed(() =>
    configForm.upstream_failure_mode === 'fail_close' ? '故障关闭' : '故障放行',
  )
  const http3StatusLabel = computed(() => {
    const status = stats.value?.http3_status || 'unknown'
    if (status === 'running') return '运行中'
    if (status === 'degraded') return '未就绪'
    if (status === 'unsupported') return '未编译支持'
    if (status === 'disabled') return '已关闭'
    return '待初始化'
  })
  const http3StatusType = computed(() => {
    const status = stats.value?.http3_status || 'unknown'
    if (status === 'running') return 'success'
    if (status === 'disabled') return 'muted'
    if (status === 'unsupported') return 'warning'
    return 'error'
  })
  const protocolTags = computed(() => [
    { text: 'HTTP/1.1 常驻', type: 'info' as const },
    {
      text: configForm.http2_enabled ? 'HTTP/2 已启用' : 'HTTP/2 未启用',
      type: configForm.http2_enabled
        ? ('success' as const)
        : ('muted' as const),
    },
    {
      text: configForm.http3_enabled ? 'HTTP/3 已启用' : 'HTTP/3 未启用',
      type: configForm.http3_enabled
        ? ('success' as const)
        : ('muted' as const),
    },
  ])

  useAdminRealtimeTopic<L7StatsPayload>('l7_stats', (payload) => {
    stats.value = payload
    lastUpdated.value = Date.now()
  })

  useAdminRealtimeTopic<SecurityEventsResponse>('recent_events', (payload) => {
    events.value = payload.events
      .filter((event) => event.layer.toLowerCase() === 'l7')
      .slice(0, 6)
    lastUpdated.value = Date.now()
  })

  onMounted(async () => {
    await refreshAll(true)
  })

  return {
    blockL7Rules,
    configForm,
    enabledL7Rules,
    error,
    events,
    failureModeLabel,
    http3StatusLabel,
    http3StatusType,
    l7Rules,
    lastUpdated,
    listenAddrsText,
    loading,
    meta,
    protocolTags,
    proxySuccessRate,
    refreshAll,
    rules,
    runtimeProfileLabel,
    runtimeStatus,
    saveConfig,
    saving,
    stats,
    successMessage,
    trustedProxyCidrsText,
    upstreamStatusText,
    upstreamStatusType,
    refreshing,
  }
}
