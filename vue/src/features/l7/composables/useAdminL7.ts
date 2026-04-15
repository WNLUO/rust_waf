import { computed, onMounted, reactive, ref } from 'vue'
import {
  fetchL7Config,
  fetchL7Stats,
  updateL7CompatibilityConfig,
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
  const compatibilityForm = reactive<L7ConfigForm>(createDefaultL7ConfigForm())

  const assignBaseFields = (target: L7ConfigForm, payload: L7ConfigPayload) => {
    Object.assign(target, {
      ...payload,
      trusted_proxy_cidrs: [...payload.trusted_proxy_cidrs],
      listen_addrs: [...payload.listen_addrs],
      safeline_intercept: {
        ...payload.safeline_intercept,
        response_template: {
          ...payload.safeline_intercept.response_template,
          headers: [...payload.safeline_intercept.response_template.headers],
        },
      },
    })
  }

  const applyConfig = (payload: L7ConfigPayload) => {
    assignBaseFields(configForm, payload)
    Object.assign(configForm, {
      cc_defense: {
        ...payload.cc_defense,
      },
      auto_tuning: {
        ...payload.auto_tuning,
        pinned_fields: [...payload.auto_tuning.pinned_fields],
        slo: {
          ...payload.auto_tuning.slo,
        },
      },
    })
    assignBaseFields(compatibilityForm, payload)
    Object.assign(compatibilityForm, {
      cc_defense: {
        ...payload.advanced_compatibility.persisted_cc_defense,
      },
      auto_tuning: {
        ...payload.advanced_compatibility.persisted_auto_tuning,
        pinned_fields: [
          ...payload.advanced_compatibility.persisted_auto_tuning.pinned_fields,
        ],
        slo: {
          ...payload.advanced_compatibility.persisted_auto_tuning.slo,
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
    return saveConfigInternal(false)
  }

  const saveCompatibilityConfig = async () => {
    return saveConfigInternal(true)
  }

  const saveConfigInternal = async (compatibilityMode: boolean) => {
    saving.value = true
    error.value = ''
    successMessage.value = ''

    try {
      const targetForm = compatibilityMode ? compatibilityForm : configForm

      targetForm.max_request_size = clampInteger(
        targetForm.max_request_size,
        1024,
        16_777_216,
        8192,
      )
      targetForm.first_byte_timeout_ms = clampInteger(
        targetForm.first_byte_timeout_ms,
        100,
        60_000,
        2000,
      )
      targetForm.read_idle_timeout_ms = clampInteger(
        targetForm.read_idle_timeout_ms,
        100,
        300_000,
        5000,
      )
      targetForm.tls_handshake_timeout_ms = clampInteger(
        targetForm.tls_handshake_timeout_ms,
        500,
        60_000,
        3000,
      )
      targetForm.proxy_connect_timeout_ms = clampInteger(
        targetForm.proxy_connect_timeout_ms,
        100,
        60_000,
        1500,
      )
      targetForm.proxy_write_timeout_ms = clampInteger(
        targetForm.proxy_write_timeout_ms,
        100,
        300_000,
        3000,
      )
      targetForm.proxy_read_timeout_ms = clampInteger(
        targetForm.proxy_read_timeout_ms,
        100,
        300_000,
        10000,
      )
      targetForm.upstream_healthcheck_interval_secs = clampInteger(
        targetForm.upstream_healthcheck_interval_secs,
        1,
        86_400,
        5,
      )
      targetForm.upstream_healthcheck_timeout_ms = clampInteger(
        targetForm.upstream_healthcheck_timeout_ms,
        100,
        60_000,
        1000,
      )
      targetForm.bloom_filter_scale = clampFloat(
        targetForm.bloom_filter_scale,
        0.1,
        4,
        1,
      )
      targetForm.http2_max_concurrent_streams = clampInteger(
        targetForm.http2_max_concurrent_streams,
        1,
        10_000,
        100,
      )
      targetForm.http2_max_frame_size = clampInteger(
        targetForm.http2_max_frame_size,
        1024,
        16_777_216,
        16384,
      )
      targetForm.http2_initial_window_size = clampInteger(
        targetForm.http2_initial_window_size,
        1024,
        16_777_216,
        65535,
      )
      targetForm.http3_max_concurrent_streams = clampInteger(
        targetForm.http3_max_concurrent_streams,
        1,
        1000,
        100,
      )
      targetForm.http3_idle_timeout_secs = clampInteger(
        targetForm.http3_idle_timeout_secs,
        1,
        86_400,
        300,
      )
      targetForm.http3_mtu = clampInteger(
        targetForm.http3_mtu,
        1200,
        1500,
        1350,
      )
      targetForm.http3_max_frame_size = clampInteger(
        targetForm.http3_max_frame_size,
        65536,
        16_777_215,
        65536,
      )
      targetForm.http3_qpack_table_size = clampInteger(
        targetForm.http3_qpack_table_size,
        1024,
        65536,
        4096,
      )
      targetForm.cc_defense.request_window_secs = clampInteger(
        targetForm.cc_defense.request_window_secs,
        3,
        120,
        10,
      )
      targetForm.cc_defense.ip_challenge_threshold = clampInteger(
        targetForm.cc_defense.ip_challenge_threshold,
        10,
        10000,
        60,
      )
      targetForm.cc_defense.ip_block_threshold = clampInteger(
        targetForm.cc_defense.ip_block_threshold,
        targetForm.cc_defense.ip_challenge_threshold,
        20000,
        120,
      )
      targetForm.cc_defense.host_challenge_threshold = clampInteger(
        targetForm.cc_defense.host_challenge_threshold,
        5,
        targetForm.cc_defense.ip_challenge_threshold,
        48,
      )
      targetForm.cc_defense.host_block_threshold = clampInteger(
        targetForm.cc_defense.host_block_threshold,
        targetForm.cc_defense.host_challenge_threshold,
        targetForm.cc_defense.ip_block_threshold,
        96,
      )
      targetForm.cc_defense.route_challenge_threshold = clampInteger(
        targetForm.cc_defense.route_challenge_threshold,
        3,
        targetForm.cc_defense.host_challenge_threshold,
        24,
      )
      targetForm.cc_defense.route_block_threshold = clampInteger(
        targetForm.cc_defense.route_block_threshold,
        targetForm.cc_defense.route_challenge_threshold,
        targetForm.cc_defense.host_block_threshold,
        48,
      )
      targetForm.cc_defense.hot_path_challenge_threshold = clampInteger(
        targetForm.cc_defense.hot_path_challenge_threshold,
        32,
        200000,
        800,
      )
      targetForm.cc_defense.hot_path_block_threshold = clampInteger(
        targetForm.cc_defense.hot_path_block_threshold,
        targetForm.cc_defense.hot_path_challenge_threshold,
        400000,
        1600,
      )
      targetForm.cc_defense.delay_threshold_percent = clampInteger(
        targetForm.cc_defense.delay_threshold_percent,
        25,
        95,
        70,
      )
      targetForm.cc_defense.delay_ms = clampInteger(
        targetForm.cc_defense.delay_ms,
        0,
        5000,
        150,
      )
      targetForm.cc_defense.challenge_ttl_secs = clampInteger(
        targetForm.cc_defense.challenge_ttl_secs,
        30,
        86400,
        1800,
      )
      targetForm.cc_defense.challenge_cookie_name =
        targetForm.cc_defense.challenge_cookie_name.trim().toLowerCase() || 'rwaf_cc'
      targetForm.cc_defense.hard_route_block_multiplier = clampInteger(
        targetForm.cc_defense.hard_route_block_multiplier,
        1,
        20,
        4,
      )
      targetForm.cc_defense.hard_host_block_multiplier = clampInteger(
        targetForm.cc_defense.hard_host_block_multiplier,
        1,
        20,
        4,
      )
      targetForm.cc_defense.hard_ip_block_multiplier = clampInteger(
        targetForm.cc_defense.hard_ip_block_multiplier,
        1,
        20,
        4,
      )
      targetForm.cc_defense.hard_hot_path_block_multiplier = clampInteger(
        targetForm.cc_defense.hard_hot_path_block_multiplier,
        1,
        20,
        3,
      )
      targetForm.safeline_intercept.max_body_bytes = clampInteger(
        targetForm.safeline_intercept.max_body_bytes,
        256,
        524288,
        32768,
      )
      targetForm.safeline_intercept.block_duration_secs = clampInteger(
        targetForm.safeline_intercept.block_duration_secs,
        30,
        86400,
        600,
      )
      targetForm.safeline_intercept.response_template.status_code = clampInteger(
        targetForm.safeline_intercept.response_template.status_code,
        100,
        599,
        403,
      )
      targetForm.safeline_intercept.response_template.headers =
        targetForm.safeline_intercept.response_template.headers
          .map((header) => ({
            key: header.key.trim(),
            value: header.value.trim(),
          }))
          .filter((header) => header.key)
      targetForm.auto_tuning.bootstrap_secs = clampInteger(
        targetForm.auto_tuning.bootstrap_secs,
        10,
        300,
        60,
      )
      targetForm.auto_tuning.control_interval_secs = clampInteger(
        targetForm.auto_tuning.control_interval_secs,
        10,
        300,
        30,
      )
      targetForm.auto_tuning.cooldown_secs = clampInteger(
        targetForm.auto_tuning.cooldown_secs,
        30,
        900,
        120,
      )
      targetForm.auto_tuning.max_step_percent = clampInteger(
        targetForm.auto_tuning.max_step_percent,
        1,
        25,
        8,
      )
      targetForm.auto_tuning.rollback_window_minutes = clampInteger(
        targetForm.auto_tuning.rollback_window_minutes,
        5,
        120,
        10,
      )
      targetForm.auto_tuning.slo.tls_handshake_timeout_rate_percent = clampFloat(
        targetForm.auto_tuning.slo.tls_handshake_timeout_rate_percent,
        0.1,
        20,
        0.3,
      )
      targetForm.auto_tuning.slo.bucket_reject_rate_percent = clampFloat(
        targetForm.auto_tuning.slo.bucket_reject_rate_percent,
        0.1,
        25,
        0.5,
      )
      targetForm.auto_tuning.slo.p95_proxy_latency_ms = clampInteger(
        targetForm.auto_tuning.slo.p95_proxy_latency_ms,
        50,
        30_000,
        800,
      )
      targetForm.auto_tuning.pinned_fields = [
        ...new Set(
          targetForm.auto_tuning.pinned_fields
            .map((item) => item.trim().toLowerCase())
            .filter(Boolean),
        ),
      ].slice(0, 64)
      if (
        targetForm.auto_tuning.mode === 'off' ||
        targetForm.auto_tuning.mode === 'observe'
      ) {
        targetForm.auto_tuning.runtime_adjust_enabled = false
      }

      if (!targetForm.bloom_enabled) {
        targetForm.bloom_false_positive_verification = false
      }

      const response = compatibilityMode
        ? await updateL7CompatibilityConfig({ ...targetForm })
        : await updateL7Config({ ...targetForm })
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
  const upstreamProtocolLabel = computed(() => {
    switch (configForm.upstream_protocol_policy) {
      case 'http2_only':
        return '仅 HTTP/2'
      case 'http2_preferred':
        return '优先 HTTP/2'
      case 'http1_only':
        return '仅 HTTP/1.1'
      case 'auto':
        return '自动选择'
      default:
        return configForm.upstream_protocol_policy || '未知'
    }
  })
  const http1SecurityLabel = computed(() =>
    configForm.upstream_http1_strict_mode ? 'H1 严格模式' : 'H1 兼容模式',
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
    {
      text: `上游 ${upstreamProtocolLabel.value}`,
      type:
        configForm.upstream_protocol_policy === 'http1_only'
          ? ('warning' as const)
          : ('info' as const),
    },
    {
      text: http1SecurityLabel.value,
      type: configForm.upstream_http1_strict_mode ? ('success' as const) : ('warning' as const),
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
    compatibilityForm,
    configForm,
    enabledL7Rules,
    error,
    events,
    failureModeLabel,
    http1SecurityLabel,
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
    saveCompatibilityConfig,
    saving,
    stats,
    successMessage,
    trustedProxyCidrsText,
    upstreamProtocolLabel,
    upstreamStatusText,
    upstreamStatusType,
    refreshing,
  }
}
