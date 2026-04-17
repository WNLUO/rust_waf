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

  const assignBaseFields = (target: L7ConfigForm, payload: L7ConfigPayload) => {
    Object.assign(target, {
      ...payload,
      listen_addrs: [...payload.listen_addrs],
      slow_attack_defense: {
        ...payload.slow_attack_defense,
      },
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
    return saveConfigInternal()
  }

  const saveConfigInternal = async () => {
    saving.value = true
    error.value = ''
    successMessage.value = ''

    try {
      const targetForm = configForm
      const response = await updateL7Config({
        upstream_healthcheck_enabled: targetForm.upstream_healthcheck_enabled,
        upstream_failure_mode: targetForm.upstream_failure_mode,
        upstream_protocol_policy: targetForm.upstream_protocol_policy,
        upstream_http1_strict_mode: targetForm.upstream_http1_strict_mode,
        upstream_http1_allow_connection_reuse:
          targetForm.upstream_http1_allow_connection_reuse,
        reject_ambiguous_http1_requests:
          targetForm.reject_ambiguous_http1_requests,
        reject_http1_transfer_encoding_requests:
          targetForm.reject_http1_transfer_encoding_requests,
        reject_body_on_safe_http_methods:
          targetForm.reject_body_on_safe_http_methods,
        reject_expect_100_continue: targetForm.reject_expect_100_continue,
        http2_enabled: targetForm.http2_enabled,
        bloom_enabled: targetForm.bloom_enabled,
        listen_addrs: [...targetForm.listen_addrs],
        upstream_endpoint: targetForm.upstream_endpoint,
        http3_enabled: targetForm.http3_enabled,
        http3_certificate_path: targetForm.http3_certificate_path,
        http3_private_key_path: targetForm.http3_private_key_path,
        http3_enable_tls13: targetForm.http3_enable_tls13,
      })
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
    saving,
    stats,
    successMessage,
    upstreamProtocolLabel,
    upstreamStatusText,
    upstreamStatusType,
    refreshing,
  }
}
