import { computed, onMounted, reactive, ref } from 'vue'
import {
  fetchL4Config,
  fetchL4Stats,
  updateL4Config,
} from '@/shared/api/l4'
import { createDefaultL4ConfigForm, type L4ConfigForm } from '@/features/l4/utils/adminL4'
import type {
  AdaptiveProtectionRuntimePayload,
  L4BehaviorOverview,
  L4ConfigPayload,
  L4StatsPayload,
} from '@/shared/types'
import { useAdminRealtimeTopic } from '@/shared/realtime/adminRealtime'

const clampInteger = (
  value: number,
  min: number,
  max: number,
  fallback: number,
) => {
  const normalized = Number.isFinite(value) ? Math.round(value) : fallback
  return Math.min(Math.max(normalized, min), max)
}

export function useAdminL4() {
  const loading = ref(true)
  const refreshing = ref(false)
  const saving = ref(false)
  const error = ref('')
  const successMessage = ref('')
  const stats = ref<L4StatsPayload | null>(null)
  const lastUpdated = ref<number | null>(null)
  const meta = ref({
    runtime_enabled: false,
    bloom_enabled: true,
    bloom_false_positive_verification: true,
    runtime_profile: 'standard',
    adaptive_managed_fields: false,
    adaptive_runtime: null as AdaptiveProtectionRuntimePayload | null,
  })

  const configForm = reactive<L4ConfigForm>(createDefaultL4ConfigForm())

  const assignBaseFields = (target: L4ConfigForm, payload: L4ConfigPayload) => {
    Object.assign(target, {
      ddos_protection_enabled: payload.ddos_protection_enabled,
      advanced_ddos_enabled: payload.advanced_ddos_enabled,
      connection_rate_limit: payload.connection_rate_limit,
      syn_flood_threshold: payload.syn_flood_threshold,
      max_tracked_ips: payload.max_tracked_ips,
      max_blocked_ips: payload.max_blocked_ips,
      state_ttl_secs: payload.state_ttl_secs,
      bloom_filter_scale: payload.bloom_filter_scale,
      trusted_cdn: {
        manual_cidrs: [...payload.trusted_cdn.manual_cidrs],
        effective_cidrs: [...payload.trusted_cdn.effective_cidrs],
        sync_interval_value: payload.trusted_cdn.sync_interval_value,
        sync_interval_unit: payload.trusted_cdn.sync_interval_unit,
        edgeone_overseas: {
          ...payload.trusted_cdn.edgeone_overseas,
          synced_cidrs: [...payload.trusted_cdn.edgeone_overseas.synced_cidrs],
        },
        aliyun_esa: {
          ...payload.trusted_cdn.aliyun_esa,
          synced_cidrs: [...payload.trusted_cdn.aliyun_esa.synced_cidrs],
        },
      },
    })
  }

  const applyConfig = (payload: L4ConfigPayload) => {
    assignBaseFields(configForm, payload)
    Object.assign(configForm, {
      behavior_event_channel_capacity: payload.behavior_event_channel_capacity,
      behavior_drop_critical_threshold: payload.behavior_drop_critical_threshold,
      behavior_fallback_ratio_percent: payload.behavior_fallback_ratio_percent,
      behavior_overload_blocked_connections_threshold:
        payload.behavior_overload_blocked_connections_threshold,
      behavior_overload_active_connections_threshold:
        payload.behavior_overload_active_connections_threshold,
      behavior_normal_connection_budget_per_minute:
        payload.behavior_normal_connection_budget_per_minute,
      behavior_suspicious_connection_budget_per_minute:
        payload.behavior_suspicious_connection_budget_per_minute,
      behavior_high_risk_connection_budget_per_minute:
        payload.behavior_high_risk_connection_budget_per_minute,
      behavior_high_overload_budget_scale_percent:
        payload.behavior_high_overload_budget_scale_percent,
      behavior_critical_overload_budget_scale_percent:
        payload.behavior_critical_overload_budget_scale_percent,
      behavior_high_overload_delay_ms: payload.behavior_high_overload_delay_ms,
      behavior_critical_overload_delay_ms:
        payload.behavior_critical_overload_delay_ms,
      behavior_soft_delay_threshold_percent:
        payload.behavior_soft_delay_threshold_percent,
      behavior_hard_delay_threshold_percent:
        payload.behavior_hard_delay_threshold_percent,
      behavior_soft_delay_ms: payload.behavior_soft_delay_ms,
      behavior_hard_delay_ms: payload.behavior_hard_delay_ms,
      behavior_reject_threshold_percent:
        payload.behavior_reject_threshold_percent,
      behavior_critical_reject_threshold_percent:
        payload.behavior_critical_reject_threshold_percent,
    })
    meta.value = {
      runtime_enabled: payload.runtime_enabled,
      bloom_enabled: payload.bloom_enabled,
      bloom_false_positive_verification:
        payload.bloom_false_positive_verification,
      runtime_profile: payload.runtime_profile,
      adaptive_managed_fields: payload.adaptive_managed_fields,
      adaptive_runtime: payload.adaptive_runtime,
    }
  }

  const refreshAll = async (showLoader = false) => {
    if (showLoader) loading.value = true
    refreshing.value = true

    try {
      const [configPayload, statsPayload] = await Promise.all([
        fetchL4Config(),
        fetchL4Stats(),
      ])

      applyConfig(configPayload)
      stats.value = statsPayload
      lastUpdated.value = Date.now()
      error.value = ''
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取 L4 管理信息失败'
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

      targetForm.trusted_cdn.sync_interval_value = clampInteger(
        targetForm.trusted_cdn.sync_interval_value,
        1,
        365,
        12,
      )

      const response = await updateL4Config({
        ddos_protection_enabled: targetForm.ddos_protection_enabled,
        advanced_ddos_enabled: targetForm.advanced_ddos_enabled,
        trusted_cdn: {
          manual_cidrs: [...targetForm.trusted_cdn.manual_cidrs],
          sync_interval_value: targetForm.trusted_cdn.sync_interval_value,
          sync_interval_unit: targetForm.trusted_cdn.sync_interval_unit,
          edgeone_overseas: {
            enabled: targetForm.trusted_cdn.edgeone_overseas.enabled,
          },
          aliyun_esa: {
            enabled: targetForm.trusted_cdn.aliyun_esa.enabled,
            site_id: targetForm.trusted_cdn.aliyun_esa.site_id,
            access_key_id: targetForm.trusted_cdn.aliyun_esa.access_key_id,
            access_key_secret: targetForm.trusted_cdn.aliyun_esa.access_key_secret,
            endpoint: targetForm.trusted_cdn.aliyun_esa.endpoint,
          },
        },
      })
      successMessage.value = response.message
      await refreshAll()
      return true
    } catch (e) {
      error.value = e instanceof Error ? e.message : '保存 L4 配置失败'
      return false
    } finally {
      saving.value = false
    }
  }

  const runtimeStatus = computed(
    () => stats.value?.enabled ?? meta.value.runtime_enabled,
  )
  const runtimeProfileLabel = computed(() =>
    meta.value.runtime_profile === 'standard' ? 'standard' : 'minimal',
  )
  const behaviorOverview = computed(
    () =>
      stats.value?.behavior.overview ?? ({
        bucket_count: 0,
        fine_grained_buckets: 0,
        coarse_buckets: 0,
        peer_only_buckets: 0,
        normal_buckets: 0,
        suspicious_buckets: 0,
        high_risk_buckets: 0,
        safeline_feedback_hits: 0,
        l7_feedback_hits: 0,
        dropped_events: 0,
        overload_level: 'normal',
        overload_reason: null,
      } satisfies L4BehaviorOverview),
  )
  const topBuckets = computed(() => stats.value?.behavior.top_buckets ?? [])
  const topPorts = computed(() => stats.value?.per_port_stats ?? [])
  const bloomPanels = computed(() => {
    const bloomStats = stats.value?.bloom_stats
    if (!bloomStats) return []

    return [
      { label: 'IPv4 命中', value: bloomStats.ipv4_filter },
      { label: 'IPv6 命中', value: bloomStats.ipv6_filter },
      { label: 'IP:Port 命中', value: bloomStats.ip_port_filter },
    ]
  })
  const falsePositivePanels = computed(() => {
    const falsePositiveStats = stats.value?.false_positive_stats
    if (!falsePositiveStats) return []

    return [
      { label: 'IPv4 精确校验集', value: falsePositiveStats.ipv4_exact_size },
      { label: 'IPv6 精确校验集', value: falsePositiveStats.ipv6_exact_size },
      {
        label: 'IP:Port 精确校验集',
        value: falsePositiveStats.ip_port_exact_size,
      },
    ]
  })
  const blockedCapacityRatio = computed(() => {
    const maxBlocked = configForm.max_blocked_ips
    if (!maxBlocked) return 0
    return (stats.value?.connections.blocked_connections ?? 0) / maxBlocked
  })
  const blockedCapacityLabel = computed(() => {
    if (!configForm.max_blocked_ips) return '未配置上限'
    return `${Math.min(blockedCapacityRatio.value * 100, 999).toFixed(1)}%`
  })
  const blockedCapacityTone = computed(() => {
    if (blockedCapacityRatio.value >= 0.85) return 'error'
    if (blockedCapacityRatio.value >= 0.6) return 'warning'
    return 'success'
  })
  const totalProcessedBytes = computed(() =>
    topPorts.value.reduce((sum, item) => sum + item.bytes_processed, 0),
  )

  useAdminRealtimeTopic<L4StatsPayload>('l4_stats', (payload) => {
    stats.value = payload
    lastUpdated.value = Date.now()
  })

  onMounted(async () => {
    await refreshAll(true)
  })

  return {
    behaviorOverview,
    blockedCapacityLabel,
    blockedCapacityTone,
    bloomPanels,
    configForm,
    error,
    falsePositivePanels,
    lastUpdated,
    loading,
    meta,
    refreshAll,
    refreshing,
    runtimeProfileLabel,
    runtimeStatus,
    saveConfig,
    saving,
    stats,
    successMessage,
    topBuckets,
    topPorts,
    totalProcessedBytes,
  }
}
