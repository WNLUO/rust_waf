import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { fetchL4Config, fetchL4Stats, updateL4Config } from '../lib/api'
import { createDefaultL4ConfigForm, type L4ConfigForm } from '../lib/adminL4'
import type { L4ConfigPayload, L4StatsPayload } from '../lib/types'

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

export function useAdminL4() {
  const loading = ref(true)
  const refreshing = ref(false)
  const saving = ref(false)
  const error = ref('')
  const successMessage = ref('')
  const stats = ref<L4StatsPayload | null>(null)
  const statsTimer = ref<number | null>(null)
  const lastUpdated = ref<number | null>(null)
  const meta = ref({
    runtime_enabled: false,
    bloom_enabled: false,
    bloom_false_positive_verification: false,
    runtime_profile: 'minimal',
  })

  const configForm = reactive<L4ConfigForm>(createDefaultL4ConfigForm())

  const applyConfig = (payload: L4ConfigPayload) => {
    Object.assign(configForm, {
      ddos_protection_enabled: payload.ddos_protection_enabled,
      advanced_ddos_enabled: payload.advanced_ddos_enabled,
      connection_rate_limit: payload.connection_rate_limit,
      syn_flood_threshold: payload.syn_flood_threshold,
      max_tracked_ips: payload.max_tracked_ips,
      max_blocked_ips: payload.max_blocked_ips,
      state_ttl_secs: payload.state_ttl_secs,
      bloom_filter_scale: payload.bloom_filter_scale,
    })

    meta.value = {
      runtime_enabled: payload.runtime_enabled,
      bloom_enabled: payload.bloom_enabled,
      bloom_false_positive_verification:
        payload.bloom_false_positive_verification,
      runtime_profile: payload.runtime_profile,
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

  const refreshStats = async () => {
    try {
      stats.value = await fetchL4Stats()
      lastUpdated.value = Date.now()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '刷新 L4 统计失败'
    }
  }

  const saveConfig = async () => {
    saving.value = true
    error.value = ''
    successMessage.value = ''

    try {
      configForm.connection_rate_limit = clampInteger(
        configForm.connection_rate_limit,
        1,
        1_000_000,
        100,
      )
      configForm.syn_flood_threshold = clampInteger(
        configForm.syn_flood_threshold,
        1,
        1_000_000,
        50,
      )
      configForm.max_tracked_ips = clampInteger(
        configForm.max_tracked_ips,
        1,
        1_000_000,
        4096,
      )
      configForm.max_blocked_ips = clampInteger(
        configForm.max_blocked_ips,
        1,
        1_000_000,
        1024,
      )
      configForm.state_ttl_secs = clampInteger(
        configForm.state_ttl_secs,
        60,
        86_400,
        300,
      )
      configForm.bloom_filter_scale = clampFloat(
        configForm.bloom_filter_scale,
        0.1,
        4,
        1,
      )

      const response = await updateL4Config({ ...configForm })
      successMessage.value = response.message
      await refreshAll()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '保存 L4 配置失败'
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

  onMounted(async () => {
    await refreshAll(true)
    statsTimer.value = window.setInterval(() => {
      refreshStats()
    }, 5000)
  })

  onBeforeUnmount(() => {
    if (statsTimer.value) {
      clearInterval(statsTimer.value)
    }
  })

  return {
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
    topPorts,
    totalProcessedBytes,
  }
}
