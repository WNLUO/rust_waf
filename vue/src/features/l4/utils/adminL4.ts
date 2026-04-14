import type { L4ConfigPayload } from '@/features/l4/types/l4'

export type L4ConfigForm = Omit<
  L4ConfigPayload,
  | 'runtime_enabled'
  | 'bloom_enabled'
  | 'bloom_false_positive_verification'
  | 'runtime_profile'
  | 'adaptive_managed_fields'
  | 'adaptive_runtime'
  | 'advanced_compatibility'
>

export function createDefaultL4ConfigForm(): L4ConfigForm {
  return {
    ddos_protection_enabled: true,
    advanced_ddos_enabled: true,
    connection_rate_limit: 100,
    syn_flood_threshold: 50,
    max_tracked_ips: 4096,
    max_blocked_ips: 1024,
    state_ttl_secs: 300,
    bloom_filter_scale: 1,
    behavior_event_channel_capacity: 4096,
    behavior_drop_critical_threshold: 128,
    behavior_fallback_ratio_percent: 80,
    behavior_overload_blocked_connections_threshold: 512,
    behavior_overload_active_connections_threshold: 2048,
    behavior_normal_connection_budget_per_minute: 120,
    behavior_suspicious_connection_budget_per_minute: 60,
    behavior_high_risk_connection_budget_per_minute: 20,
    behavior_high_overload_budget_scale_percent: 80,
    behavior_critical_overload_budget_scale_percent: 50,
    behavior_high_overload_delay_ms: 15,
    behavior_critical_overload_delay_ms: 40,
    behavior_soft_delay_threshold_percent: 100,
    behavior_hard_delay_threshold_percent: 200,
    behavior_soft_delay_ms: 25,
    behavior_hard_delay_ms: 60,
    behavior_reject_threshold_percent: 300,
    behavior_critical_reject_threshold_percent: 200,
    trusted_cdn: {
      manual_cidrs: [],
      effective_cidrs: [],
      sync_interval_value: 12,
      sync_interval_unit: 'hour',
      edgeone_overseas: {
        enabled: false,
        synced_cidrs: [],
        last_synced_at: null,
        last_sync_status: 'idle',
        last_sync_message: '',
      },
      aliyun_esa: {
        enabled: false,
        site_id: '',
        access_key_id: '',
        access_key_secret: '',
        endpoint: 'esa.cn-hangzhou.aliyuncs.com',
        synced_cidrs: [],
        last_synced_at: null,
        last_sync_status: 'idle',
        last_sync_message: '',
      },
    },
  }
}
