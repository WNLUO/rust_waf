import type { L4ConfigPayload } from '@/features/l4/types/l4'

export type L4ConfigForm = Omit<
  L4ConfigPayload,
  | 'runtime_enabled'
  | 'bloom_enabled'
  | 'bloom_false_positive_verification'
  | 'runtime_profile'
>

export function createDefaultL4ConfigForm(): L4ConfigForm {
  return {
    ddos_protection_enabled: true,
    advanced_ddos_enabled: false,
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
  }
}
