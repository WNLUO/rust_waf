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
  }
}
