export interface L4ConfigPayload {
  ddos_protection_enabled: boolean
  advanced_ddos_enabled: boolean
  connection_rate_limit: number
  syn_flood_threshold: number
  max_tracked_ips: number
  max_blocked_ips: number
  state_ttl_secs: number
  bloom_filter_scale: number
  runtime_enabled: boolean
  bloom_enabled: boolean
  bloom_false_positive_verification: boolean
  runtime_profile: 'minimal' | 'standard' | string
}

export interface L4ConnectionStats {
  total_connections: number
  active_connections: number
  blocked_connections: number
  rate_limit_hits: number
}

export interface L4PortStatItem {
  port: string
  connections: number
  blocks: number
  bytes_processed: number
  ddos_events: number
}

export interface L4BloomFilterCounters {
  filter_size: number
  hash_functions: number
  insert_count: number
  hit_count: number
  hit_rate: number
}

export interface L4BloomStats {
  ipv4_filter: L4BloomFilterCounters
  ipv6_filter: L4BloomFilterCounters
  ip_port_filter: L4BloomFilterCounters
  enabled: boolean
  false_positive_verification: boolean
}

export interface L4FalsePositiveStats {
  ipv4_exact_size: number
  ipv6_exact_size: number
  ip_port_exact_size: number
}

export interface L4StatsPayload {
  enabled: boolean
  connections: L4ConnectionStats
  ddos_events: number
  protocol_anomalies: number
  traffic: number
  defense_actions: number
  bloom_stats: L4BloomStats | null
  false_positive_stats: L4FalsePositiveStats | null
  per_port_stats: L4PortStatItem[]
}
