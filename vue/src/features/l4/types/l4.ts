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
  behavior: L4BehaviorSnapshot
  connections: L4ConnectionStats
  ddos_events: number
  protocol_anomalies: number
  traffic: number
  defense_actions: number
  bloom_stats: L4BloomStats | null
  false_positive_stats: L4FalsePositiveStats | null
  per_port_stats: L4PortStatItem[]
}

export interface L4BehaviorSnapshot {
  overview: L4BehaviorOverview
  top_buckets: L4BucketItem[]
}

export interface L4BehaviorOverview {
  bucket_count: number
  fine_grained_buckets: number
  coarse_buckets: number
  peer_only_buckets: number
  normal_buckets: number
  suspicious_buckets: number
  high_risk_buckets: number
  safeline_feedback_hits: number
  l7_feedback_hits: number
  dropped_events: number
  overload_level: 'normal' | 'high' | 'critical'
  overload_reason: string | null
}

export interface L4BucketPolicy {
  connection_budget_per_minute: number
  shrink_idle_timeout: boolean
  disable_keepalive: boolean
  prefer_early_close: boolean
  reject_new_connections: boolean
  mode: string
  suggested_delay_ms: number
}

export interface L4BucketItem {
  peer_ip: string
  authority: string
  alpn: string
  transport: string
  protocol_hint: string
  total_connections: number
  total_requests: number
  total_bytes: number
  recent_connections_10s: number
  recent_requests_10s: number
  recent_feedback_120s: number
  l7_block_hits: number
  safeline_hits: number
  risk_score: number
  risk_level: 'normal' | 'suspicious' | 'high'
  policy: L4BucketPolicy
  last_seen_at: number
}
