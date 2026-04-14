export interface HealthResponse {
  status: string
  version: string
  upstream_healthy: boolean
  upstream_last_check_at: number | null
  upstream_last_error: string | null
}

export interface MetricsResponse {
  total_packets: number
  blocked_packets: number
  blocked_l4: number
  blocked_l7: number
  l7_cc_challenges: number
  l7_cc_blocks: number
  l7_cc_delays: number
  l7_cc_verified_passes: number
  total_bytes: number
  proxied_requests: number
  proxy_successes: number
  proxy_failures: number
  proxy_fail_close_rejections: number
  l4_bucket_budget_rejections: number
  tls_pre_handshake_rejections: number
  tls_handshake_timeouts: number
  tls_handshake_failures: number
  upstream_healthcheck_successes: number
  upstream_healthcheck_failures: number
  proxy_latency_micros_total: number
  average_proxy_latency_micros: number
  active_rules: number
  sqlite_enabled: boolean
  persisted_security_events: number
  persisted_blocked_ips: number
  persisted_rules: number
  last_persisted_event_at: number | null
  last_rule_update_at: number | null
}

export interface AdaptiveProtectionL4RuntimePayload {
  normal_connection_budget_per_minute: number
  suspicious_connection_budget_per_minute: number
  high_risk_connection_budget_per_minute: number
  soft_delay_ms: number
  hard_delay_ms: number
  high_overload_delay_ms: number
  critical_overload_delay_ms: number
  reject_threshold_percent: number
  critical_reject_threshold_percent: number
  emergency_reject_enabled: boolean
}

export interface AdaptiveProtectionL7RuntimePayload {
  request_window_secs: number
  delay_ms: number
  route_challenge_threshold: number
  route_block_threshold: number
  ip_challenge_threshold: number
  ip_block_threshold: number
  challenge_enabled: boolean
}

export interface AdaptiveProtectionRuntimePayload {
  enabled: boolean
  mode: string
  goal: string
  system_pressure: string
  reasons: string[]
  l4: AdaptiveProtectionL4RuntimePayload
  l7: AdaptiveProtectionL7RuntimePayload
}
