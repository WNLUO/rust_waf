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
