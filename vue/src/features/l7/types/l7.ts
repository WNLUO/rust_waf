export interface RuleResponseHeaderPayload {
  key: string
  value: string
}

export interface RuleResponseTemplatePayload {
  status_code: number
  content_type: string
  body_source: 'inline_text' | 'file' | string
  gzip: boolean
  body_text: string
  body_file_path: string
  headers: RuleResponseHeaderPayload[]
}

export interface SafeLineInterceptConfigPayload {
  enabled: boolean
  action: 'pass' | 'replace' | 'drop' | 'replace_and_block_ip' | string
  match_mode: 'strict' | 'relaxed' | string
  max_body_bytes: number
  block_duration_secs: number
  response_template: RuleResponseTemplatePayload
}

export interface CcDefenseConfigPayload {
  enabled: boolean
  request_window_secs: number
  ip_challenge_threshold: number
  ip_block_threshold: number
  host_challenge_threshold: number
  host_block_threshold: number
  route_challenge_threshold: number
  route_block_threshold: number
  hot_path_challenge_threshold: number
  hot_path_block_threshold: number
  delay_threshold_percent: number
  delay_ms: number
  challenge_ttl_secs: number
  challenge_cookie_name: string
  hard_route_block_multiplier: number
  hard_host_block_multiplier: number
  hard_ip_block_multiplier: number
  hard_hot_path_block_multiplier: number
}

export interface L7ConfigPayload {
  max_request_size: number
  trusted_proxy_cidrs: string[]
  first_byte_timeout_ms: number
  read_idle_timeout_ms: number
  tls_handshake_timeout_ms: number
  proxy_connect_timeout_ms: number
  proxy_write_timeout_ms: number
  proxy_read_timeout_ms: number
  upstream_healthcheck_enabled: boolean
  upstream_healthcheck_interval_secs: number
  upstream_healthcheck_timeout_ms: number
  upstream_failure_mode: 'fail_open' | 'fail_close' | string
  bloom_filter_scale: number
  http2_enabled: boolean
  http2_max_concurrent_streams: number
  http2_max_frame_size: number
  http2_enable_priorities: boolean
  http2_initial_window_size: number
  runtime_enabled: boolean
  bloom_enabled: boolean
  bloom_false_positive_verification: boolean
  runtime_profile: 'minimal' | 'standard' | string
  listen_addrs: string[]
  upstream_endpoint: string
  http3_enabled: boolean
  http3_listen_addr: string
  http3_max_concurrent_streams: number
  http3_idle_timeout_secs: number
  http3_mtu: number
  http3_max_frame_size: number
  http3_enable_connection_migration: boolean
  http3_qpack_table_size: number
  http3_certificate_path: string
  http3_private_key_path: string
  http3_enable_tls13: boolean
  cc_defense: CcDefenseConfigPayload
  safeline_intercept: SafeLineInterceptConfigPayload
}

export interface L7StatsPayload {
  enabled: boolean
  blocked_requests: number
  cc_challenge_requests: number
  cc_block_requests: number
  cc_delayed_requests: number
  cc_verified_pass_requests: number
  proxied_requests: number
  proxy_successes: number
  proxy_failures: number
  proxy_fail_close_rejections: number
  average_proxy_latency_micros: number
  upstream_healthy: boolean
  upstream_last_check_at: number | null
  upstream_last_error: string | null
  http3_feature_available: boolean
  http3_configured_enabled: boolean
  http3_tls13_enabled: boolean
  http3_certificate_configured: boolean
  http3_private_key_configured: boolean
  http3_listener_started: boolean
  http3_listener_addr: string | null
  http3_status: string
  http3_last_error: string | null
}
