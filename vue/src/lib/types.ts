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
  total_bytes: number
  proxied_requests: number
  proxy_successes: number
  proxy_failures: number
  proxy_fail_close_rejections: number
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

export interface RuleItem {
  id: string
  name: string
  enabled: boolean
  layer: string
  pattern: string
  action: string
  severity: string
}

export interface RuleDraft {
  id: string
  name: string
  enabled: boolean
  layer: string
  pattern: string
  action: string
  severity: string
}

export interface RulesResponse {
  rules: RuleItem[]
}

export interface SecurityEventItem {
  id: number
  layer: string
  action: string
  reason: string
  source_ip: string
  dest_ip: string
  source_port: number
  dest_port: number
  protocol: string
  http_method: string | null
  uri: string | null
  http_version: string | null
  created_at: number
}

export interface SecurityEventsResponse {
  total: number
  limit: number
  offset: number
  events: SecurityEventItem[]
}

export interface BlockedIpItem {
  id: number
  ip: string
  reason: string
  blocked_at: number
  expires_at: number
}

export interface BlockedIpsResponse {
  total: number
  limit: number
  offset: number
  blocked_ips: BlockedIpItem[]
}

export interface WriteStatusResponse {
  success: boolean
  message: string
}

export interface DashboardPayload {
  health: HealthResponse
  metrics: MetricsResponse
  events: SecurityEventsResponse
  blockedIps: BlockedIpsResponse
  rules: RulesResponse
}
