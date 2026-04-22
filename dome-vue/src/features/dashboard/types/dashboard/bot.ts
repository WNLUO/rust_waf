import type { AiAuditCountItem } from './aiAudit'

export interface BotVerifierStatusResponse {
  generated_at: number
  providers: BotVerifierProviderStatus[]
}

export interface BotVerifierProviderStatus {
  provider: string
  range_count: number
  last_refresh_at: number | null
  last_success_at: number | null
  last_error: string | null
  status: string
}

export interface BotInsightsResponse {
  generated_at: number
  window_start: number
  total_bot_events: number
  by_trust_class: AiAuditCountItem[]
  top_bot_names: AiAuditCountItem[]
  top_mismatch_ips: AiAuditCountItem[]
  top_routes: AiAuditCountItem[]
}
