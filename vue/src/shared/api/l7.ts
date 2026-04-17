import type { L7ConfigPayload, L7StatsPayload, WriteStatusResponse } from '@/shared/types'
import { apiRequest } from './core'

export type L7ConfigUpdatePayload = Pick<
  L7ConfigPayload,
  | 'trusted_proxy_cidrs'
  | 'upstream_healthcheck_enabled'
  | 'upstream_failure_mode'
  | 'upstream_protocol_policy'
  | 'upstream_http1_strict_mode'
  | 'upstream_http1_allow_connection_reuse'
  | 'reject_ambiguous_http1_requests'
  | 'reject_http1_transfer_encoding_requests'
  | 'reject_body_on_safe_http_methods'
  | 'reject_expect_100_continue'
  | 'http2_enabled'
  | 'bloom_enabled'
  | 'listen_addrs'
  | 'upstream_endpoint'
  | 'http3_enabled'
  | 'http3_certificate_path'
  | 'http3_private_key_path'
  | 'http3_enable_tls13'
>

export function fetchL7Config() {
  return apiRequest<L7ConfigPayload>('/l7/config')
}

export function updateL7Config(payload: L7ConfigUpdatePayload) {
  return apiRequest<WriteStatusResponse>('/l7/config', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function fetchL7Stats() {
  return apiRequest<L7StatsPayload>('/l7/stats')
}
