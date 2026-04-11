import type { L7ConfigPayload } from './types'

export type L7ConfigForm = Omit<L7ConfigPayload, 'runtime_enabled'>

export const numberInputClass =
  'mt-2 w-full rounded-[18px] border border-slate-200 bg-white px-4 py-3 text-sm text-stone-800 outline-none transition focus:border-blue-500/40'

export const listFieldClass =
  'mt-2 min-h-[120px] w-full rounded-[18px] border border-slate-200 bg-white px-4 py-3 text-sm text-stone-800 outline-none transition focus:border-blue-500/40'

export function createDefaultL7ConfigForm(): L7ConfigForm {
  return {
    runtime_profile: 'minimal',
    http_inspection_enabled: true,
    max_request_size: 8192,
    real_ip_headers: [],
    trusted_proxy_cidrs: [],
    first_byte_timeout_ms: 2000,
    read_idle_timeout_ms: 5000,
    tls_handshake_timeout_ms: 3000,
    proxy_connect_timeout_ms: 1500,
    proxy_write_timeout_ms: 3000,
    proxy_read_timeout_ms: 10000,
    upstream_healthcheck_enabled: true,
    upstream_healthcheck_interval_secs: 5,
    upstream_healthcheck_timeout_ms: 1000,
    upstream_failure_mode: 'fail_open',
    bloom_filter_scale: 1,
    http2_enabled: false,
    http2_max_concurrent_streams: 100,
    http2_max_frame_size: 16384,
    http2_enable_priorities: true,
    http2_initial_window_size: 65535,
    bloom_enabled: false,
    bloom_false_positive_verification: false,
    listen_addrs: ['0.0.0.0:8080'],
    upstream_endpoint: '',
    http3_enabled: false,
    http3_listen_addr: '0.0.0.0:8443',
    http3_max_concurrent_streams: 100,
    http3_idle_timeout_secs: 300,
    http3_mtu: 1350,
    http3_max_frame_size: 65536,
    http3_enable_connection_migration: true,
    http3_qpack_table_size: 4096,
    http3_certificate_path: '',
    http3_private_key_path: '',
    http3_enable_tls13: true,
  }
}
