import type { LocalCertificateDraft } from '@/features/sites/types/sites'
import type { SettingsPayload } from '@/features/settings/types/settings'

export type SystemSettingsForm = SettingsPayload

export function createDefaultSystemSettings(): SystemSettingsForm {
  return {
    gateway_name: '玄枢防护网关',
    drop_unmatched_requests: false,
    https_listen_addr: '',
    default_certificate_id: null,
    api_endpoint: '127.0.0.1:3740',
    notes: '',
    safeline: {
      enabled: true,
      auto_sync_events: true,
      auto_sync_blocked_ips_push: true,
      auto_sync_blocked_ips_pull: true,
      auto_sync_interval_secs: 300,
      base_url: '',
      api_token: '',
      username: '',
      password: '',
      verify_tls: false,
      openapi_doc_path: '/openapi_doc/',
      auth_probe_path: '/api/open/system/key',
      site_list_path: '/api/open/site',
      event_list_path: '/api/open/records',
      blocklist_sync_path: '/api/open/ipgroup',
      blocklist_delete_path: '/api/open/ipgroup',
      blocklist_ip_group_ids: [],
    },
  }
}

export function createDefaultUploadCertificateForm(): LocalCertificateDraft {
  return {
    name: '',
    domains: [],
    issuer: '',
    valid_from: null,
    valid_to: null,
    source_type: 'manual',
    provider_remote_id: null,
    provider_remote_domains: [],
    last_remote_fingerprint: null,
    sync_status: 'idle',
    sync_message: '',
    auto_sync_enabled: false,
    trusted: false,
    expired: false,
    notes: '',
    last_synced_at: null,
    certificate_pem: '',
    private_key_pem: '',
  }
}

export function normalizeDomainList(value: string) {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean)
}

export function defaultGeneratedDomain() {
  return `fake-${Date.now().toString(36)}.local`
}

export function defaultCertificateName(primaryDomain?: string) {
  if (primaryDomain?.trim()) {
    return `cert-${primaryDomain.trim()}`
  }
  return `cert-${Date.now().toString(36)}`
}

export function extractPemBlocks(source: string) {
  const certificateMatches = [
    ...source.matchAll(
      /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g,
    ),
  ].map((match) => match[0].trim())
  const privateKeyMatch = source.match(
    /-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/,
  )

  return {
    certificate_pem: certificateMatches.join('\n'),
    private_key_pem: privateKeyMatch?.[0].trim() ?? '',
  }
}
