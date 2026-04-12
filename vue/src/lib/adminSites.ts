import type {
  LocalSiteItem,
  SafeLineMappingItem,
  SafeLineSiteItem,
  SiteSyncLinkItem,
} from './types'

export type ScopeFilter =
  | 'all'
  | 'mapped'
  | 'unmapped'
  | 'orphaned'
  | 'local_only'
  | 'missing_remote'

export type StateFilter = 'all' | 'enabled' | 'disabled' | 'primary'

export type RowKind =
  | 'linked'
  | 'remote_only'
  | 'local_only'
  | 'missing_remote'
  | 'orphaned_mapping'

export interface SiteRowDraft {
  row_key: string
  row_kind: RowKind
  link_id: number | null
  remote_present: boolean
  local_present: boolean
  safeline_site_id: string
  safeline_site_name: string
  safeline_site_domain: string
  remote_enabled: boolean | null
  status: string
  server_names: string[]
  remote_ports: string[]
  remote_ssl_ports: string[]
  remote_upstreams: string[]
  remote_ssl_enabled: boolean
  local_site_id: number | null
  local_site_name: string
  local_primary_hostname: string
  local_hostnames: string[]
  local_upstreams: string[]
  local_enabled: boolean
  local_notes: string
  local_updated_at: number | null
  local_sync_mode: string
  local_alias: string
  enabled: boolean
  is_primary: boolean
  notes: string
  saved: boolean
  orphaned: boolean
  link_last_error: string | null
  link_last_synced_at: number | null
}

function statusNormalized(value: string) {
  return value.trim().toLowerCase()
}

function isSiteOnline(status: string) {
  return [
    '1',
    'true',
    'online',
    'enabled',
    'active',
    'running',
    'healthy',
    'on',
  ].includes(statusNormalized(status))
}

function isSiteOffline(status: string) {
  return [
    '0',
    'false',
    'offline',
    'disabled',
    'inactive',
    'stopped',
    'off',
  ].includes(statusNormalized(status))
}

export function remoteStatusType(status: string) {
  if (!status.trim()) return 'muted'
  if (isSiteOnline(status)) return 'success'
  if (isSiteOffline(status)) return 'warning'
  return 'info'
}

export function remoteStatusText(status: string) {
  if (!status.trim()) return '未读取远端状态'
  if (isSiteOnline(status)) return `远端在线 · ${status}`
  if (isSiteOffline(status)) return `远端停用 · ${status}`
  return `远端状态 · ${status}`
}

function createSiteRow({
  site,
  mapping,
  local,
  link,
}: {
  site?: SafeLineSiteItem | null
  mapping?: SafeLineMappingItem | null
  local?: LocalSiteItem | null
  link?: SiteSyncLinkItem | null
}): SiteRowDraft {
  const remote = site ?? null
  const savedMapping = mapping ?? null
  const localSite = local ?? null
  const siteLink = link ?? null

  let rowKind: RowKind = 'orphaned_mapping'
  if (remote && localSite) {
    rowKind = 'linked'
  } else if (remote) {
    rowKind = 'remote_only'
  } else if (localSite && siteLink) {
    rowKind = 'missing_remote'
  } else if (localSite) {
    rowKind = 'local_only'
  }

  return {
    row_key: remote?.id
      ? `remote:${remote.id}`
      : localSite
        ? `local:${localSite.id}`
        : `mapping:${savedMapping?.safeline_site_id || savedMapping?.id || 'unknown'}`,
    row_kind: rowKind,
    link_id: siteLink?.id ?? null,
    remote_present: Boolean(remote),
    local_present: Boolean(localSite),
    safeline_site_id:
      remote?.id ??
      savedMapping?.safeline_site_id ??
      siteLink?.remote_site_id ??
      '',
    safeline_site_name:
      remote?.name ??
      savedMapping?.safeline_site_name ??
      siteLink?.remote_site_name ??
      '',
    safeline_site_domain:
      remote?.domain ?? savedMapping?.safeline_site_domain ?? '',
    remote_enabled: remote?.enabled ?? null,
    status: remote?.status ?? '',
    server_names: remote?.server_names ?? [],
    remote_ports: remote?.ports ?? [],
    remote_ssl_ports: remote?.ssl_ports ?? [],
    remote_upstreams: remote?.upstreams ?? [],
    remote_ssl_enabled: remote?.ssl_enabled ?? false,
    local_site_id: localSite?.id ?? null,
    local_site_name: localSite?.name ?? '',
    local_primary_hostname: localSite?.primary_hostname ?? '',
    local_hostnames: localSite?.hostnames ?? [],
    local_upstreams: localSite?.upstreams ?? [],
    local_enabled: localSite?.enabled ?? false,
    local_notes: localSite?.notes ?? '',
    local_updated_at: localSite?.updated_at ?? null,
    local_sync_mode: siteLink?.sync_mode ?? localSite?.sync_mode ?? 'manual',
    local_alias:
      savedMapping?.local_alias ??
      remote?.name ??
      remote?.domain ??
      localSite?.name ??
      '',
    enabled:
      savedMapping?.enabled ?? (remote ? true : (localSite?.enabled ?? true)),
    is_primary: savedMapping?.is_primary ?? false,
    notes: savedMapping?.notes ?? (remote ? '' : (localSite?.notes ?? '')),
    saved: Boolean(savedMapping),
    orphaned: Boolean(savedMapping && !remote),
    link_last_error: siteLink?.last_error ?? null,
    link_last_synced_at:
      siteLink?.last_synced_at ?? localSite?.last_synced_at ?? null,
  }
}

export function mergeSiteRows(
  siteList: SafeLineSiteItem[],
  mappingList: SafeLineMappingItem[],
  localSiteList: LocalSiteItem[],
  linkList: SiteSyncLinkItem[],
) {
  const rows: SiteRowDraft[] = []
  const localById = new Map(localSiteList.map((item) => [item.id, item]))
  const safeLineLinks = linkList.filter((item) => item.provider === 'safeline')
  const linkByRemoteId = new Map(
    safeLineLinks.map((item) => [item.remote_site_id, item]),
  )
  const linkByLocalId = new Map(
    safeLineLinks.map((item) => [item.local_site_id, item]),
  )
  const mappingByRemoteId = new Map(
    mappingList.map((item) => [item.safeline_site_id, item]),
  )
  const usedLocalIds = new Set<number>()
  const usedMappingIds = new Set<string>()

  for (const site of siteList) {
    const mapping = mappingByRemoteId.get(site.id) ?? null
    const link = linkByRemoteId.get(site.id) ?? null
    const local = link ? (localById.get(link.local_site_id) ?? null) : null
    rows.push(createSiteRow({ site, mapping, local, link }))
    if (mapping) usedMappingIds.add(mapping.safeline_site_id)
    if (local) usedLocalIds.add(local.id)
  }

  for (const mapping of mappingList) {
    if (usedMappingIds.has(mapping.safeline_site_id)) continue
    const link = linkByRemoteId.get(mapping.safeline_site_id) ?? null
    const local = link ? (localById.get(link.local_site_id) ?? null) : null
    rows.push(createSiteRow({ mapping, local, link }))
    usedMappingIds.add(mapping.safeline_site_id)
    if (local) usedLocalIds.add(local.id)
  }

  for (const local of localSiteList) {
    if (usedLocalIds.has(local.id)) continue
    const link = linkByLocalId.get(local.id) ?? null
    const site = link
      ? (siteList.find((item) => item.id === link.remote_site_id) ?? null)
      : null
    const mapping = link
      ? (mappingByRemoteId.get(link.remote_site_id) ?? null)
      : null
    rows.push(createSiteRow({ site, mapping, local, link }))
  }

  return rows
}

export function mappingStateText(item: SiteRowDraft) {
  switch (item.row_kind) {
    case 'linked':
      return item.saved ? '已映射' : '已建链'
    case 'remote_only':
      return item.saved ? '仅映射' : '仅雷池'
    case 'local_only':
      return '仅本地'
    case 'missing_remote':
      return '远端缺失'
    case 'orphaned_mapping':
      return '孤儿映射'
  }
}

export function mappingStateType(item: SiteRowDraft) {
  switch (item.row_kind) {
    case 'linked':
      return item.saved ? 'success' : 'info'
    case 'remote_only':
      return item.saved ? 'warning' : 'muted'
    case 'local_only':
      return 'info'
    case 'missing_remote':
    case 'orphaned_mapping':
      return 'warning'
  }
}

export function syncModeLabel(value: string) {
  switch (value.trim()) {
    case 'remote_to_local':
    case 'pull_only':
      return '仅回流'
    case 'local_to_remote':
    case 'push_only':
      return '仅推送'
    case 'bidirectional':
      return '双向同步'
    case 'manual':
      return '手动'
    default:
      return value.trim() || '未设置'
  }
}
