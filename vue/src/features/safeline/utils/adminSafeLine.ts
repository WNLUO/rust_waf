import type {
  SafeLineMappingItem,
  SafeLineSiteItem,
} from '@/features/sites/types/sites'

export interface SafeLineMappingDraft {
  safeline_site_id: string
  safeline_site_name: string
  safeline_site_domain: string
  local_alias: string
  enabled: boolean
  is_primary: boolean
  notes: string
  updated_at: number | null
  orphaned: boolean
}

export function mergeMappingDrafts(
  siteList: SafeLineSiteItem[],
  mappingList: SafeLineMappingItem[],
) {
  const nextDrafts: SafeLineMappingDraft[] = siteList.map((site) => {
    const existing = mappingList.find(
      (item) => item.safeline_site_id === site.id,
    )
    return {
      safeline_site_id: site.id,
      safeline_site_name: site.name,
      safeline_site_domain: site.domain,
      local_alias: existing?.local_alias ?? site.name ?? site.domain ?? '',
      enabled: existing?.enabled ?? true,
      is_primary: existing?.is_primary ?? false,
      notes: existing?.notes ?? '',
      updated_at: existing?.updated_at ?? null,
      orphaned: false,
    }
  })

  const existingIds = new Set(nextDrafts.map((item) => item.safeline_site_id))
  for (const item of mappingList) {
    if (existingIds.has(item.safeline_site_id)) continue
    nextDrafts.push({
      safeline_site_id: item.safeline_site_id,
      safeline_site_name: item.safeline_site_name,
      safeline_site_domain: item.safeline_site_domain,
      local_alias: item.local_alias,
      enabled: item.enabled,
      is_primary: item.is_primary,
      notes: item.notes,
      updated_at: item.updated_at ?? null,
      orphaned: true,
    })
  }

  return nextDrafts
}

export function sortMappingDrafts(drafts: SafeLineMappingDraft[]) {
  return [...drafts].sort((left, right) => {
    if (left.is_primary !== right.is_primary) return left.is_primary ? -1 : 1
    if (left.enabled !== right.enabled) return left.enabled ? -1 : 1
    if (left.orphaned !== right.orphaned) return left.orphaned ? 1 : -1
    return left.local_alias.localeCompare(right.local_alias, 'zh-CN')
  })
}
