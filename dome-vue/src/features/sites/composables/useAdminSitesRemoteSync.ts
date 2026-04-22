import { computed, ref, type Ref } from 'vue'
import type { SafeLineSitePullOptions } from '@/shared/types'
import type { SiteRowDraft } from '@/features/sites/utils/adminSites'
import type { LocalSiteItem, SafeLineSiteItem } from '@/shared/types'

export interface RemoteSyncCandidate {
  id: string
  name: string
  domain: string
  serverNames: string[]
  upstreams: string[]
  ports: string[]
  sslPorts: string[]
  sslEnabled: boolean
  localMatchLabel: string | null
  recommendation: 'recommended' | 'update' | 'hostname_conflict' | 'name_conflict'
  recommendationText: string
  selectable: boolean
  defaultSelected: boolean
  linkedLocalSiteId: number | null
}

function createDefaultPullOptions(): SafeLineSitePullOptions {
  return {
    name: true,
    primary_hostname: true,
    hostnames: true,
    listen_ports: true,
    upstreams: true,
    enabled: true,
  }
}

interface UseAdminSitesRemoteSyncOptions {
  clearFeedback: () => void
  error: Ref<string>
  loadRemoteSites: () => Promise<void>
  notifyError: (message: string, options?: { title?: string; duration?: number }) => void
  notifySuccess: (message: string, options?: { title?: string; duration?: number }) => void
  pullSafeLineSite: (
    remoteSiteId: string,
    options?: SafeLineSitePullOptions,
  ) => Promise<{ message: string }>
  refreshCollections: (
    remoteSource: 'none' | 'cached' | 'live',
  ) => Promise<void>
  setSuccessMessage: (value: string) => void
  localSites: Ref<LocalSiteItem[]>
  sites: Ref<SafeLineSiteItem[]>
  siteRows: Ref<SiteRowDraft[]>
}

export function useAdminSitesRemoteSync({
  clearFeedback,
  error,
  loadRemoteSites,
  notifyError,
  notifySuccess,
  pullSafeLineSite,
  refreshCollections,
  setSuccessMessage,
  localSites,
  sites,
  siteRows,
}: UseAdminSitesRemoteSyncOptions) {
  const isRemoteSyncDialogOpen = ref(false)
  const selectedRemoteSiteIds = ref<string[]>([])
  const remoteSitePullOptions = ref<Record<string, SafeLineSitePullOptions>>({})
  const syncingRemoteSelection = ref(false)

  const remoteSyncCandidates = computed<RemoteSyncCandidate[]>(() => {
    const localByHostname = new Map<string, LocalSiteItem>()
    const localByName = new Map<string, LocalSiteItem>()

    for (const site of localSites.value) {
      const names = [site.primary_hostname, ...site.hostnames]
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean)
      for (const hostname of names) {
        if (!localByHostname.has(hostname)) {
          localByHostname.set(hostname, site)
        }
      }
      const normalizedName = site.name.trim().toLowerCase()
      if (normalizedName && !localByName.has(normalizedName)) {
        localByName.set(normalizedName, site)
      }
    }

    return [...sites.value]
      .map((site) => {
        const linkedRow =
          siteRows.value.find(
            (item) => item.safeline_site_id === site.id && item.local_present,
          ) ?? null
        const hostnameMatch = [site.domain, ...site.server_names]
          .map((item) => item.trim().toLowerCase())
          .find((hostname) => localByHostname.has(hostname))
        const matchedByHostname = hostnameMatch
          ? (localByHostname.get(hostnameMatch) ?? null)
          : null
        const matchedByName =
          localByName.get(site.name.trim().toLowerCase()) ?? null

        if (linkedRow) {
          return {
            id: site.id,
            name: site.name || site.domain || `站点 ${site.id}`,
            domain: site.domain,
            serverNames: site.server_names,
            upstreams: site.upstreams,
            ports: site.ports,
            sslPorts: site.ssl_ports,
            sslEnabled: site.ssl_enabled,
            localMatchLabel:
              linkedRow.local_site_name || linkedRow.local_primary_hostname,
            recommendation: 'update' as const,
            recommendationText: '已有关联本地站点，可按需更新本地配置。',
            selectable: true,
            defaultSelected: false,
            linkedLocalSiteId: linkedRow.local_site_id,
          }
        }

        if (matchedByHostname) {
          return {
            id: site.id,
            name: site.name || site.domain || `站点 ${site.id}`,
            domain: site.domain,
            serverNames: site.server_names,
            upstreams: site.upstreams,
            ports: site.ports,
            sslPorts: site.ssl_ports,
            sslEnabled: site.ssl_enabled,
            localMatchLabel:
              matchedByHostname.name || matchedByHostname.primary_hostname,
            recommendation: 'hostname_conflict' as const,
            recommendationText:
              '本地域名已存在相似站点，建议人工确认后再导入。',
            selectable: true,
            defaultSelected: false,
            linkedLocalSiteId: null,
          }
        }

        if (matchedByName) {
          return {
            id: site.id,
            name: site.name || site.domain || `站点 ${site.id}`,
            domain: site.domain,
            serverNames: site.server_names,
            upstreams: site.upstreams,
            ports: site.ports,
            sslPorts: site.ssl_ports,
            sslEnabled: site.ssl_enabled,
            localMatchLabel:
              matchedByName.name || matchedByName.primary_hostname,
            recommendation: 'name_conflict' as const,
            recommendationText:
              '本地已有同名站点，默认不勾选，避免重复导入。',
            selectable: true,
            defaultSelected: false,
            linkedLocalSiteId: null,
          }
        }

        return {
          id: site.id,
          name: site.name || site.domain || `站点 ${site.id}`,
          domain: site.domain,
          serverNames: site.server_names,
          upstreams: site.upstreams,
          ports: site.ports,
          sslPorts: site.ssl_ports,
          sslEnabled: site.ssl_enabled,
          localMatchLabel: null,
          recommendation: 'recommended' as const,
          recommendationText: '本地未发现重复站点，建议直接导入。',
          selectable: true,
          defaultSelected: true,
          linkedLocalSiteId: null,
        }
      })
      .sort((left, right) => {
        const priority = {
          recommended: 0,
          update: 1,
          hostname_conflict: 2,
          name_conflict: 3,
        }
        if (priority[left.recommendation] !== priority[right.recommendation]) {
          return priority[left.recommendation] - priority[right.recommendation]
        }
        return left.name.localeCompare(right.name, 'zh-CN')
      })
  })

  const recommendedRemoteSiteIds = computed(() =>
    remoteSyncCandidates.value
      .filter((item) => item.defaultSelected && item.selectable)
      .map((item) => item.id),
  )

  async function openRemoteSyncDialog() {
    await loadRemoteSites()
    if (error.value) return
    selectedRemoteSiteIds.value = recommendedRemoteSiteIds.value
    remoteSitePullOptions.value = Object.fromEntries(
      remoteSyncCandidates.value.map((candidate) => [
        candidate.id,
        createDefaultPullOptions(),
      ]),
    )
    isRemoteSyncDialogOpen.value = true
  }

  function closeRemoteSyncDialog() {
    isRemoteSyncDialogOpen.value = false
  }

  function toggleRemoteSiteSelection(remoteSiteId: string) {
    if (selectedRemoteSiteIds.value.includes(remoteSiteId)) {
      selectedRemoteSiteIds.value = selectedRemoteSiteIds.value.filter(
        (item) => item !== remoteSiteId,
      )
      return
    }
    selectedRemoteSiteIds.value = [...selectedRemoteSiteIds.value, remoteSiteId]
  }

  function selectRecommendedRemoteSites() {
    selectedRemoteSiteIds.value = recommendedRemoteSiteIds.value
  }

  function clearRemoteSiteSelection() {
    selectedRemoteSiteIds.value = []
  }

  function toggleRemoteSitePullOption(
    remoteSiteId: string,
    field: keyof SafeLineSitePullOptions,
  ) {
    const candidate = remoteSyncCandidates.value.find((item) => item.id === remoteSiteId)
    if (!candidate) return
    if (field === 'primary_hostname' && candidate.linkedLocalSiteId === null) return

    const current = remoteSitePullOptions.value[remoteSiteId] ?? createDefaultPullOptions()
    remoteSitePullOptions.value = {
      ...remoteSitePullOptions.value,
      [remoteSiteId]: {
        ...current,
        [field]: !current[field],
      },
    }
  }

  async function syncSelectedRemoteSites() {
    if (!selectedRemoteSiteIds.value.length) {
      error.value = '请先选择要同步的雷池站点。'
      return
    }

    syncingRemoteSelection.value = true
    clearFeedback()
    let successCount = 0
    const failed: string[] = []

    try {
      for (const remoteSiteId of selectedRemoteSiteIds.value) {
        const candidate = remoteSyncCandidates.value.find((item) => item.id === remoteSiteId)
        try {
          await pullSafeLineSite(
            remoteSiteId,
            remoteSitePullOptions.value[remoteSiteId] ?? createDefaultPullOptions(),
          )
          successCount += 1
          notifySuccess(
            `${candidate?.domain || candidate?.name || remoteSiteId} 已同步到本地。`,
            {
              title: '站点同步成功',
              duration: 2400,
            },
          )
        } catch (e) {
          const message =
            e instanceof Error ? e.message : '站点同步失败'
          failed.push(
            e instanceof Error ? `${remoteSiteId}: ${e.message}` : remoteSiteId,
          )
          notifyError(
            `${candidate?.domain || candidate?.name || remoteSiteId}：${message}`,
            {
              title: '站点同步失败',
              duration: 5600,
            },
          )
        }
      }

      await refreshCollections('live')
      if (failed.length) {
        error.value = `已同步 ${successCount} 个站点，${failed.length} 个失败：${failed.join('；')}`
      } else {
        setSuccessMessage(`已从雷池同步 ${successCount} 个站点到本地。`)
      }
      if (successCount > 0) {
        closeRemoteSyncDialog()
      }
    } finally {
      syncingRemoteSelection.value = false
    }
  }

  return {
    clearRemoteSiteSelection,
    closeRemoteSyncDialog,
    isRemoteSyncDialogOpen,
    openRemoteSyncDialog,
    recommendedRemoteSiteIds,
    remoteSitePullOptions,
    remoteSyncCandidates,
    selectRecommendedRemoteSites,
    selectedRemoteSiteIds,
    syncingRemoteSelection,
    syncSelectedRemoteSites,
    toggleRemoteSitePullOption,
    toggleRemoteSiteSelection,
  }
}
