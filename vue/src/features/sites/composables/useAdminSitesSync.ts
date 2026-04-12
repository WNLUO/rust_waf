import { reactive } from 'vue'
import type { SiteRowDraft } from '@/features/sites/utils/adminSites'

export function useAdminSitesSync(
  formatTimestamp: (timestamp?: number | null) => string,
  sitesLoadedAt: { value: number | null },
  clearFeedback: () => void,
  refreshCollections: (
    remoteSource: 'none' | 'cached' | 'live',
  ) => Promise<void>,
  pullRemote: (siteId: string) => Promise<{ message: string }>,
  pushLocal: (siteId: number) => Promise<{ message: string }>,
  setSuccessMessage: (value: string) => void,
  setErrorMessage: (value: string) => void,
) {
  const rowActions = reactive<Record<string, 'pull' | 'push' | undefined>>({})

  async function syncRemoteSite(row: SiteRowDraft) {
    if (!row.safeline_site_id) return
    rowActions[row.row_key] = 'pull'
    clearFeedback()
    try {
      const response = await pullRemote(row.safeline_site_id)
      await refreshCollections('live')
      setSuccessMessage(response.message)
    } catch (e) {
      setErrorMessage(e instanceof Error ? e.message : '单站点回流失败')
    } finally {
      delete rowActions[row.row_key]
    }
  }

  async function syncLocalSite(row: SiteRowDraft) {
    if (!row.local_site_id) return
    rowActions[row.row_key] = 'push'
    clearFeedback()
    try {
      const response = await pushLocal(row.local_site_id)
      await refreshCollections('live')
      setSuccessMessage(response.message)
    } catch (e) {
      setErrorMessage(e instanceof Error ? e.message : '单站点推送失败')
    } finally {
      delete rowActions[row.row_key]
    }
  }

  function rowActionPending(row: SiteRowDraft, action: 'pull' | 'push') {
    return rowActions[row.row_key] === action
  }

  function rowBusy(row: SiteRowDraft) {
    return Boolean(rowActions[row.row_key])
  }

  function remoteActionLabel(row: SiteRowDraft) {
    return row.local_present ? '从雷池更新' : '导入到本地'
  }

  function localActionLabel(row: SiteRowDraft) {
    if (row.row_kind === 'missing_remote') return '重新创建到雷池'
    return row.remote_present && row.link_id ? '推送到雷池' : '创建到雷池'
  }

  function rowSyncText(row: SiteRowDraft) {
    if (row.link_last_error) return row.link_last_error
    if (row.link_last_synced_at)
      return `最近同步：${formatTimestamp(row.link_last_synced_at)}`
    if (row.remote_present && sitesLoadedAt.value) {
      return `远端读取：${formatTimestamp(sitesLoadedAt.value)}`
    }
    if (row.local_updated_at) {
      return `本地更新：${formatTimestamp(row.local_updated_at)}`
    }
    return '尚未执行单站点同步'
  }

  return {
    localActionLabel,
    remoteActionLabel,
    rowActionPending,
    rowBusy,
    rowSyncText,
    syncLocalSite,
    syncRemoteSite,
  }
}
