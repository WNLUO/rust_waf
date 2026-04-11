export interface SafeLineEventSyncResponse {
  success: boolean
  imported: number
  skipped: number
  last_cursor: number | null
  message: string
}

export interface SafeLineSyncStateResponse {
  resource: string
  last_cursor: number | null
  last_success_at: number | null
  last_imported_count: number
  last_skipped_count: number
  updated_at: number
}

export interface SafeLineSyncOverviewResponse {
  events: SafeLineSyncStateResponse | null
  blocked_ips_push: SafeLineSyncStateResponse | null
  blocked_ips_pull: SafeLineSyncStateResponse | null
  blocked_ips_delete: SafeLineSyncStateResponse | null
}

export interface SafeLineBlocklistSyncResponse {
  success: boolean
  synced: number
  skipped: number
  failed: number
  last_cursor: number | null
  message: string
}

export interface SafeLineBlocklistPullResponse {
  success: boolean
  imported: number
  skipped: number
  last_cursor: number | null
  message: string
}
