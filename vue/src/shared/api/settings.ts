import type {
  GlobalSettingsPayload,
  SettingsPayload,
  WriteStatusResponse,
} from '@/shared/types'
import { apiRequest } from './core'

export function fetchSettings() {
  return apiRequest<SettingsPayload>('/settings')
}

export function updateSettings(payload: SettingsPayload) {
  return apiRequest<WriteStatusResponse>('/settings', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function fetchGlobalSettings() {
  return apiRequest<GlobalSettingsPayload>('/global-settings')
}

export function updateGlobalSettings(payload: GlobalSettingsPayload) {
  return apiRequest<WriteStatusResponse>('/global-settings', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}
