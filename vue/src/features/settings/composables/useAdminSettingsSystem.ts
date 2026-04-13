import {
  clearLocalSiteData,
  fetchGlobalEntryConfig,
  updateGlobalEntryConfig,
} from '@/shared/api/sites'
import { fetchSettings, updateSettings } from '@/shared/api/settings'
import type { AdminSettingsState } from '@/features/settings/composables/useAdminSettingsState'

interface UseAdminSettingsSystemOptions {
  state: AdminSettingsState
}

export function useAdminSettingsSystem({
  state,
}: UseAdminSettingsSystemOptions) {
  const {
    clearingSiteData,
    clearFeedback,
    error,
    globalEntryForm,
    loading,
    mappings,
    saving,
    sites,
    sitesLoadedAt,
    successMessage,
    systemSettings,
    toPlainSettingsPayload,
  } = state

  async function loadSettings() {
    loading.value = true
    error.value = ''
    try {
      const [payload, globalEntryPayload] = await Promise.all([
        fetchSettings(),
        fetchGlobalEntryConfig(),
      ])
      Object.assign(systemSettings, payload)
      Object.assign(globalEntryForm, globalEntryPayload)
    } catch (e) {
      error.value = e instanceof Error ? e.message : '系统设置加载失败'
    } finally {
      loading.value = false
    }
  }

  async function saveSettings() {
    saving.value = true
    clearFeedback()
    try {
      systemSettings.auto_refresh_seconds = Number.isFinite(
        systemSettings.auto_refresh_seconds,
      )
        ? Math.min(Math.max(systemSettings.auto_refresh_seconds, 3), 60)
        : 5
      systemSettings.retain_days = Number.isFinite(systemSettings.retain_days)
        ? Math.min(Math.max(systemSettings.retain_days, 1), 365)
        : 30
      systemSettings.safeline.auto_sync_interval_secs = Number.isFinite(
        systemSettings.safeline.auto_sync_interval_secs,
      )
        ? Math.min(
            Math.max(systemSettings.safeline.auto_sync_interval_secs, 15),
            86400,
          )
        : 300

      const [settingsResponse, globalEntryResponse] = await Promise.all([
        updateSettings(toPlainSettingsPayload()),
        updateGlobalEntryConfig({
          http_port: globalEntryForm.http_port.trim(),
          https_port: globalEntryForm.https_port.trim(),
        }),
      ])
      successMessage.value =
        globalEntryResponse.message || settingsResponse.message
    } catch (e) {
      error.value = e instanceof Error ? e.message : '系统设置保存失败'
    } finally {
      saving.value = false
    }
  }

  async function clearSiteData() {
    clearingSiteData.value = true
    clearFeedback()
    try {
      const response = await clearLocalSiteData()
      sites.value = []
      mappings.value = []
      sitesLoadedAt.value = null
      successMessage.value = response.message
    } catch (e) {
      error.value = e instanceof Error ? e.message : '清空站点数据失败'
    } finally {
      clearingSiteData.value = false
    }
  }

  return {
    clearSiteData,
    loadSettings,
    saveSettings,
  }
}
