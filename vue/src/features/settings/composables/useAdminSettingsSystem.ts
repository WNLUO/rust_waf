import { fetchGlobalEntryConfig, updateGlobalEntryConfig } from '@/shared/api/sites'
import { fetchSettings, updateSettings } from '@/shared/api/settings'
import type { AdminSettingsState } from '@/features/settings/composables/useAdminSettingsState'

interface UseAdminSettingsSystemOptions {
  state: AdminSettingsState
}

export function useAdminSettingsSystem({
  state,
}: UseAdminSettingsSystemOptions) {
  const {
    clearFeedback,
    error,
    globalEntryForm,
    loading,
    saving,
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

  return {
    loadSettings,
    saveSettings,
  }
}
