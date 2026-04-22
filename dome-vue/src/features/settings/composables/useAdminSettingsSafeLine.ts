import { computed } from 'vue'
import {
  fetchSafeLineMappings,
  fetchSafeLineSites,
  testSafeLineConnection,
  updateSafeLineMappings,
} from '@/shared/api/safeline'
import type { SafeLineSiteItem } from '@/shared/types'
import type { AdminSettingsState } from '@/features/settings/composables/useAdminSettingsState'

interface UseAdminSettingsSafeLineOptions {
  state: AdminSettingsState
}

export function useAdminSettingsSafeLine({
  state,
}: UseAdminSettingsSafeLineOptions) {
  const {
    clearFeedback,
    error,
    loadingSites,
    mappings,
    savingMappings,
    sites,
    sitesLoadedAt,
    successMessage,
    testResult,
    testing,
    toPlainSafeLineTestPayload,
  } = state

  async function loadMappings() {
    try {
      const response = await fetchSafeLineMappings()
      mappings.value = response.mappings
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取雷池站点映射失败'
    }
  }

  async function runSafeLineTest() {
    testing.value = true
    error.value = ''
    try {
      testResult.value = await testSafeLineConnection(
        toPlainSafeLineTestPayload(),
      )
    } catch (e) {
      error.value = e instanceof Error ? e.message : '雷池连通性测试失败'
      testResult.value = null
    } finally {
      testing.value = false
    }
  }

  async function loadSafeLineSites() {
    loadingSites.value = true
    error.value = ''
    try {
      const response = await fetchSafeLineSites(toPlainSafeLineTestPayload())
      sites.value = response.sites
      sitesLoadedAt.value = Math.floor(Date.now() / 1000)
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取雷池站点列表失败'
      sites.value = []
    } finally {
      loadingSites.value = false
    }
  }

  function siteMappingDraft(site: SafeLineSiteItem) {
    const existing = mappings.value.find(
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
    }
  }

  const mappingDrafts = computed(() => sites.value.map(siteMappingDraft))

  async function saveMappings() {
    savingMappings.value = true
    clearFeedback()
    try {
      const payload = {
        mappings: mappingDrafts.value.map((item) => ({
          safeline_site_id: item.safeline_site_id,
          safeline_site_name: item.safeline_site_name,
          safeline_site_domain: item.safeline_site_domain,
          local_alias: item.local_alias,
          enabled: item.enabled,
          is_primary: item.is_primary,
          notes: item.notes,
        })),
      }
      const response = await updateSafeLineMappings(payload)
      successMessage.value = response.message
      await loadMappings()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '保存雷池站点映射失败'
    } finally {
      savingMappings.value = false
    }
  }

  return {
    loadMappings,
    loadSafeLineSites,
    mappingDrafts,
    runSafeLineTest,
    saveMappings,
  }
}
