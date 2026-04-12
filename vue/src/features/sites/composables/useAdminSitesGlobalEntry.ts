import { ref, type Reactive, type Ref } from 'vue'
import { fetchGlobalEntryConfig, updateGlobalEntryConfig } from '@/shared/api/sites'
import type { GlobalEntryConfigPayload } from '@/shared/types'

interface UseAdminSitesGlobalEntryOptions {
  actions: {
    savingGlobalEntry: boolean
  }
  clearFeedback: () => void
  error: Ref<string>
  globalEntryForm: Reactive<GlobalEntryConfigPayload>
  successMessage: Ref<string>
}

export function useAdminSitesGlobalEntry({
  actions,
  clearFeedback,
  error,
  globalEntryForm,
  successMessage,
}: UseAdminSitesGlobalEntryOptions) {
  const isGlobalEntryModalOpen = ref(false)

  function openGlobalEntryModal() {
    isGlobalEntryModalOpen.value = true
  }

  function closeGlobalEntryModal() {
    isGlobalEntryModalOpen.value = false
  }

  async function saveGlobalEntry() {
    actions.savingGlobalEntry = true
    clearFeedback()
    try {
      const response = await updateGlobalEntryConfig({
        http_port: globalEntryForm.http_port.trim(),
        https_port: globalEntryForm.https_port.trim(),
      })
      successMessage.value = response.message
      Object.assign(globalEntryForm, await fetchGlobalEntryConfig())
      closeGlobalEntryModal()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '保存全局入口失败'
    } finally {
      actions.savingGlobalEntry = false
    }
  }

  return {
    closeGlobalEntryModal,
    isGlobalEntryModalOpen,
    openGlobalEntryModal,
    saveGlobalEntry,
  }
}
