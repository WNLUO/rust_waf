import type { Ref } from 'vue'
import { createLocalSite, deleteLocalSite, updateLocalSite } from '@/shared/api/sites'
import type { LocalSiteDraft } from '@/shared/types'
import type { useAdminSitesData } from './useAdminSitesData'
import type { useAdminSitesEditor } from './useAdminSitesEditor'

function cloneSafelineIntercept(
  value: LocalSiteDraft['safeline_intercept'],
): LocalSiteDraft['safeline_intercept'] {
  if (!value) return null
  return {
    ...value,
    response_template: {
      ...value.response_template,
      headers: value.response_template.headers.map((header) => ({ ...header })),
    },
  }
}

interface UseAdminSitesLocalCrudOptions {
  clearFeedback: () => void
  data: ReturnType<typeof useAdminSitesData>
  editor: ReturnType<typeof useAdminSitesEditor>
  error: Ref<string>
  successMessage: Ref<string>
}

export function useAdminSitesLocalCrud({
  clearFeedback,
  data,
  editor,
  error,
  successMessage,
}: UseAdminSitesLocalCrudOptions) {
  async function saveLocalSite() {
    data.actions.savingLocalSite = true
    clearFeedback()
    try {
      const payload: LocalSiteDraft = {
        name: editor.localSiteForm.name.trim(),
        primary_hostname: editor.localSiteForm.primary_hostname.trim(),
        hostnames: editor.localSiteForm.hostnames
          .map((item) => item.trim())
          .filter(Boolean),
        listen_ports: [],
        upstreams: editor.localSiteForm.upstreams
          .map((item) => item.trim())
          .filter(Boolean),
        safeline_intercept: cloneSafelineIntercept(
          editor.localSiteForm.safeline_intercept,
        ),
        enabled: editor.localSiteForm.enabled,
        tls_enabled: editor.localSiteForm.tls_enabled,
        local_certificate_id: editor.localSiteForm.local_certificate_id,
        source: 'manual',
        sync_mode: editor.localSiteForm.sync_mode.trim() || 'manual',
        notes: editor.localSiteForm.notes.trim(),
        last_synced_at: editor.currentLocalSite.value?.last_synced_at ?? null,
      }

      if (editor.editingLocalSiteId.value === null) {
        const created = await createLocalSite(payload)
        successMessage.value = `本地站点 ${created.name} 已创建。重启服务后生效。`
        editor.editingLocalSiteId.value = created.id
      } else {
        const response = await updateLocalSite(
          editor.editingLocalSiteId.value,
          payload,
        )
        successMessage.value = response.message
      }

      await data.refreshCollections(
        data.sitesLoadedAt.value !== null ? 'cached' : 'none',
      )

      if (editor.editingLocalSiteId.value !== null) {
        const updatedSite =
          data.localSites.value.find(
            (item) => item.id === editor.editingLocalSiteId.value,
          ) ?? null
        if (updatedSite) {
          editor.populateLocalSiteForm(
            editor.siteDraftFromItem(updatedSite),
            updatedSite.id,
          )
        }
      }

      editor.closeLocalSiteModal()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '保存本地站点失败'
    } finally {
      data.actions.savingLocalSite = false
    }
  }

  async function removeCurrentLocalSite() {
    if (editor.editingLocalSiteId.value === null) return
    data.actions.deletingLocalSite = true
    clearFeedback()
    try {
      const response = await deleteLocalSite(editor.editingLocalSiteId.value)
      successMessage.value = response.message
      editor.resetLocalSiteForm()
      await data.refreshCollections(
        data.sitesLoadedAt.value !== null ? 'cached' : 'none',
      )
      editor.closeLocalSiteModal()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '删除本地站点失败'
    } finally {
      data.actions.deletingLocalSite = false
    }
  }

  return {
    removeCurrentLocalSite,
    saveLocalSite,
  }
}
