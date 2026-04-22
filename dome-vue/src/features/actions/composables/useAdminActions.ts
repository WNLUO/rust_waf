import { onMounted, ref } from 'vue'
import { useAdminActionPreview } from './useAdminActionPreview'
import { useAdminActionsData } from './useAdminActionsData'

export function useAdminActions() {
  const error = ref('')
  const data = useAdminActionsData(error)
  const preview = useAdminActionPreview({
    actionIdeas: data.actionIdeas,
    actionIdeasById: data.actionIdeasById,
    error,
    pluginsById: data.pluginsById,
  })

  onMounted(data.loadActionCenter)

  return {
    ...data,
    ...preview,
    error,
  }
}
