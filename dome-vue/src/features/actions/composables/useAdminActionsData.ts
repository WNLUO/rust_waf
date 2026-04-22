import { computed, ref, type Ref } from 'vue'
import {
  deleteRuleActionPlugin,
  fetchActionIdeaPresets,
  fetchRuleActionPlugins,
  fetchRuleActionTemplates,
  updateRuleActionPlugin,
  uploadRuleActionPlugin,
} from '@/shared/api/rules'
import type {
  ActionIdeaPreset,
  RuleActionPluginItem,
  RuleActionTemplateItem,
} from '@/shared/types'
import {
  toActionIdeaCards,
  type ActionIdeaCard,
} from '@/features/actions/utils/actionIdeaPreview'

export function useAdminActionsData(error: Ref<string>) {
  const loading = ref(true)
  const refreshing = ref(false)
  const installingPlugin = ref(false)
  const installedPlugins = ref<RuleActionPluginItem[]>([])
  const pluginTemplates = ref<RuleActionTemplateItem[]>([])
  const actionIdeas = ref<ActionIdeaPreset[]>([])

  const templateCount = computed(() => pluginTemplates.value.length)
  const pluginsById = computed(
    () => new Map(installedPlugins.value.map((item) => [item.plugin_id, item])),
  )
  const actionIdeasById = computed(
    () => new Map(actionIdeas.value.map((item) => [item.id, item])),
  )
  const funIdeaCards = computed<ActionIdeaCard[]>(() =>
    toActionIdeaCards(actionIdeas.value, pluginTemplates.value),
  )

  const loadActionCenter = async () => {
    loading.value = true
    refreshing.value = true
    try {
      const [plugins, templates, ideas] = await Promise.all([
        fetchRuleActionPlugins(),
        fetchRuleActionTemplates(),
        fetchActionIdeaPresets(),
      ])
      installedPlugins.value = plugins.plugins
      pluginTemplates.value = templates.templates
      actionIdeas.value = ideas.ideas
      error.value = ''
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取动作中心失败'
    } finally {
      loading.value = false
      refreshing.value = false
    }
  }

  const installPlugin = async (file: File) => {
    installingPlugin.value = true
    try {
      await uploadRuleActionPlugin(file)
      await loadActionCenter()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '插件安装失败'
    } finally {
      installingPlugin.value = false
    }
  }

  const togglePluginStatus = async (plugin: RuleActionPluginItem) => {
    try {
      await updateRuleActionPlugin(plugin.plugin_id, !plugin.enabled)
      await loadActionCenter()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '更新插件状态失败'
    }
  }

  const deletePlugin = async (pluginId: string) => {
    if (!window.confirm('确认卸载这个动作插件吗？相关动作模板会一并移除。')) {
      return
    }
    try {
      await deleteRuleActionPlugin(pluginId)
      await loadActionCenter()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '插件卸载失败'
    }
  }

  return {
    actionIdeas,
    actionIdeasById,
    deletePlugin,
    funIdeaCards,
    installPlugin,
    installedPlugins,
    installingPlugin,
    loadActionCenter,
    loading,
    pluginTemplates,
    pluginsById,
    refreshing,
    templateCount,
    togglePluginStatus,
  }
}
