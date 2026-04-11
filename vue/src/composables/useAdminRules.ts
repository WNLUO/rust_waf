import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  createRule,
  deleteRule,
  deleteRuleActionPlugin,
  fetchRuleActionPlugins,
  fetchRuleActionTemplates,
  fetchRulesList,
  installRuleActionPlugin,
  updateRuleActionPlugin,
  uploadRuleActionPlugin,
  updateRule,
} from '../lib/api'
import {
  applyPluginTemplateToDraft,
  buildRulePayload,
  createDefaultResponseTemplate,
  createDefaultRuleDraft,
  createEditableRuleDraft,
  isPluginActionValue,
  toPluginActionValue,
} from '../lib/adminRules'
import type {
  RuleActionPluginItem,
  RuleActionTemplateItem,
  RuleDraft,
  RuleItem,
  RulesResponse,
} from '../lib/types'

export function useAdminRules() {
  const route = useRoute()
  const router = useRouter()
  const loading = ref(true)
  const saving = ref(false)
  const installingPlugin = ref(false)
  const error = ref('')
  const rulesPayload = ref<RulesResponse>({ rules: [] })
  const isRuleModalOpen = ref(false)
  const pluginInstallUrl = ref('')
  const pluginInstallFile = ref<File | null>(null)
  const pluginInstallSha256 = ref('')
  const installedPlugins = ref<RuleActionPluginItem[]>([])
  const pluginTemplates = ref<RuleActionTemplateItem[]>([])

  const ruleForm = reactive<RuleDraft>(createDefaultRuleDraft())
  const ruleFilters = reactive({
    search: '',
    layer: 'all',
    action: 'all',
    severity: 'all',
    status: 'all',
  })

  const filteredRules = computed(() =>
    rulesPayload.value.rules.filter((rule) => {
      if (ruleFilters.layer !== 'all' && rule.layer !== ruleFilters.layer)
        return false
      if (ruleFilters.action !== 'all' && rule.action !== ruleFilters.action)
        return false
      if (
        ruleFilters.severity !== 'all' &&
        rule.severity !== ruleFilters.severity
      )
        return false
      if (
        ruleFilters.status !== 'all' &&
        rule.enabled !== (ruleFilters.status === 'enabled')
      )
        return false
      if (!ruleFilters.search.trim()) return true
      const keyword = ruleFilters.search.trim().toLowerCase()
      return (
        rule.name.toLowerCase().includes(keyword) ||
        rule.id.toLowerCase().includes(keyword) ||
        rule.pattern.toLowerCase().includes(keyword)
      )
    }),
  )

  const selectedPluginTemplate = computed(() =>
    pluginTemplates.value.find(
      (item) => item.template_id === ruleForm.plugin_template_id,
    ),
  )

  const consumeCreateRuleQuery = async () => {
    if (route.query.create !== '1') return

    const nextQuery = { ...route.query }
    delete nextQuery.create
    delete nextQuery.template
    delete nextQuery.action

    Object.assign(ruleForm, createDefaultRuleDraft())
    const templateId =
      typeof route.query.template === 'string' ? route.query.template : null
    const action =
      typeof route.query.action === 'string' ? route.query.action : null

    if (templateId) {
      const template = pluginTemplates.value.find(
        (item) => item.template_id === templateId,
      )
      if (!template) return
      ruleForm.action = toPluginActionValue(template.template_id)
      Object.assign(ruleForm, applyPluginTemplateToDraft(ruleForm, template))
    } else if (action) {
      ruleForm.action = action
      if (action === 'respond') {
        ruleForm.layer = 'l7'
        ruleForm.response_template = createDefaultResponseTemplate()
      }
    }

    isRuleModalOpen.value = true
    await router.replace({ query: nextQuery })
  }

  const displayActionLabel = (
    rule: RuleItem,
    actionLabel: (value: string) => string,
  ) => {
    if (rule.plugin_template_id) {
      const template = pluginTemplates.value.find(
        (item) => item.template_id === rule.plugin_template_id,
      )
      if (template) return `插件 · ${template.name}`
    }
    return actionLabel(rule.action)
  }

  const loadRules = async () => {
    loading.value = true
    try {
      const [rules, plugins, templates] = await Promise.all([
        fetchRulesList(),
        fetchRuleActionPlugins(),
        fetchRuleActionTemplates(),
      ])
      rulesPayload.value = rules
      installedPlugins.value = plugins.plugins
      pluginTemplates.value = templates.templates
      error.value = ''
    } catch (e) {
      error.value = e instanceof Error ? e.message : '读取规则失败'
    } finally {
      loading.value = false
    }
  }

  const openCreateRule = () => {
    Object.assign(ruleForm, createDefaultRuleDraft())
    isRuleModalOpen.value = true
  }

  const openEditRule = (rule: RuleItem) => {
    Object.assign(ruleForm, createEditableRuleDraft(rule))
    isRuleModalOpen.value = true
  }

  const closeRuleModal = () => {
    isRuleModalOpen.value = false
  }

  const handleCreateOrUpdateRule = async () => {
    saving.value = true
    try {
      const payload = buildRulePayload(ruleForm, pluginTemplates.value)
      if (ruleForm.id) {
        await updateRule(payload)
      } else {
        await createRule(payload)
      }
      isRuleModalOpen.value = false
      await loadRules()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '规则保存失败'
    } finally {
      saving.value = false
    }
  }

  const onActionChange = () => {
    if (isPluginActionValue(ruleForm.action)) {
      const templateId = ruleForm.action.slice('plugin:'.length)
      const template = pluginTemplates.value.find(
        (item) => item.template_id === templateId,
      )
      if (!template) return
      Object.assign(ruleForm, applyPluginTemplateToDraft(ruleForm, template))
      return
    }

    ruleForm.plugin_template_id = null
    if (ruleForm.layer !== 'l7' && ruleForm.action === 'respond') {
      ruleForm.action = 'block'
    }
  }

  const addResponseHeader = () => {
    ruleForm.response_template?.headers.push({ key: '', value: '' })
  }

  const removeResponseHeader = (index: number) => {
    ruleForm.response_template?.headers.splice(index, 1)
  }

  const handleInstallPlugin = async () => {
    const packageUrl = pluginInstallUrl.value.trim()
    if (!packageUrl && !pluginInstallFile.value) {
      error.value = '请输入插件包 URL 或选择本地 zip 文件'
      return
    }

    installingPlugin.value = true
    try {
      if (pluginInstallFile.value) {
        await uploadRuleActionPlugin(
          pluginInstallFile.value,
          pluginInstallSha256.value,
        )
      } else {
        await installRuleActionPlugin(packageUrl, pluginInstallSha256.value)
      }
      pluginInstallUrl.value = ''
      pluginInstallFile.value = null
      pluginInstallSha256.value = ''
      await loadRules()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '插件安装失败'
    } finally {
      installingPlugin.value = false
    }
  }

  const toggleRuleStatus = async (rule: RuleItem) => {
    try {
      await updateRule({ ...rule, enabled: !rule.enabled })
      await loadRules()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '更新规则状态失败'
    }
  }

  const togglePluginStatus = async (plugin: RuleActionPluginItem) => {
    try {
      await updateRuleActionPlugin(plugin.plugin_id, !plugin.enabled)
      await loadRules()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '更新插件状态失败'
    }
  }

  const handleDeletePlugin = async (pluginId: string) => {
    if (!window.confirm('确认卸载这个插件吗？相关规则会被停用。')) return
    try {
      await deleteRuleActionPlugin(pluginId)
      await loadRules()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '插件卸载失败'
    }
  }

  const handleDeleteRule = async (id: string) => {
    if (!window.confirm('确认删除这条规则吗？')) return
    try {
      await deleteRule(id)
      await loadRules()
    } catch (e) {
      error.value = e instanceof Error ? e.message : '规则删除失败'
    }
  }

  onMounted(loadRules)

  watch(
    [
      () => route.query.create,
      () => route.query.template,
      () => pluginTemplates.value.length,
    ],
    () => {
      void consumeCreateRuleQuery()
    },
    { immediate: true },
  )

  return {
    addResponseHeader,
    closeRuleModal,
    createDefaultResponseTemplate,
    displayActionLabel,
    error,
    filteredRules,
    handleCreateOrUpdateRule,
    handleDeleteRule,
    handleInstallPlugin,
    installedPlugins,
    installingPlugin,
    isPluginActionValue,
    isRuleModalOpen,
    loadRules,
    loading,
    onActionChange,
    openCreateRule,
    openEditRule,
    pluginInstallUrl,
    pluginInstallFile,
    pluginInstallSha256,
    pluginTemplates,
    removeResponseHeader,
    ruleFilters,
    ruleForm,
    rulesPayload,
    saving,
    selectedPluginTemplate,
    toPluginActionValue,
    togglePluginStatus,
    toggleRuleStatus,
    handleDeletePlugin,
  }
}
