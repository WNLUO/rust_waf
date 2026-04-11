<script setup lang="ts">
import { RefreshCw } from 'lucide-vue-next'
import AppLayout from '../components/layout/AppLayout.vue'
import AdminRuleEditorDialog from '../components/rules/AdminRuleEditorDialog.vue'
import AdminRulesFilterBar from '../components/rules/AdminRulesFilterBar.vue'
import AdminRulesPluginSection from '../components/rules/AdminRulesPluginSection.vue'
import AdminRulesTableSection from '../components/rules/AdminRulesTableSection.vue'
import { useAdminRules } from '../composables/useAdminRules'
import { useFormatters } from '../composables/useFormatters'

const { actionLabel, layerLabel, severityLabel } = useFormatters()

const {
  addResponseHeader,
  closeRuleModal,
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
  saving,
  selectedPluginTemplate,
  toPluginActionValue,
  togglePluginStatus,
  toggleRuleStatus,
  handleDeletePlugin,
} = useAdminRules()
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
        :disabled="loading"
        @click="loadRules"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': loading }" />
        刷新规则
      </button>
    </template>

    <div class="space-y-6">
      <div
        v-if="error"
        class="rounded-xl border border-red-500/25 bg-red-500/8 px-4 py-3 text-sm text-red-600 shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

      <AdminRulesFilterBar
        :filters="ruleFilters"
        @create="openCreateRule"
        @update:filters="Object.assign(ruleFilters, $event)"
      />

      <AdminRulesPluginSection
        :installed-plugins="installedPlugins"
        :installing-plugin="installingPlugin"
        :plugin-install-file="pluginInstallFile"
        :plugin-install-sha256="pluginInstallSha256"
        :plugin-install-url="pluginInstallUrl"
        @delete-plugin="handleDeletePlugin"
        @install="handleInstallPlugin"
        @update:plugin-install-file="pluginInstallFile = $event"
        @update:plugin-install-sha256="pluginInstallSha256 = $event"
        @update:plugin-install-url="pluginInstallUrl = $event"
        @toggle-plugin="togglePluginStatus"
      />

      <AdminRulesTableSection
        :display-action-label="(rule) => displayActionLabel(rule, actionLabel)"
        :filtered-rules="filteredRules"
        :layer-label="layerLabel"
        :loading="loading"
        :severity-label="severityLabel"
        @delete="handleDeleteRule"
        @edit="openEditRule"
        @toggle="toggleRuleStatus"
      />
    </div>

    <AdminRuleEditorDialog
      :is-plugin-action-value="isPluginActionValue"
      :open="isRuleModalOpen"
      :plugin-templates="pluginTemplates"
      :rule-form="ruleForm"
      :saving="saving"
      :selected-plugin-template="selectedPluginTemplate"
      :to-plugin-action-value="toPluginActionValue"
      @action-change="onActionChange"
      @add-header="addResponseHeader"
      @close="closeRuleModal"
      @remove-header="removeResponseHeader"
      @save="handleCreateOrUpdateRule"
      @update:rule-form="Object.assign(ruleForm, $event)"
    />
  </AppLayout>
</template>
