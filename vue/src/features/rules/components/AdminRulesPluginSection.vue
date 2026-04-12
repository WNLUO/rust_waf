<script setup lang="ts">
import { Power, Trash2 } from 'lucide-vue-next'
import type { RuleActionPluginItem } from '@/shared/types'

defineProps<{
  installedPlugins: RuleActionPluginItem[]
}>()

defineEmits<{
  'delete-plugin': [pluginId: string]
  'toggle-plugin': [plugin: RuleActionPluginItem]
}>()
</script>

<template>
  <div v-if="installedPlugins.length" class="rounded-[28px] border border-white/70 bg-white/60 p-4">
    <div class="flex flex-wrap gap-2">
      <div
        v-for="plugin in installedPlugins"
        :key="plugin.plugin_id"
        class="flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 text-xs text-stone-700"
      >
        <span>{{ plugin.name }} v{{ plugin.version }}</span>
        <span
          class="rounded-full px-2 py-0.5"
          :class="
            plugin.enabled
              ? 'bg-emerald-100 text-emerald-700'
              : 'bg-slate-200 text-slate-600'
          "
        >
          {{ plugin.enabled ? '启用' : '停用' }}
        </span>
        <button
          class="inline-flex items-center gap-1 rounded-full border border-slate-200 px-2 py-1 text-[11px] transition hover:border-blue-500/40 hover:text-blue-700"
          @click="$emit('toggle-plugin', plugin)"
        >
          <Power :size="12" />
          {{ plugin.enabled ? '停用' : '启用' }}
        </button>
        <button
          class="inline-flex items-center gap-1 rounded-full border border-red-500/20 px-2 py-1 text-[11px] text-red-600 transition hover:bg-red-500/8"
          @click="$emit('delete-plugin', plugin.plugin_id)"
        >
          <Trash2 :size="12" />
          卸载
        </button>
      </div>
    </div>
  </div>
</template>
