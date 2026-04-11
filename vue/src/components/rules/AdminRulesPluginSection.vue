<script setup lang="ts">
import { Power, Trash2 } from 'lucide-vue-next'
import type { RuleActionPluginItem } from '../../lib/types'

defineProps<{
  installedPlugins: RuleActionPluginItem[]
  installingPlugin: boolean
  pluginInstallFile: File | null
  pluginInstallSha256: string
  pluginInstallUrl: string
}>()

defineEmits<{
  'delete-plugin': [pluginId: string]
  install: []
  'toggle-plugin': [plugin: RuleActionPluginItem]
  'update:plugin-install-file': [value: File | null]
  'update:plugin-install-sha256': [value: string]
  'update:plugin-install-url': [value: string]
}>()
</script>

<template>
  <div class="rounded-[28px] border border-white/70 bg-white/60 p-4">
    <div class="flex flex-wrap items-center gap-3">
      <div class="min-w-[220px] flex-1">
        <p class="text-sm font-medium text-stone-900">动作插件</p>
        <p class="text-xs text-slate-500">
          支持输入 zip 包 URL，或直接上传本地 zip。安装后会把动作模板加入动作中心，并可在规则中心绑定到站点。
        </p>
      </div>
      <input
        :value="pluginInstallUrl"
        type="text"
        class="min-w-[240px] flex-1 rounded-lg border border-slate-200 bg-white px-4 py-3 text-sm outline-none transition focus:border-blue-500"
        placeholder="https://example.com/plugins/gzip-block.zip"
        @input="
          $emit(
            'update:plugin-install-url',
            ($event.target as HTMLInputElement).value,
          )
        "
      />
      <input
        :value="pluginInstallSha256"
        type="text"
        class="min-w-[240px] flex-1 rounded-lg border border-slate-200 bg-white px-4 py-3 text-sm outline-none transition focus:border-blue-500"
        placeholder="可选：SHA-256 校验值"
        @input="
          $emit(
            'update:plugin-install-sha256',
            ($event.target as HTMLInputElement).value,
          )
        "
      />
      <label
        class="inline-flex cursor-pointer items-center gap-2 rounded-[18px] border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
      >
        <input
          type="file"
          accept=".zip,application/zip"
          class="hidden"
          @change="
            $emit(
              'update:plugin-install-file',
              (($event.target as HTMLInputElement).files ?? [])[0] ?? null,
            )
          "
        />
        {{ pluginInstallFile ? pluginInstallFile.name : '选择本地 zip' }}
      </label>
      <button
        class="inline-flex items-center gap-2 rounded-[18px] bg-stone-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-stone-800 disabled:opacity-60"
        :disabled="installingPlugin"
        @click="$emit('install')"
      >
        {{ installingPlugin ? '安装中...' : '安装动作插件' }}
      </button>
    </div>

    <div v-if="installedPlugins.length" class="mt-4 flex flex-wrap gap-2">
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
