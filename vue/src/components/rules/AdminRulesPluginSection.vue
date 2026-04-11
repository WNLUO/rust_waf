<script setup lang="ts">
defineProps<{
  installedPlugins: Array<{
    plugin_id: string
    name: string
    version: string
  }>
  installingPlugin: boolean
  pluginInstallUrl: string
}>()

defineEmits<{
  install: []
  'update:plugin-install-url': [value: string]
}>()
</script>

<template>
  <div class="rounded-[28px] border border-white/70 bg-white/60 p-4">
    <div class="flex flex-wrap items-center gap-3">
      <div class="min-w-[220px] flex-1">
        <p class="text-sm font-medium text-stone-900">规则模板插件</p>
        <p class="text-xs text-slate-500">
          输入 zip 包 URL，系统会下载并安装为可选的 `respond` 模板。
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
      <button
        class="inline-flex items-center gap-2 rounded-[18px] bg-stone-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-stone-800 disabled:opacity-60"
        :disabled="installingPlugin"
        @click="$emit('install')"
      >
        {{ installingPlugin ? '安装中...' : '安装插件' }}
      </button>
    </div>

    <div v-if="installedPlugins.length" class="mt-4 flex flex-wrap gap-2">
      <span
        v-for="plugin in installedPlugins"
        :key="plugin.plugin_id"
        class="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs text-stone-700"
      >
        {{ plugin.name }} v{{ plugin.version }}
      </span>
    </div>
  </div>
</template>
