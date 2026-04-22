<script setup lang="ts">
import { Plus, RefreshCw } from 'lucide-vue-next'
import { RouterLink } from 'vue-router'
import CyberCard from '@/shared/ui/CyberCard.vue'
import type { RuleActionPluginItem, RuleActionTemplateItem } from '@/shared/types'

defineProps<{
  installingPlugin: boolean
  loading: boolean
  performanceClass: (value: '低' | '中') => string
  pluginsById: Map<string, RuleActionPluginItem>
  pluginTemplates: RuleActionTemplateItem[]
  previewResponse: (template: RuleActionTemplateItem) => string
  templateCount: number
}>()

const emit = defineEmits<{
  installPlugin: [file: File]
  previewTemplate: [template: RuleActionTemplateItem]
}>()

function handlePluginFilePicked(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0] ?? null
  input.value = ''
  if (!file) return
  emit('installPlugin', file)
}
</script>

<template>
  <CyberCard
    title="模板动作"
    sub-title="当前已安装插件提供的现成动作模板，适合快速落地 respond 场景。"
  >
    <template #header-action>
      <label
        class="inline-flex cursor-pointer items-center gap-2 rounded-full bg-stone-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-stone-800"
        :class="{ 'pointer-events-none opacity-60': installingPlugin }"
      >
        <Plus :size="14" />
        {{ installingPlugin ? '上传中...' : '上传动作插件' }}
        <input
          type="file"
          accept=".zip,application/zip"
          class="hidden"
          :disabled="installingPlugin"
          @change="handlePluginFilePicked"
        />
      </label>
    </template>
    <div v-if="loading" class="flex h-32 items-center justify-center">
      <RefreshCw class="animate-spin text-blue-700" :size="24" />
    </div>
    <div
      v-else-if="!templateCount"
      class="rounded-2xl border border-dashed border-slate-300 bg-slate-50 px-4 py-8 text-center text-sm text-slate-500"
    >
      当前还没有可用的模板动作。你可以先在本页安装动作插件，再回来浏览动作库。
    </div>
    <div v-else class="grid gap-4 xl:grid-cols-2">
      <article
        v-for="template in pluginTemplates"
        :key="template.template_id"
        class="rounded-[24px] border border-slate-200 bg-[linear-gradient(180deg,_rgba(255,255,255,0.96),_rgba(246,250,255,0.96))] p-5 shadow-sm"
      >
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p class="text-lg font-semibold text-slate-900">
              {{ template.name }}
            </p>
            <p class="mt-1 text-sm text-slate-500">
              来自 {{ pluginsById.get(template.plugin_id)?.name || template.plugin_id }}
            </p>
          </div>
          <div class="flex flex-wrap gap-2 text-xs">
            <span class="rounded-full bg-blue-100 px-2.5 py-1 text-blue-700">
              {{ template.layer.toUpperCase() }}
            </span>
            <span class="rounded-full bg-slate-100 px-2.5 py-1 text-slate-700">
              {{ template.response_template.status_code }}
            </span>
            <span
              class="rounded-full px-2.5 py-1"
              :class="performanceClass('中')"
            >
              gzip {{ template.response_template.gzip ? '开' : '关' }}
            </span>
          </div>
        </div>

        <p class="mt-4 text-sm leading-6 text-slate-600">
          {{ template.description || '这是一个可直接套用的响应动作模板。' }}
        </p>

        <div class="mt-4 grid gap-3 md:grid-cols-2">
          <div class="rounded-2xl bg-white px-4 py-3">
            <p class="text-xs uppercase tracking-[0.14em] text-slate-400">
              内容类型
            </p>
            <p class="mt-2 text-sm font-medium text-slate-800">
              {{ template.response_template.content_type }}
            </p>
          </div>
          <div class="rounded-2xl bg-white px-4 py-3">
            <p class="text-xs uppercase tracking-[0.14em] text-slate-400">
              预设匹配
            </p>
            <p class="mt-2 font-mono text-xs text-slate-700">
              {{ template.pattern }}
            </p>
          </div>
        </div>

        <div class="mt-4 rounded-2xl border border-slate-200 bg-white px-4 py-3">
          <p class="text-xs uppercase tracking-[0.14em] text-slate-400">
            响应预览
          </p>
          <p class="mt-2 line-clamp-2 text-sm text-slate-700">
            {{ previewResponse(template) }}
          </p>
        </div>

        <div class="mt-4 flex flex-wrap gap-3">
          <RouterLink
            :to="`/admin/rules?template=${encodeURIComponent(template.template_id)}`"
            class="inline-flex items-center gap-2 rounded-full bg-stone-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-stone-800"
          >
            去规则中心绑定
          </RouterLink>
          <RouterLink
            to="/admin/rules"
            class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-slate-700 transition hover:border-blue-500/40 hover:text-blue-700"
          >
            查看规则中心
          </RouterLink>
          <button
            class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-slate-700 transition hover:border-blue-500/40 hover:text-blue-700"
            @click="emit('previewTemplate', template)"
          >
            预览响应
          </button>
        </div>
      </article>
    </div>
  </CyberCard>
</template>
