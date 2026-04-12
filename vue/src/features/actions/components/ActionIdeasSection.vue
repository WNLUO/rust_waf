<script setup lang="ts">
import type { ActionIdeaCard } from '@/features/actions/utils/actionIdeaPreview'

defineProps<{
  downloadingIdeaId: string
  funIdeaCards: ActionIdeaCard[]
}>()

const emit = defineEmits<{
  downloadIdea: [ideaId: string]
  previewIdea: [ideaId: string]
}>()
</script>

<template>
  <section class="rounded-[28px] border border-slate-200 bg-white p-5 shadow-sm">
    <div class="mb-4">
      <p class="text-lg font-semibold text-slate-900">动作方案</p>
      <p class="mt-1 text-sm text-slate-500">
        围绕品牌呈现、通知提示、调试验证和对抗策略整理的可复用方案。能直接复用现有模板时，会优先给出最快路径。
      </p>
    </div>
    <div class="grid gap-3 [grid-template-columns:repeat(auto-fit,minmax(220px,1fr))] 2xl:[grid-template-columns:repeat(5,minmax(0,1fr))]">
      <article
        v-for="idea in funIdeaCards"
        :key="idea.id"
        class="relative flex min-h-[238px] h-full flex-col overflow-hidden rounded-[20px] border border-slate-200 bg-[linear-gradient(140deg,_rgba(255,250,245,0.96),_rgba(245,250,255,0.96))] p-4 shadow-sm"
      >
        <div class="relative flex h-full flex-col">
          <div class="flex items-start justify-between gap-4">
            <h3 class="text-[17px] font-semibold leading-6 text-slate-900">
              {{ idea.title }}
            </h3>
            <span
              class="ml-auto shrink-0 rounded-full bg-stone-900 px-2.5 py-1 text-[11px] text-white"
            >
              {{ idea.mood }}
            </span>
          </div>

          <div v-if="idea.template" class="mt-2 flex flex-wrap gap-1.5 text-[11px]">
            <span class="rounded-full bg-blue-100 px-2.5 py-1 text-blue-700">
              可直接复用模板
            </span>
            <span
              v-if="idea.requires_upload"
              class="rounded-full bg-slate-100 px-2.5 py-1 text-slate-700"
            >
              需上传 gzip
            </span>
            <span
              v-if="idea.has_overrides"
              class="rounded-full bg-amber-100 px-2.5 py-1 text-amber-700"
            >
              已自定义
            </span>
          </div>

          <div class="mt-3 flex-1 rounded-2xl border border-white/80 bg-white/85 px-3 py-3">
            <p class="text-[11px] uppercase tracking-[0.14em] text-slate-400">
              实现方式
            </p>
            <p class="mt-2 text-sm leading-6 text-slate-700">
              {{ idea.mechanism }}
            </p>
            <div
              v-if="idea.template"
              class="mt-3 flex items-center gap-2 rounded-xl bg-blue-50 px-2.5 py-2"
            >
              <span class="text-[11px] uppercase tracking-[0.12em] text-blue-500">
                推荐模板
              </span>
              <span class="truncate text-xs font-medium text-blue-800">
                {{ idea.template.name }}
              </span>
            </div>
          </div>

          <div class="mt-3 grid grid-cols-2 gap-2">
            <button
              class="inline-flex items-center justify-center gap-2 rounded-full bg-stone-900 px-3 py-2 text-xs font-medium text-white transition hover:bg-stone-800"
              @click="emit('previewIdea', idea.id)"
            >
              预览动作
            </button>
            <button
              class="inline-flex items-center justify-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-2 text-xs text-slate-700 transition hover:border-blue-500/40 hover:text-blue-700"
              :disabled="idea.requires_upload"
              @click="emit('downloadIdea', idea.id)"
            >
              {{
                idea.requires_upload
                  ? '需在弹窗上传'
                  : downloadingIdeaId === idea.id
                    ? '打包中...'
                    : '下载插件样例'
              }}
            </button>
          </div>
        </div>
      </article>
    </div>
  </section>
</template>
