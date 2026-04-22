<script setup lang="ts">
import { ArrowRight, Eye } from 'lucide-vue-next'
import { RouterLink } from 'vue-router'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import type {
  FlowNode,
  ResponseMode,
  TemplatePreviewMeta,
} from '@/features/rules/composables/useAdminSiteActionFlow'
import type { RuleActionTemplateItem } from '@/shared/types'

defineProps<{
  activeNode: FlowNode
  blockIp: boolean
  canSave: boolean
  pendingSummary: string
  previewBody: string
  previewError: string
  previewLoading: boolean
  previewMeta: TemplatePreviewMeta | null
  responseCards: Array<{
    chip: string
    description: string
    id: ResponseMode
    title: string
  }>
  responseMode: ResponseMode
  saving?: boolean
  selectedTemplateId: string
  templates: RuleActionTemplateItem[]
}>()

const emit = defineEmits<{
  close: []
  save: []
  selectResponseMode: [value: ResponseMode]
  selectTemplate: [value: string]
  toggleBlockIp: []
}>()
</script>

<template>
  <section class="space-y-4">
    <div class="rounded-[28px] border border-white/80 bg-white/78 p-5 shadow-[0_18px_50px_rgba(15,23,42,0.06)]">
      <div class="flex items-center justify-between gap-3">
        <div>
          <p class="text-sm font-semibold text-slate-900">主动作配置</p>
          <p class="mt-1 text-xs leading-6 text-slate-500">
            先确定拦截后返回什么，再决定是否添加附加动作。
          </p>
        </div>
        <StatusBadge
          :text="activeNode === 'response' ? '正在编辑' : '点击流程节点切换'"
          :type="activeNode === 'response' ? 'info' : 'muted'"
        />
      </div>

      <div class="mt-4 grid gap-3">
        <button
          v-for="card in responseCards"
          :key="card.id"
          class="rounded-2xl border px-4 py-4 text-left transition"
          :class="
            responseMode === card.id
              ? 'border-indigo-400 bg-indigo-50'
              : 'border-slate-200 bg-slate-50 hover:border-indigo-300 hover:bg-white'
          "
          @click="emit('selectResponseMode', card.id)"
        >
          <div class="flex items-start justify-between gap-3">
            <div>
              <p class="font-semibold text-slate-900">{{ card.title }}</p>
              <p class="mt-1 text-sm leading-6 text-slate-600">
                {{ card.description }}
              </p>
            </div>
            <StatusBadge
              :text="card.chip"
              :type="responseMode === card.id ? 'info' : 'muted'"
              compact
            />
          </div>
        </button>
      </div>

      <div
        v-if="responseMode === 'legacy'"
        class="mt-4 rounded-2xl border border-amber-300 bg-amber-50 px-4 py-4 text-sm text-amber-900"
      >
        当前站点挂的是历史自定义动作，已经不适合继续用下拉模式维护了。建议直接迁移成“全局默认页面”或“站点模板动作”。
      </div>
    </div>

    <div
      v-if="responseMode === 'template'"
      class="rounded-[28px] border border-white/80 bg-white/78 p-5 shadow-[0_18px_50px_rgba(15,23,42,0.06)]"
    >
      <div class="flex items-center justify-between gap-3">
        <div>
          <p class="text-sm font-semibold text-slate-900">模板动作节点</p>
          <p class="mt-1 text-xs leading-6 text-slate-500">
            这里用卡片挑选模板，比单个下拉框更适合后续继续扩展。
          </p>
        </div>
        <RouterLink
          to="/admin/actions"
          class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-2 text-xs text-stone-700 transition hover:border-sky-300 hover:text-sky-700"
        >
          去动作中心
          <ArrowRight :size="14" />
        </RouterLink>
      </div>

      <div class="mt-4 grid max-h-[18rem] gap-3 overflow-y-auto pr-1">
        <button
          v-for="template in templates"
          :key="template.template_id"
          class="rounded-2xl border px-4 py-4 text-left transition"
          :class="
            selectedTemplateId === template.template_id
              ? 'border-sky-400 bg-sky-50'
              : 'border-slate-200 bg-slate-50 hover:border-sky-300 hover:bg-white'
          "
          @click="emit('selectTemplate', template.template_id)"
        >
          <div class="flex items-start justify-between gap-3">
            <div>
              <p class="font-semibold text-slate-900">{{ template.name }}</p>
              <p class="mt-1 text-sm leading-6 text-slate-600">
                {{ template.description || '动作中心模板' }}
              </p>
            </div>
            <div class="flex flex-wrap justify-end gap-2">
              <StatusBadge
                :text="`HTTP ${template.response_template.status_code}`"
                type="muted"
                compact
              />
              <StatusBadge
                :text="template.response_template.content_type"
                type="info"
                compact
              />
            </div>
          </div>
        </button>
      </div>

      <div class="mt-4 rounded-2xl border border-slate-200 bg-slate-950 p-4 text-slate-100">
        <div class="flex items-center gap-2">
          <Eye :size="16" />
          <p class="text-sm font-semibold">模板预览</p>
        </div>
        <p v-if="previewLoading" class="mt-3 text-sm text-slate-300">
          正在读取模板预览...
        </p>
        <p v-else-if="previewError" class="mt-3 text-sm text-rose-300">
          {{ previewError }}
        </p>
        <div v-else-if="previewMeta" class="mt-3">
          <div class="flex flex-wrap gap-2">
            <StatusBadge :text="`HTTP ${previewMeta.statusCode}`" type="muted" compact />
            <StatusBadge :text="previewMeta.contentType" type="info" compact />
            <StatusBadge
              :text="previewMeta.truncated ? '已截断预览' : '完整预览'"
              type="muted"
              compact
            />
          </div>
          <pre class="mt-3 max-h-56 overflow-auto whitespace-pre-wrap rounded-2xl bg-slate-900 p-4 text-xs leading-6 text-slate-200">{{ previewBody }}</pre>
        </div>
        <p v-else class="mt-3 text-sm text-slate-300">
          先选择一个模板，再查看它会返回什么内容。
        </p>
      </div>
    </div>

    <div class="rounded-[28px] border border-white/80 bg-white/78 p-5 shadow-[0_18px_50px_rgba(15,23,42,0.06)]">
      <div class="flex items-center justify-between gap-3">
        <div>
          <p class="text-sm font-semibold text-slate-900">附加动作节点</p>
          <p class="mt-1 text-xs leading-6 text-slate-500">
            这里单独承载扩展能力，后续新增节点时不需要重构主动作模型。
          </p>
        </div>
        <StatusBadge
          :text="activeNode === 'extras' ? '正在编辑' : '可独立扩展'"
          :type="activeNode === 'extras' ? 'info' : 'muted'"
        />
      </div>

      <button
        class="mt-4 w-full rounded-2xl border px-4 py-4 text-left transition"
        :class="
          blockIp
            ? 'border-rose-400 bg-rose-50'
            : 'border-slate-200 bg-slate-50 hover:border-rose-300 hover:bg-white'
        "
        @click="emit('toggleBlockIp')"
      >
        <div class="flex items-start justify-between gap-3">
          <div>
            <p class="font-semibold text-slate-900">封禁来源 IP</p>
            <p class="mt-1 text-sm leading-6 text-slate-600">
              拦截命中后，把来源 IP 一并加入封禁流程。后面如果你想加事件标签、回调通知，也可以继续按这个区域扩展。
            </p>
          </div>
          <StatusBadge
            :text="blockIp ? '已启用' : '未启用'"
            :type="blockIp ? 'warning' : 'muted'"
          />
        </div>
      </button>
    </div>

    <div class="flex flex-wrap items-center gap-3">
      <button
        :disabled="!canSave || saving"
        class="inline-flex items-center gap-2 rounded-xl bg-sky-600 px-5 py-3 text-sm font-semibold text-white transition hover:bg-sky-600/90 disabled:cursor-not-allowed disabled:opacity-60"
        @click="emit('save')"
      >
        {{ saving ? '保存中...' : '保存流程动作' }}
      </button>
      <button
        class="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-5 py-3 text-sm font-semibold text-slate-700 transition hover:border-sky-300 hover:text-sky-700"
        @click="emit('close')"
      >
        取消
      </button>
    </div>
  </section>
</template>
