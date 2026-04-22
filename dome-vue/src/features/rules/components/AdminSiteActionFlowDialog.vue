<script setup lang="ts">
import { X } from 'lucide-vue-next'
import AdminSiteActionFlowControls from '@/features/rules/components/AdminSiteActionFlowControls.vue'
import AdminSiteActionFlowOverview from '@/features/rules/components/AdminSiteActionFlowOverview.vue'
import { useAdminSiteActionFlow } from '@/features/rules/composables/useAdminSiteActionFlow'
import type {
  L7ConfigPayload,
  LocalSiteItem,
  RuleActionTemplateItem,
  SafeLineInterceptConfigPayload,
} from '@/shared/types'

const props = defineProps<{
  open: boolean
  site: LocalSiteItem | null
  l7Config: L7ConfigPayload | null
  templates: RuleActionTemplateItem[]
  pendingTemplate?: RuleActionTemplateItem | null
  saving?: boolean
}>()

const emit = defineEmits<{
  close: []
  save: [payload: SafeLineInterceptConfigPayload | null]
}>()

const {
  activeNode,
  canSave,
  currentSummary,
  flowDraft,
  pendingPayload,
  pendingSummary,
  previewBody,
  previewError,
  previewLoading,
  previewMeta,
  responseCards,
  selectResponseMode,
  selectTemplate,
  setActiveNode,
  toggleBlockIp,
} = useAdminSiteActionFlow(props)
</script>

<template>
  <div
    v-if="open && site"
    class="fixed inset-0 z-[100] flex items-center justify-center p-4 md:p-6"
  >
    <div
      class="absolute inset-0 bg-stone-950/45 backdrop-blur-sm"
      @click="emit('close')"
    ></div>

    <div
      class="relative max-h-[calc(100vh-2rem)] w-full max-w-6xl overflow-y-auto rounded-[32px] border border-[#d7e6f8] bg-[linear-gradient(135deg,#fffaf4_0%,#f5fbff_48%,#f8f5ff_100%)] p-5 shadow-[0_30px_120px_rgba(15,23,42,0.28)] md:max-h-[calc(100vh-3rem)] md:p-6"
    >
      <div class="flex items-start justify-between gap-4">
        <div>
          <p class="text-sm tracking-[0.24em] text-sky-700">站点动作流程编排</p>
          <h3 class="mt-2 text-3xl font-semibold text-slate-900">
            {{ site.name }}
          </h3>
          <p class="mt-2 text-sm text-slate-600">
            以
            <span class="font-mono text-slate-900">{{ site.primary_hostname }}</span>
            为对象，把雷池拦截后的接管路径直接编排成一张流程图。
          </p>
        </div>
        <button
          class="flex h-11 w-11 items-center justify-center rounded-full border border-white/80 bg-white/80 text-slate-600 transition hover:border-sky-300 hover:text-sky-700"
          @click="emit('close')"
        >
          <X :size="18" />
        </button>
      </div>

      <div class="mt-6 grid gap-5 xl:grid-cols-[1.35fr_0.95fr]">
        <AdminSiteActionFlowOverview
          :active-node="activeNode"
          :current-summary="currentSummary"
          :pending-summary="pendingSummary"
          :site="site"
          @update:active-node="setActiveNode"
        />

        <AdminSiteActionFlowControls
          :active-node="activeNode"
          :block-ip="flowDraft.blockIp"
          :can-save="canSave"
          :pending-summary="pendingSummary"
          :preview-body="previewBody"
          :preview-error="previewError"
          :preview-loading="previewLoading"
          :preview-meta="previewMeta"
          :response-cards="responseCards"
          :response-mode="flowDraft.responseMode"
          :saving="saving"
          :selected-template-id="flowDraft.templateId"
          :templates="templates"
          @close="emit('close')"
          @save="emit('save', pendingPayload)"
          @select-response-mode="selectResponseMode"
          @select-template="selectTemplate"
          @toggle-block-ip="toggleBlockIp"
        />
      </div>
    </div>
  </div>
</template>
