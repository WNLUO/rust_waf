<script setup lang="ts">
import { ref } from 'vue'
import { Check, Copy, PencilLine, RefreshCw, X } from 'lucide-vue-next'
import AppLayout from '@/app/layout/AppLayout.vue'
import ActionIdeasSection from '@/features/actions/components/ActionIdeasSection.vue'
import ActionTemplatesSection from '@/features/actions/components/ActionTemplatesSection.vue'
import { useAdminActions } from '@/features/actions/composables/useAdminActions'
import AdminRulesPluginSection from '@/features/rules/components/AdminRulesPluginSection.vue'
import { useFlashMessages } from '@/shared/composables/useNotifications'

const actionIdeaFileInput = ref<HTMLInputElement | null>(null)

const {
  closePagePreview,
  closePreview,
  copyToClipboard,
  currentPreviewIdea,
  defaultRandomStatuses,
  deletePlugin,
  downloadingIdeaId,
  downloadGeneratedPlugin,
  editingPreviewTitle,
  error,
  funIdeaCards,
  installPlugin,
  installedPlugins,
  installingPlugin,
  isFakeSqlIdea,
  isFakeXssIdea,
  isInlineJsIdea,
  isRandomErrorIdea,
  isRedirectIdea,
  isTarpitIdea,
  loadActionCenter,
  loading,
  openGeneratedPreview,
  openPagePreview,
  openTemplatePreview,
  pagePreviewOpen,
  performanceClass,
  pluginsById,
  pluginTemplates,
  previewCanPagePreview,
  previewDirty,
  previewDraftContent,
  previewDraftContentType,
  previewDraftRandomFailureBody,
  previewDraftRandomStatuses,
  previewDraftRandomSuccessBody,
  previewDraftRandomSuccessRate,
  previewDraftSqlError,
  previewDraftSqlResult,
  previewDraftStatusCode,
  previewDraftTarpitBody,
  previewDraftTarpitBytesPerChunk,
  previewDraftTarpitIntervalMs,
  previewDraftTitle,
  previewDraftXssPayload,
  previewIsActionIdea,
  previewLoading,
  previewOpen,
  previewPayload,
  previewRandomErrorSummary,
  previewRenderedBody,
  previewResponse,
  previewSourceLabel,
  previewTitle,
  refreshing,
  saveActionIdeaPreview,
  savingIdea,
  templateCount,
  togglePluginStatus,
  uploadingIdeaAsset,
  uploadingIdeaId,
  uploadIdeaAsset,
} = useAdminActions()

useFlashMessages({
  error,
  errorTitle: '动作中心',
  errorDuration: 5600,
})

function openIdeaPreviewById(ideaId: string) {
  const idea = funIdeaCards.value.find((item) => item.id === ideaId)
  if (idea) {
    openGeneratedPreview(idea)
  }
}

function triggerIdeaAssetPicker() {
  if (!currentPreviewIdea.value?.requires_upload || uploadingIdeaAsset.value) return
  actionIdeaFileInput.value?.click()
}

function handleIdeaAssetPicked(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0] ?? null
  input.value = ''
  if (file) {
    uploadIdeaAsset(file)
  }
}
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
        :disabled="refreshing"
        @click="loadActionCenter"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': refreshing }" />
        刷新动作库
      </button>
    </template>

    <div class="space-y-6">
      <AdminRulesPluginSection
        :installed-plugins="installedPlugins"
        @delete-plugin="deletePlugin"
        @toggle-plugin="togglePluginStatus"
      />

      <ActionTemplatesSection
        :installing-plugin="installingPlugin"
        :loading="loading"
        :performance-class="performanceClass"
        :plugins-by-id="pluginsById"
        :plugin-templates="pluginTemplates"
        :preview-response="previewResponse"
        :template-count="templateCount"
        @install-plugin="installPlugin"
        @preview-template="openTemplatePreview"
      />

      <ActionIdeasSection
        :downloading-idea-id="downloadingIdeaId"
        :fun-idea-cards="funIdeaCards"
        @download-idea="downloadGeneratedPlugin"
        @preview-idea="openIdeaPreviewById"
      />
    </div>

    <div
      v-if="previewOpen"
      class="fixed inset-0 z-[100] overflow-y-auto px-4 py-6 md:py-8"
    >
      <div
        class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm"
        @click="closePreview"
      ></div>
      <div
        class="relative mx-auto flex min-h-[calc(100vh-3rem)] w-full max-w-5xl flex-col rounded-xl border border-white/85 bg-[linear-gradient(160deg,rgba(255,250,244,0.98),rgba(244,239,231,0.98))] p-4 shadow-[0_24px_80px_rgba(60,40,20,0.24)] md:min-h-[calc(100vh-4rem)] md:max-h-[calc(100vh-4rem)] md:p-5"
      >
        <div class="flex items-start justify-between gap-4">
          <div>
            <p class="text-sm tracking-wide text-blue-700">{{ previewSourceLabel }}</p>
            <div class="mt-2 flex items-center gap-3">
              <template v-if="previewIsActionIdea && editingPreviewTitle">
                <input
                  v-model="previewDraftTitle"
                  type="text"
                  class="w-full max-w-md rounded-xl border border-slate-200 bg-white px-3 py-2 text-xl font-semibold text-stone-900 outline-none transition focus:border-blue-500/50"
                />
                <button
                  class="inline-flex h-10 w-10 items-center justify-center rounded-full border border-slate-200 bg-white text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
                  :disabled="savingIdea"
                  @click="saveActionIdeaPreview"
                >
                  <Check :size="18" />
                </button>
              </template>
              <template v-else>
                <h3 class="text-2xl font-semibold text-stone-900">
                  {{ previewIsActionIdea ? previewDraftTitle || previewTitle : previewTitle }}
                </h3>
                <button
                  v-if="previewIsActionIdea"
                  class="inline-flex h-10 w-10 items-center justify-center rounded-full border border-slate-200 bg-white/75 transition hover:border-blue-500/40 hover:text-blue-700"
                  @click="editingPreviewTitle = true"
                >
                  <PencilLine :size="16" />
                </button>
              </template>
            </div>
          </div>
          <button
            class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-slate-200 bg-white/75 transition hover:border-blue-500/40 hover:text-blue-700"
            @click="closePreview"
          >
            <X :size="18" />
          </button>
        </div>

        <div v-if="previewLoading" class="flex flex-1 items-center justify-center">
          <RefreshCw class="animate-spin text-blue-700" :size="24" />
        </div>

        <template v-else-if="previewPayload">
          <div class="mt-4 flex min-h-0 flex-1 flex-col overflow-hidden">
            <div
              class="grid gap-3"
              :class="previewIsActionIdea ? 'md:grid-cols-2' : 'md:grid-cols-4'"
            >
              <div class="rounded-xl border border-slate-200 bg-white/80 px-4 py-3">
                <p class="text-xs tracking-wide text-slate-500">状态码</p>
                <template v-if="previewIsActionIdea">
                  <input
                    v-model.number="previewDraftStatusCode"
                    type="number"
                    min="100"
                    max="599"
                    class="mt-2 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-lg font-semibold text-stone-900 outline-none transition focus:border-blue-500/50"
                  />
                </template>
                <p v-else class="mt-2 text-lg font-semibold text-stone-900">
                  {{ previewPayload.status_code }}
                </p>
              </div>
              <div class="rounded-xl border border-slate-200 bg-white/80 px-4 py-3">
                <p class="text-xs tracking-wide text-slate-500">内容类型</p>
                <template v-if="previewIsActionIdea">
                  <input
                    v-model="previewDraftContentType"
                    type="text"
                    class="mt-2 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-stone-900 outline-none transition focus:border-blue-500/50"
                  />
                </template>
                <p v-else class="mt-2 text-sm font-medium text-stone-900">
                  {{ previewPayload.content_type }}
                </p>
              </div>
              <div
                v-if="!previewIsActionIdea"
                class="rounded-xl border border-slate-200 bg-white/80 px-4 py-3"
              >
                <p class="text-xs tracking-wide text-slate-500">Body 来源</p>
                <p class="mt-2 text-sm font-medium text-stone-900">
                  {{ previewPayload.body_source }}
                </p>
              </div>
              <div
                v-if="!previewIsActionIdea"
                class="rounded-xl border border-slate-200 bg-white/80 px-4 py-3"
              >
                <p class="text-xs tracking-wide text-slate-500">gzip</p>
                <p class="mt-2 text-sm font-medium text-stone-900">
                  {{ previewPayload.gzip ? '开启' : '关闭' }}
                </p>
              </div>
            </div>

            <div class="mt-4 min-h-0 flex-1 overflow-y-auto pr-1">
              <div
                v-if="previewIsActionIdea && currentPreviewIdea?.requires_upload"
                class="rounded-xl border border-slate-200 bg-white/80 p-5"
              >
                <div class="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p class="text-xs tracking-wide text-slate-500">Gzip 文件</p>
                    <p class="mt-2 text-sm text-stone-800">
                      {{
                        currentPreviewIdea.uploaded_file_name ||
                        '还没有上传 gzip 文件'
                      }}
                    </p>
                  </div>
                  <button
                    class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700 disabled:opacity-60"
                    :disabled="uploadingIdeaAsset"
                    @click="triggerIdeaAssetPicker"
                  >
                    <RefreshCw
                      v-if="uploadingIdeaAsset && uploadingIdeaId === currentPreviewIdea.id"
                      :size="14"
                      class="animate-spin"
                    />
                    {{
                      uploadingIdeaAsset && uploadingIdeaId === currentPreviewIdea.id
                        ? '上传中...'
                        : currentPreviewIdea.uploaded_file_ready
                          ? '重新上传 Gzip'
                          : '上传 Gzip 文件'
                    }}
                  </button>
                  <input
                    ref="actionIdeaFileInput"
                    type="file"
                    accept=".gz,application/gzip,application/x-gzip"
                    class="hidden"
                    @change="handleIdeaAssetPicked"
                  />
                </div>
                <p class="mt-3 text-xs leading-6 text-slate-500">
                  这里上传的是已经压缩好的 `.gz` 文件。系统会把它保存在本地数据目录里，更新代码时不会覆盖。
                </p>
              </div>

              <div class="mt-4 rounded-xl border border-slate-200 bg-white/80 p-5">
                <div class="flex items-center justify-between gap-4">
                  <p class="text-xs tracking-wide text-slate-500">
                    {{
                      previewIsActionIdea && currentPreviewIdea?.requires_upload
                        ? '文件说明'
                        : '原始内容'
                    }}
                  </p>
                  <span
                    v-if="previewPayload.truncated"
                    class="rounded-full bg-amber-100 px-2.5 py-1 text-[11px] text-amber-700"
                  >
                    已截断
                  </span>
                </div>
                <div
                  v-if="previewIsActionIdea && !currentPreviewIdea?.requires_upload"
                  class="mt-3 space-y-3"
                >
                  <p
                    v-if="currentPreviewIdea && isInlineJsIdea(currentPreviewIdea)"
                    class="text-xs leading-6 text-slate-500"
                  >
                    这里填写的是纯 JavaScript 代码。系统会自动把它内嵌进一个正常 HTML 页面后再返回。
                  </p>
                  <p
                    v-else-if="currentPreviewIdea && isRedirectIdea(currentPreviewIdea)"
                    class="text-xs leading-6 text-slate-500"
                  >
                    这里填写的是跳转目标 URL。系统会自动写入 `Location` 头，并返回一个 302 响应。
                  </p>
                  <p
                    v-else-if="currentPreviewIdea && isFakeSqlIdea(currentPreviewIdea)"
                    class="text-xs leading-6 text-slate-500"
                  >
                    这里分别配置伪造的 SQL 错误文案和查询结果，让攻击者误以为注入已经成功。
                  </p>
                  <p
                    v-else-if="currentPreviewIdea && isFakeXssIdea(currentPreviewIdea)"
                    class="text-xs leading-6 text-slate-500"
                  >
                    这里填写一个要被“假装反射”的 payload。系统会把它放进伪造的回显页面里。
                  </p>
                  <p
                    v-else-if="currentPreviewIdea && isTarpitIdea(currentPreviewIdea)"
                    class="text-xs leading-6 text-slate-500"
                  >
                    这里配置慢速返回的节奏和拖延文案。保存后会按设定的字节数与间隔缓慢响应。
                  </p>
                  <p
                    v-else-if="currentPreviewIdea && isRandomErrorIdea(currentPreviewIdea)"
                    class="text-xs leading-6 text-slate-500"
                  >
                    这里配置失败状态码、成功概率和两套文案。运行时会随机决定这次请求是成功还是失败。
                  </p>
                  <div
                    v-if="currentPreviewIdea && isRedirectIdea(currentPreviewIdea)"
                    class="rounded-2xl border border-slate-200 bg-[linear-gradient(140deg,_rgba(248,250,252,0.96),_rgba(239,246,255,0.96))] p-4"
                  >
                    <label class="block text-xs tracking-wide text-slate-500">
                      跳转链接
                    </label>
                    <div
                      class="mt-3 flex items-center gap-3 rounded-2xl border border-blue-200 bg-white px-4 py-3 shadow-[0_10px_30px_rgba(37,99,235,0.08)]"
                    >
                      <span
                        class="shrink-0 rounded-full bg-blue-50 px-2.5 py-1 text-[11px] font-medium uppercase tracking-[0.14em] text-blue-700"
                      >
                        URL
                      </span>
                      <input
                        v-model="previewDraftContent"
                        type="url"
                        placeholder="https://www.war.gov/"
                        class="w-full bg-transparent text-sm text-stone-900 outline-none placeholder:text-slate-400"
                        spellcheck="false"
                        autocomplete="off"
                      />
                    </div>
                  </div>
                  <div
                    v-else-if="currentPreviewIdea && isFakeSqlIdea(currentPreviewIdea)"
                    class="grid gap-4 rounded-2xl border border-slate-200 bg-[linear-gradient(140deg,_rgba(255,250,245,0.96),_rgba(248,250,252,0.96))] p-4"
                  >
                    <div>
                      <label class="block text-xs tracking-wide text-slate-500">
                        错误文案
                      </label>
                      <textarea
                        v-model="previewDraftSqlError"
                        class="mt-3 min-h-32 w-full rounded-2xl border border-rose-200 bg-white px-4 py-3 font-mono text-sm leading-6 text-stone-800 outline-none transition focus:border-rose-400/70"
                      ></textarea>
                    </div>
                    <div>
                      <label class="block text-xs tracking-wide text-slate-500">
                        伪结果
                      </label>
                      <input
                        v-model="previewDraftSqlResult"
                        type="text"
                        class="mt-3 w-full rounded-2xl border border-sky-200 bg-white px-4 py-3 font-mono text-sm text-stone-900 outline-none transition focus:border-sky-400/70"
                      />
                    </div>
                  </div>
                  <div
                    v-else-if="currentPreviewIdea && isFakeXssIdea(currentPreviewIdea)"
                    class="rounded-2xl border border-slate-200 bg-[linear-gradient(140deg,_rgba(248,250,252,0.96),_rgba(255,245,245,0.96))] p-4"
                  >
                    <label class="block text-xs tracking-wide text-slate-500">
                      回显 payload
                    </label>
                    <div
                      class="mt-3 rounded-2xl border border-amber-200 bg-white px-4 py-3 shadow-[0_10px_30px_rgba(245,158,11,0.08)]"
                    >
                      <input
                        v-model="previewDraftXssPayload"
                        type="text"
                        class="w-full bg-transparent font-mono text-sm text-stone-900 outline-none placeholder:text-slate-400"
                        spellcheck="false"
                        autocomplete="off"
                      />
                    </div>
                  </div>
                  <div
                    v-else-if="currentPreviewIdea && isTarpitIdea(currentPreviewIdea)"
                    class="grid gap-4 rounded-2xl border border-slate-200 bg-[linear-gradient(140deg,_rgba(240,253,244,0.96),_rgba(248,250,252,0.96))] p-4"
                  >
                    <div class="grid gap-4 md:grid-cols-2">
                      <div>
                        <label class="block text-xs tracking-wide text-slate-500">
                          每次发送字节数
                        </label>
                        <input
                          v-model.number="previewDraftTarpitBytesPerChunk"
                          type="number"
                          min="1"
                          class="mt-3 w-full rounded-2xl border border-emerald-200 bg-white px-4 py-3 text-sm text-stone-900 outline-none transition focus:border-emerald-400/70"
                        />
                      </div>
                      <div>
                        <label class="block text-xs tracking-wide text-slate-500">
                          每次间隔毫秒
                        </label>
                        <input
                          v-model.number="previewDraftTarpitIntervalMs"
                          type="number"
                          min="1"
                          step="100"
                          class="mt-3 w-full rounded-2xl border border-emerald-200 bg-white px-4 py-3 text-sm text-stone-900 outline-none transition focus:border-emerald-400/70"
                        />
                      </div>
                    </div>
                    <div>
                      <label class="block text-xs tracking-wide text-slate-500">
                        拖延文案
                      </label>
                      <textarea
                        v-model="previewDraftTarpitBody"
                        class="mt-3 min-h-28 w-full rounded-2xl border border-emerald-200 bg-white px-4 py-3 font-mono text-sm leading-6 text-stone-800 outline-none transition focus:border-emerald-400/70"
                      ></textarea>
                    </div>
                  </div>
                  <div
                    v-else-if="currentPreviewIdea && isRandomErrorIdea(currentPreviewIdea)"
                    class="grid gap-4 rounded-2xl border border-slate-200 bg-[linear-gradient(140deg,_rgba(255,247,237,0.96),_rgba(248,250,252,0.96))] p-4"
                  >
                    <div class="grid gap-4 md:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
                      <div>
                        <label class="block text-xs tracking-wide text-slate-500">
                          失败状态码列表
                        </label>
                        <input
                          v-model="previewDraftRandomStatuses"
                          type="text"
                          class="mt-3 w-full rounded-2xl border border-amber-200 bg-white px-4 py-3 font-mono text-sm text-stone-900 outline-none transition focus:border-amber-400/70"
                        />
                      </div>
                      <div>
                        <label class="block text-xs tracking-wide text-slate-500">
                          成功概率（%）
                        </label>
                        <input
                          v-model.number="previewDraftRandomSuccessRate"
                          type="number"
                          min="0"
                          max="100"
                          class="mt-3 w-full rounded-2xl border border-amber-200 bg-white px-4 py-3 text-sm text-stone-900 outline-none transition focus:border-amber-400/70"
                        />
                      </div>
                    </div>
                    <div>
                      <label class="block text-xs tracking-wide text-slate-500">
                        成功文案
                      </label>
                      <textarea
                        v-model="previewDraftRandomSuccessBody"
                        class="mt-3 min-h-24 w-full rounded-2xl border border-emerald-200 bg-white px-4 py-3 font-mono text-sm leading-6 text-stone-800 outline-none transition focus:border-emerald-400/70"
                      ></textarea>
                    </div>
                    <div>
                      <label class="block text-xs tracking-wide text-slate-500">
                        失败文案
                      </label>
                      <textarea
                        v-model="previewDraftRandomFailureBody"
                        class="mt-3 min-h-28 w-full rounded-2xl border border-rose-200 bg-white px-4 py-3 font-mono text-sm leading-6 text-stone-800 outline-none transition focus:border-rose-400/70"
                      ></textarea>
                    </div>
                  </div>
                  <textarea
                    v-else
                    v-model="previewDraftContent"
                    class="min-h-[min(42vh,28rem)] w-full rounded-xl border border-slate-200 bg-white px-3 py-3 font-mono text-sm leading-6 text-stone-800 outline-none transition focus:border-blue-500/50"
                  ></textarea>
                </div>
                <div
                  v-else-if="previewIsActionIdea && currentPreviewIdea?.requires_upload"
                  class="mt-3 rounded-xl border border-dashed border-slate-200 bg-slate-50 px-4 py-4 text-sm leading-6 text-slate-600"
                >
                  这个动作不会编辑文本内容，而是直接返回你上传的 gzip 文件。
                </div>
                <div
                  v-else-if="previewIsActionIdea && currentPreviewIdea && isRandomErrorIdea(currentPreviewIdea)"
                  class="mt-3 grid gap-4"
                >
                  <div class="grid gap-3 md:grid-cols-3">
                    <div class="rounded-2xl border border-amber-200 bg-amber-50/80 px-4 py-4">
                      <p class="text-xs tracking-wide text-amber-700">可能失败状态</p>
                      <p class="mt-2 font-mono text-lg font-semibold text-stone-900">
                        {{ previewRandomErrorSummary.statuses.join(', ') || defaultRandomStatuses }}
                      </p>
                    </div>
                    <div class="rounded-2xl border border-emerald-200 bg-emerald-50/80 px-4 py-4">
                      <p class="text-xs tracking-wide text-emerald-700">成功概率</p>
                      <p class="mt-2 text-lg font-semibold text-stone-900">
                        {{ previewRandomErrorSummary.successRate }}%
                      </p>
                    </div>
                    <div class="rounded-2xl border border-slate-200 bg-slate-50/80 px-4 py-4">
                      <p class="text-xs tracking-wide text-slate-500">运行效果</p>
                      <p class="mt-2 text-sm leading-6 text-stone-700">
                        同一路径会呈现时好时坏的故障感，干扰攻击者判断。
                      </p>
                    </div>
                  </div>
                  <div class="grid gap-4 md:grid-cols-2">
                    <div class="rounded-2xl border border-rose-200 bg-white px-5 py-4 shadow-sm">
                      <div class="flex items-center justify-between gap-3">
                        <p class="text-sm font-medium text-stone-900">失败响应示意</p>
                        <span class="rounded-full bg-rose-100 px-2.5 py-1 text-xs font-medium text-rose-700">
                          {{ previewRandomErrorSummary.statuses[0] ?? 500 }}
                        </span>
                      </div>
                      <pre class="mt-4 whitespace-pre-wrap break-all font-mono text-sm leading-6 text-stone-800">{{ previewRandomErrorSummary.failureBody }}</pre>
                    </div>
                    <div class="rounded-2xl border border-emerald-200 bg-white px-5 py-4 shadow-sm">
                      <div class="flex items-center justify-between gap-3">
                        <p class="text-sm font-medium text-stone-900">成功响应示意</p>
                        <span class="rounded-full bg-emerald-100 px-2.5 py-1 text-xs font-medium text-emerald-700">
                          200
                        </span>
                      </div>
                      <pre class="mt-4 whitespace-pre-wrap break-all font-mono text-sm leading-6 text-stone-800">{{ previewRandomErrorSummary.successBody }}</pre>
                    </div>
                  </div>
                </div>
                <pre
                  v-else
                  class="mt-3 max-h-[min(48vh,32rem)] overflow-auto whitespace-pre-wrap break-all font-mono text-sm leading-7 text-stone-800"
                >{{ previewRenderedBody }}</pre>
              </div>
            </div>

            <div class="mt-4 flex flex-wrap gap-3">
              <button
                v-if="!currentPreviewIdea?.requires_upload"
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/80 px-4 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                @click="copyToClipboard(previewRenderedBody)"
              >
                <Copy :size="14" />
                复制内容
              </button>
              <button
                v-if="previewIsActionIdea"
                class="inline-flex items-center gap-2 rounded-full bg-stone-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-stone-800 disabled:opacity-60"
                :disabled="savingIdea || !previewDirty"
                @click="saveActionIdeaPreview"
              >
                <RefreshCw v-if="savingIdea" :size="14" class="animate-spin" />
                {{ savingIdea ? '保存中...' : '保存修改' }}
              </button>
              <button
                v-if="previewCanPagePreview"
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/80 px-4 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                @click="openPagePreview"
              >
                页面预览
              </button>
              <button
                class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/70 px-4 py-2 text-sm text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                @click="closePreview"
              >
                关闭
              </button>
            </div>
          </div>
        </template>
      </div>
    </div>

    <div
      v-if="pagePreviewOpen"
      class="fixed inset-0 z-[110] overflow-y-auto px-4 py-6 md:py-8"
    >
      <div
        class="absolute inset-0 bg-stone-950/45 backdrop-blur-sm"
        @click="closePagePreview"
      ></div>
      <div
        class="relative mx-auto flex min-h-[calc(100vh-3rem)] w-full max-w-6xl flex-col rounded-xl border border-white/85 bg-white p-4 shadow-[0_24px_80px_rgba(60,40,20,0.24)] md:min-h-[calc(100vh-4rem)] md:max-h-[calc(100vh-4rem)] md:p-5"
      >
        <div class="flex items-start justify-between gap-4">
          <div>
            <p class="text-sm tracking-wide text-blue-700">页面预览</p>
            <h3 class="mt-2 text-2xl font-semibold text-stone-900">
              {{ previewIsActionIdea ? previewDraftTitle || previewTitle : previewTitle }}
            </h3>
          </div>
          <button
            class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-slate-200 bg-white/75 transition hover:border-blue-500/40 hover:text-blue-700"
            @click="closePagePreview"
          >
            <X :size="18" />
          </button>
        </div>

        <div class="mt-4 min-h-0 flex-1 overflow-hidden rounded-xl border border-slate-200 bg-white">
          <iframe
            class="h-full min-h-[70vh] w-full bg-white"
            :srcdoc="previewRenderedBody"
          ></iframe>
        </div>
      </div>
    </div>
  </AppLayout>
</template>
