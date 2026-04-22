<script setup lang="ts">
import { Save, X } from 'lucide-vue-next'
import type { RuleActionTemplateItem, RuleDraft } from '@/shared/types'

const props = defineProps<{
  isPluginActionValue: (value: string) => boolean
  open: boolean
  pluginTemplates: RuleActionTemplateItem[]
  ruleForm: RuleDraft
  saving: boolean
  selectedPluginTemplate?: RuleActionTemplateItem
  toPluginActionValue: (templateId: string) => string
}>()

const emit = defineEmits<{
  addHeader: []
  close: []
  removeHeader: [index: number]
  save: []
  'update:rule-form': [value: RuleDraft]
  actionChange: []
}>()

function patchRuleForm(current: RuleDraft, patch: Partial<RuleDraft>) {
  return { ...current, ...patch }
}

function updateRuleForm(patch: Partial<RuleDraft>) {
  emit('update:rule-form', patchRuleForm(props.ruleForm, patch))
}

function handleLayerChange(event: Event) {
  updateRuleForm({
    layer: (event.target as HTMLSelectElement).value,
  })
  emit('actionChange')
}

function handleActionChange(event: Event) {
  updateRuleForm({
    action: (event.target as HTMLSelectElement).value,
  })
  emit('actionChange')
}
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 z-[100] flex items-center justify-center p-4 md:p-6"
  >
    <div
      class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm"
      @click="$emit('close')"
    ></div>
    <div
      class="relative max-h-[calc(100vh-2rem)] w-full max-w-3xl overflow-y-auto rounded-[28px] border border-slate-200 bg-[#fffaf4] p-5 shadow-[0_24px_80px_rgba(60,40,20,0.24)] md:max-h-[calc(100vh-3rem)] md:p-6"
    >
      <div class="flex items-center justify-between">
        <div>
          <p class="text-sm tracking-wide text-blue-700">
            {{ ruleForm.id ? '编辑规则' : '新建规则' }}
          </p>
          <h3 class="mt-2 text-3xl font-semibold text-stone-900">
            {{ ruleForm.id ? '调整现有策略' : '创建新的防护策略' }}
          </h3>
        </div>
        <button
          class="flex h-10 w-10 items-center justify-center rounded-full border border-slate-200 bg-white/75 transition hover:border-blue-500/40 hover:text-blue-700"
          @click="$emit('close')"
        >
          <X :size="18" />
        </button>
      </div>

      <form class="mt-3 space-y-6" @submit.prevent="$emit('save')">
        <div class="space-y-2">
          <label class="text-sm text-slate-500">规则名称</label>
          <input
            :value="ruleForm.name"
            type="text"
            class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
            required
            @input="
              $emit(
                'update:rule-form',
                patchRuleForm(ruleForm, {
                  name: ($event.target as HTMLInputElement).value,
                }),
              )
            "
          />
        </div>

        <div class="grid gap-4 md:grid-cols-3">
          <div class="space-y-2">
            <label class="text-sm text-slate-500">层级</label>
            <select
              :value="ruleForm.layer"
              class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
              :disabled="!!ruleForm.plugin_template_id"
              @change="handleLayerChange"
            >
              <option value="l4">四层</option>
              <option value="l7">HTTP</option>
            </select>
          </div>

          <div class="space-y-2">
            <label class="text-sm text-slate-500">级别</label>
            <select
              :value="ruleForm.severity"
              class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
              :disabled="!!ruleForm.plugin_template_id"
              @change="
                $emit(
                  'update:rule-form',
                  patchRuleForm(ruleForm, {
                    severity: ($event.target as HTMLSelectElement).value,
                  }),
                )
              "
            >
              <option value="low">低</option>
              <option value="medium">中</option>
              <option value="high">高</option>
              <option value="critical">紧急</option>
            </select>
          </div>

          <div class="space-y-2">
            <label class="text-sm text-slate-500">动作</label>
            <select
              :value="ruleForm.action"
              class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
              @change="handleActionChange"
            >
              <option value="block">拦截</option>
              <option value="allow">放行</option>
              <option value="alert">告警</option>
              <option value="respond" :disabled="ruleForm.layer !== 'l7'">
                自定义响应
              </option>
              <option
                v-for="template in pluginTemplates"
                :key="template.template_id"
                :value="toPluginActionValue(template.template_id)"
              >
                插件 · {{ template.name }}
              </option>
            </select>
          </div>
        </div>

        <div class="space-y-2">
          <label class="text-sm text-slate-500">匹配内容</label>
          <textarea
            :value="ruleForm.pattern"
            rows="6"
            class="w-full rounded-xl border border-slate-200 bg-white px-4 py-3 font-mono text-sm outline-none transition focus:border-blue-500"
            required
            :disabled="!!ruleForm.plugin_template_id"
            @input="
              $emit(
                'update:rule-form',
                patchRuleForm(ruleForm, {
                  pattern: ($event.target as HTMLTextAreaElement).value,
                }),
              )
            "
          ></textarea>
        </div>

        <div
          v-if="
            ruleForm.layer === 'l7' &&
            (ruleForm.action === 'respond' || !!ruleForm.plugin_template_id)
          "
          class="space-y-4 rounded-2xl border border-blue-100 bg-blue-50/60 p-4"
        >
          <div>
            <p class="text-sm font-medium text-stone-900">命中后直接回包</p>
            <p class="text-xs text-slate-500">
              <template v-if="selectedPluginTemplate">
                当前使用插件动作 `{{
                  selectedPluginTemplate.name
                }}`，配置已由插件预设。
              </template>
              <template v-else>
                这里写原始文本内容，服务端会按需压缩并自动补齐
                `Content-Encoding`。
              </template>
            </p>
          </div>

          <div class="grid gap-4 md:grid-cols-2">
            <div class="space-y-2">
              <label class="text-sm text-slate-500">HTTP 状态码</label>
              <input
                :value="ruleForm.response_template?.status_code"
                type="number"
                min="100"
                max="599"
                class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
                :disabled="!!ruleForm.plugin_template_id"
                @input="
                  $emit(
                    'update:rule-form',
                    patchRuleForm(ruleForm, {
                      response_template: {
                        ...ruleForm.response_template!,
                        status_code: Number(
                          ($event.target as HTMLInputElement).value,
                        ),
                      },
                    }),
                  )
                "
              />
            </div>

            <div class="space-y-2">
              <label class="text-sm text-slate-500">Content-Type</label>
              <input
                :value="ruleForm.response_template?.content_type"
                type="text"
                class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
                :disabled="!!ruleForm.plugin_template_id"
                @input="
                  $emit(
                    'update:rule-form',
                    patchRuleForm(ruleForm, {
                      response_template: {
                        ...ruleForm.response_template!,
                        content_type: ($event.target as HTMLInputElement).value,
                      },
                    }),
                  )
                "
              />
            </div>
          </div>

          <div class="space-y-2">
            <label class="text-sm text-slate-500">响应体来源</label>
            <select
              :value="ruleForm.response_template?.body_source"
              class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
              @change="
                $emit(
                  'update:rule-form',
                  patchRuleForm(ruleForm, {
                    response_template: {
                      ...ruleForm.response_template!,
                      body_source: ($event.target as HTMLSelectElement).value,
                    },
                  }),
                )
              "
            >
              <option value="inline_text">直接填写文本</option>
              <option value="file">读取文件</option>
            </select>
          </div>

          <div class="space-y-2">
            <label class="text-sm text-slate-500">
              {{
                ruleForm.response_template?.body_source === 'file'
                  ? '文件路径'
                  : '响应内容'
              }}
            </label>
            <input
              v-if="ruleForm.response_template?.body_source === 'file'"
              :value="ruleForm.response_template?.body_file_path"
              type="text"
              class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 text-sm outline-none transition focus:border-blue-500"
              placeholder="例如 block-page.html 或 pages/block-page.html"
              :disabled="!!ruleForm.plugin_template_id"
              @input="
                $emit(
                  'update:rule-form',
                  patchRuleForm(ruleForm, {
                    response_template: {
                      ...ruleForm.response_template!,
                      body_file_path: ($event.target as HTMLInputElement).value,
                    },
                  }),
                )
              "
            />
            <textarea
              v-else
              :value="ruleForm.response_template?.body_text"
              rows="8"
              class="w-full rounded-xl border border-slate-200 bg-white px-4 py-3 font-mono text-sm outline-none transition focus:border-blue-500"
              placeholder="例如返回一段 HTML、JSON 或说明文本"
              :disabled="!!ruleForm.plugin_template_id"
              @input="
                $emit(
                  'update:rule-form',
                  patchRuleForm(ruleForm, {
                    response_template: {
                      ...ruleForm.response_template!,
                      body_text: ($event.target as HTMLTextAreaElement).value,
                    },
                  }),
                )
              "
            ></textarea>
          </div>

          <label
            class="flex items-center gap-3 rounded-xl border border-slate-200 bg-white/80 p-4"
          >
            <input
              :checked="Boolean(ruleForm.response_template?.gzip)"
              type="checkbox"
              class="h-4 w-4 accent-blue-600"
              :disabled="!!ruleForm.plugin_template_id"
              @change="
                $emit(
                  'update:rule-form',
                  patchRuleForm(ruleForm, {
                    response_template: {
                      ...ruleForm.response_template!,
                      gzip: ($event.target as HTMLInputElement).checked,
                    },
                  }),
                )
              "
            />
            <span class="text-sm text-stone-800">
              自动 gzip 压缩并添加 `Content-Encoding: gzip`
            </span>
          </label>

          <div class="space-y-3">
            <div class="flex items-center justify-between">
              <label class="text-sm text-slate-500">附加响应头</label>
              <button
                type="button"
                class="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                :disabled="!!ruleForm.plugin_template_id"
                @click="$emit('addHeader')"
              >
                添加响应头
              </button>
            </div>

            <div
              v-for="(header, index) in ruleForm.response_template?.headers ||
              []"
              :key="index"
              class="grid gap-3 md:grid-cols-[1fr_1fr_auto]"
            >
              <input
                :value="header.key"
                type="text"
                class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 text-sm outline-none transition focus:border-blue-500"
                placeholder="响应头名称"
                :disabled="!!ruleForm.plugin_template_id"
                @input="
                  $emit(
                    'update:rule-form',
                    patchRuleForm(ruleForm, {
                      response_template: {
                        ...ruleForm.response_template!,
                        headers: (
                          ruleForm.response_template?.headers || []
                        ).map((item, headerIndex) =>
                          headerIndex === index
                            ? {
                                ...item,
                                key: ($event.target as HTMLInputElement).value,
                              }
                            : item,
                        ),
                      },
                    }),
                  )
                "
              />
              <input
                :value="header.value"
                type="text"
                class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 text-sm outline-none transition focus:border-blue-500"
                placeholder="响应头值"
                :disabled="!!ruleForm.plugin_template_id"
                @input="
                  $emit(
                    'update:rule-form',
                    patchRuleForm(ruleForm, {
                      response_template: {
                        ...ruleForm.response_template!,
                        headers: (
                          ruleForm.response_template?.headers || []
                        ).map((item, headerIndex) =>
                          headerIndex === index
                            ? {
                                ...item,
                                value: ($event.target as HTMLInputElement)
                                  .value,
                              }
                            : item,
                        ),
                      },
                    }),
                  )
                "
              />
              <button
                type="button"
                class="rounded-full border border-red-500/20 px-3 py-2 text-xs text-red-600 transition hover:bg-red-500/8"
                :disabled="!!ruleForm.plugin_template_id"
                @click="$emit('removeHeader', index)"
              >
                删除
              </button>
            </div>
          </div>
        </div>

        <label
          class="flex items-center gap-3 rounded-xl border border-slate-200 bg-white/70 p-4"
        >
          <input
            :checked="ruleForm.enabled"
            type="checkbox"
            class="h-4 w-4 accent-blue-600"
            @change="
              $emit(
                'update:rule-form',
                patchRuleForm(ruleForm, {
                  enabled: ($event.target as HTMLInputElement).checked,
                }),
              )
            "
          />
          <span class="text-sm text-stone-800">保存后立即启用这条规则</span>
        </label>

        <button
          type="submit"
          class="inline-flex w-full items-center justify-center gap-2 rounded-full bg-blue-600 px-4 py-3 text-base font-semibold text-white shadow-sm transition hover:-translate-y-0.5 disabled:opacity-60"
          :disabled="saving"
        >
          <Save :size="18" />
          保存规则
        </button>
      </form>
    </div>
  </div>
</template>
