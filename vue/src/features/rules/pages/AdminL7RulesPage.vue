<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import AppLayout from '@/app/layout/AppLayout.vue'
import L7SectionNav from '@/features/l7/components/L7SectionNav.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import { useFormatters } from '@/shared/composables/useFormatters'
import { useFlashMessages } from '@/shared/composables/useNotifications'
import { createRule, deleteRule, fetchRulesList, updateRule } from '@/shared/api/rules'
import type { RuleDraft, RuleItem } from '@/shared/types'
import {
  Check,
  Edit3,
  Plus,
  RefreshCw,
  Save,
  Search,
  Trash2,
  X,
} from 'lucide-vue-next'

const { actionLabel, severityLabel } = useFormatters()

const loading = ref(true)
const saving = ref(false)
const error = ref('')
const successMessage = ref('')
const isRuleModalOpen = ref(false)
const editingId = ref<string | null>(null)
const rules = ref<RuleItem[]>([])

const filters = reactive({
  search: '',
  action: 'all',
  severity: 'all',
  status: 'all',
})

const ruleForm = reactive<RuleDraft>({
  id: '',
  name: '',
  enabled: true,
  layer: 'l7',
  pattern: '',
  action: 'block',
  severity: 'high',
})

const l7Rules = computed(() =>
  rules.value.filter((rule) => rule.layer === 'l7'),
)
const filteredRules = computed(() =>
  l7Rules.value.filter((rule) => {
    if (filters.action !== 'all' && rule.action !== filters.action) return false
    if (filters.severity !== 'all' && rule.severity !== filters.severity)
      return false
    if (
      filters.status !== 'all' &&
      rule.enabled !== (filters.status === 'enabled')
    )
      return false
    if (!filters.search.trim()) return true
    const keyword = filters.search.trim().toLowerCase()
    return (
      rule.name.toLowerCase().includes(keyword) ||
      rule.id.toLowerCase().includes(keyword) ||
      rule.pattern.toLowerCase().includes(keyword)
    )
  }),
)

const enabledCount = computed(
  () => l7Rules.value.filter((rule) => rule.enabled).length,
)
const blockCount = computed(
  () => l7Rules.value.filter((rule) => rule.action === 'block').length,
)

useFlashMessages({
  error,
  success: successMessage,
  errorTitle: 'L7 规则',
  successTitle: 'L7 规则',
  errorDuration: 5600,
  successDuration: 3200,
})

const l7RuleTemplates = [
  {
    label: '拦截后台路径',
    description: '快速阻断访问敏感后台入口的请求。',
    id: 'l7-block-admin-path',
    name: '拦截后台路径访问',
    pattern: String.raw`(?:GET|POST)\s+/(?:admin|manage|console)\b`,
    action: 'block',
    severity: 'high',
  },
  {
    label: '告警异常 User-Agent',
    description: '适合先观测扫描器或脚本化工具流量。',
    id: 'l7-alert-suspicious-ua',
    name: '可疑 User-Agent 告警',
    pattern: String.raw`user-agent:\s*(?:sqlmap|curl|python-requests|go-http-client)`,
    action: 'alert',
    severity: 'medium',
  },
  {
    label: '拦截 SQL 注入特征',
    description: '对 URI 或 Body 中常见注入片段进行阻断。',
    id: 'l7-block-sqli-basic',
    name: '基础 SQL 注入阻断',
    pattern: String.raw`(?i)(union\s+select|or\s+1=1|sleep\(|benchmark\()`,
    action: 'block',
    severity: 'critical',
  },
  {
    label: '拦截伪造真实来源头',
    description: '利用统一请求串中的头部信息匹配伪造来源行为。',
    id: 'l7-block-forged-real-ip',
    name: '伪造来源头拦截',
    pattern: String.raw`(?:x-forwarded-for|x-real-ip):\s*(?:127\.0\.0\.1|10\.)`,
    action: 'block',
    severity: 'high',
  },
] as const

const resetForm = () => {
  Object.assign(ruleForm, {
    id: '',
    name: '',
    enabled: true,
    layer: 'l7',
    pattern: '',
    action: 'block',
    severity: 'high',
  })
  editingId.value = null
}

const applyTemplate = (template: (typeof l7RuleTemplates)[number]) => {
  Object.assign(ruleForm, {
    id: editingId.value ? ruleForm.id : template.id,
    name: template.name,
    enabled: true,
    layer: 'l7',
    pattern: template.pattern,
    action: template.action,
    severity: template.severity,
  })
}

const loadRules = async () => {
  loading.value = true
  try {
    const payload = await fetchRulesList()
    rules.value = payload.rules
    error.value = ''
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取 HTTP 规则失败'
  } finally {
    loading.value = false
  }
}

const openCreateRule = () => {
  resetForm()
  isRuleModalOpen.value = true
}

const openEditRule = (rule: RuleItem) => {
  Object.assign(ruleForm, { ...rule, layer: 'l7' })
  editingId.value = rule.id
  isRuleModalOpen.value = true
}

const saveRule = async () => {
  saving.value = true
  error.value = ''
  successMessage.value = ''

  try {
    const payload = {
      ...ruleForm,
      id: ruleForm.id.trim(),
      name: ruleForm.name.trim(),
      pattern: ruleForm.pattern.trim(),
      layer: 'l7',
    }

    if (!payload.id || !payload.name || !payload.pattern) {
      throw new Error('规则 ID、规则名称和匹配内容不能为空')
    }

    if (editingId.value) {
      await updateRule(payload)
      successMessage.value = `HTTP 规则 ${payload.id} 已更新。`
    } else {
      await createRule(payload)
      successMessage.value = `HTTP 规则 ${payload.id} 已创建。`
    }

    isRuleModalOpen.value = false
    await loadRules()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '保存 HTTP 规则失败'
  } finally {
    saving.value = false
  }
}

const toggleRuleStatus = async (rule: RuleItem) => {
  error.value = ''
  successMessage.value = ''
  try {
    await updateRule({ ...rule, enabled: !rule.enabled, layer: 'l7' })
    successMessage.value = `HTTP 规则 ${rule.id} 已${rule.enabled ? '停用' : '启用'}。`
    await loadRules()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '更新 HTTP 规则状态失败'
  }
}

const removeRule = async (id: string) => {
  if (!window.confirm(`确认删除 HTTP 规则 ${id} 吗？`)) return
  error.value = ''
  successMessage.value = ''
  try {
    await deleteRule(id)
    successMessage.value = `HTTP 规则 ${id} 已删除。`
    await loadRules()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '删除 HTTP 规则失败'
  }
}

onMounted(loadRules)
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
      <L7SectionNav />

      <section
        class="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm"
      >
        <div
          class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between"
        >
          <div>
            <p class="text-sm tracking-wider text-blue-700">HTTP 规则</p>
            <h2 class="mt-3 font-sans text-4xl font-semibold text-stone-900">
              HTTP 请求规则编排与启停控制
            </h2>
            <p class="mt-4 max-w-2xl text-sm leading-7 text-stone-700">
              HTTP 规则匹配的是统一请求字符串，包含方法、URI、Header、元数据和
              Body。适合做路径访问控制、请求特征拦截和应用侧告警。
            </p>
          </div>
          <button
            class="inline-flex items-center gap-2 self-start rounded-full bg-blue-600 px-4 py-3 text-sm font-semibold text-white transition hover:bg-blue-600/90"
            @click="openCreateRule"
          >
            <Plus :size="16" />
            新建 HTTP 规则
          </button>
        </div>
      </section>

      <section class="grid gap-4 md:grid-cols-3">
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <p class="text-xs tracking-wider text-slate-500">HTTP 规则总数</p>
          <p class="mt-3 text-3xl font-semibold text-stone-900">
            {{ l7Rules.length }}
          </p>
        </div>
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <p class="text-xs tracking-wider text-slate-500">已启用规则</p>
          <p class="mt-3 text-3xl font-semibold text-stone-900">
            {{ enabledCount }}
          </p>
        </div>
        <div class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <p class="text-xs tracking-wider text-slate-500">拦截动作规则</p>
          <p class="mt-3 text-3xl font-semibold text-stone-900">
            {{ blockCount }}
          </p>
        </div>
      </section>

      <div
        class="flex flex-wrap gap-3 rounded-[28px] border border-white/70 bg-white/60 p-4"
      >
        <label
          class="flex min-w-[220px] flex-1 items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-500"
        >
          <Search :size="14" />
          <input
            v-model="filters.search"
            type="text"
            class="w-full bg-transparent text-stone-800 outline-none"
            placeholder="搜索名称 / ID / 匹配内容"
          />
        </label>
        <select
          v-model="filters.action"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="all">全部动作</option>
          <option value="block">拦截</option>
          <option value="allow">放行</option>
          <option value="alert">告警</option>
        </select>
        <select
          v-model="filters.severity"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="all">全部级别</option>
          <option value="low">低</option>
          <option value="medium">中</option>
          <option value="high">高</option>
          <option value="critical">紧急</option>
        </select>
        <select
          v-model="filters.status"
          class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
        >
          <option value="all">全部状态</option>
          <option value="enabled">启用</option>
          <option value="disabled">停用</option>
        </select>
      </div>

      <div
        class="overflow-hidden rounded-xl border border-white/80 bg-white/78 shadow-[0_16px_44px_rgba(90,60,30,0.08)]"
      >
        <div class="overflow-x-auto">
          <table class="min-w-full border-collapse text-left">
            <thead class="bg-slate-50 text-sm text-slate-500">
              <tr>
                <th class="px-4 py-3 font-medium">状态</th>
                <th class="px-4 py-3 font-medium">规则 ID</th>
                <th class="px-4 py-3 font-medium">规则名称</th>
                <th class="px-4 py-3 font-medium">级别</th>
                <th class="px-4 py-3 font-medium">动作</th>
                <th class="px-4 py-3 font-medium">匹配内容</th>
                <th class="px-4 py-3 text-right font-medium">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="rule in filteredRules"
                :key="rule.id"
                class="border-t border-slate-200 text-sm text-stone-800 transition hover:bg-[#fff8ef]"
              >
                <td class="px-4 py-3">
                  <StatusBadge
                    :text="rule.enabled ? '启用' : '停用'"
                    :type="rule.enabled ? 'success' : 'muted'"
                    compact
                  />
                </td>
                <td class="px-4 py-3 font-mono text-xs text-slate-500">
                  {{ rule.id }}
                </td>
                <td class="px-4 py-3 font-semibold">{{ rule.name }}</td>
                <td class="px-4 py-3">{{ severityLabel(rule.severity) }}</td>
                <td class="px-4 py-3">{{ actionLabel(rule.action) }}</td>
                <td
                  class="max-w-[420px] px-4 py-3 font-mono text-xs text-slate-500"
                >
                  {{ rule.pattern }}
                </td>
                <td class="px-4 py-3">
                  <div class="flex justify-end gap-2">
                    <button
                      class="inline-flex items-center gap-1 rounded-full border border-slate-200 px-3 py-2 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                      @click="openEditRule(rule)"
                    >
                      <Edit3 :size="14" />
                      编辑
                    </button>
                    <button
                      class="inline-flex items-center gap-1 rounded-full border border-slate-200 px-3 py-2 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                      @click="toggleRuleStatus(rule)"
                    >
                      <Check :size="14" />
                      {{ rule.enabled ? '停用' : '启用' }}
                    </button>
                    <button
                      class="inline-flex items-center gap-1 rounded-full border border-red-500/20 px-3 py-2 text-xs text-red-600 transition hover:bg-red-500/8"
                      @click="removeRule(rule.id)"
                    >
                      <Trash2 :size="14" />
                      删除
                    </button>
                  </div>
                </td>
              </tr>
              <tr v-if="!filteredRules.length && !loading">
                <td
                  colspan="7"
                  class="px-4 py-6 text-center text-sm text-slate-500"
                >
                  当前还没有可显示的 HTTP 规则。
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div
      v-if="isRuleModalOpen"
      class="fixed inset-0 z-[100] flex items-stretch justify-end"
    >
      <div
        class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm"
        @click="isRuleModalOpen = false"
      ></div>
      <div
        class="relative h-full w-full max-w-3xl overflow-y-auto border-l border-slate-200 bg-[#fffaf4] p-5 shadow-[0_24px_80px_rgba(60,40,20,0.24)]"
      >
        <div class="flex items-center justify-between">
          <div>
            <p class="text-sm tracking-wide text-blue-700">
              {{ editingId ? '编辑 HTTP 规则' : '新建 HTTP 规则' }}
            </p>
            <h3 class="mt-2 text-3xl font-semibold text-stone-900">
              {{ editingId ? '调整 HTTP 请求策略' : '创建新的 HTTP 请求策略' }}
            </h3>
          </div>
          <button
            class="flex h-10 w-10 items-center justify-center rounded-full border border-slate-200 bg-white/75 transition hover:border-blue-500/40 hover:text-blue-700"
            @click="isRuleModalOpen = false"
          >
            <X :size="18" />
          </button>
        </div>

        <form class="mt-3 space-y-6" @submit.prevent="saveRule">
          <div
            class="space-y-3 rounded-xl border border-slate-200 bg-white/70 p-4"
          >
            <div>
              <p class="text-sm font-medium text-stone-900">快速模板</p>
              <p class="mt-1 text-xs leading-5 text-slate-500">
                HTTP 规则匹配的是统一请求字符串，常见内容包括 `GET
                /path`、`header: value`、`@network.client_ip: 1.2.3.4`
                和请求体。
              </p>
            </div>
            <div class="grid gap-3">
              <button
                v-for="template in l7RuleTemplates"
                :key="template.label"
                type="button"
                class="rounded-[18px] border border-slate-200 bg-white px-4 py-3 text-left transition hover:border-blue-500/40 hover:bg-[#fff8ef]"
                @click="applyTemplate(template)"
              >
                <div class="flex items-center justify-between gap-3">
                  <span class="text-sm font-medium text-stone-900">{{
                    template.label
                  }}</span>
                  <span class="text-xs text-slate-500"
                    >{{ severityLabel(template.severity) }} /
                    {{ actionLabel(template.action) }}</span
                  >
                </div>
                <p class="mt-1 text-xs leading-5 text-slate-500">
                  {{ template.description }}
                </p>
                <p class="mt-2 font-mono text-[11px] text-slate-500">
                  {{ template.pattern }}
                </p>
              </button>
            </div>
          </div>

          <div class="space-y-2">
            <label class="text-sm text-slate-500">规则 ID</label>
            <input
              v-model="ruleForm.id"
              type="text"
              class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 font-mono outline-none transition focus:border-blue-500"
              placeholder="例如 l7-block-admin-path"
              :disabled="Boolean(editingId)"
              required
            />
          </div>

          <div class="space-y-2">
            <label class="text-sm text-slate-500">规则名称</label>
            <input
              v-model="ruleForm.name"
              type="text"
              class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
              required
            />
          </div>

          <div class="grid gap-4 md:grid-cols-2">
            <div class="space-y-2">
              <label class="text-sm text-slate-500">级别</label>
              <select
                v-model="ruleForm.severity"
                class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
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
                v-model="ruleForm.action"
                class="w-full rounded-lg border border-slate-200 bg-white px-4 py-3 outline-none transition focus:border-blue-500"
              >
                <option value="block">拦截</option>
                <option value="allow">放行</option>
                <option value="alert">告警</option>
              </select>
            </div>
          </div>

          <div class="space-y-2">
            <label class="text-sm text-slate-500">匹配内容</label>
            <textarea
              v-model="ruleForm.pattern"
              rows="7"
              class="w-full rounded-xl border border-slate-200 bg-white px-4 py-3 font-mono text-sm outline-none transition focus:border-blue-500"
              placeholder="例如 (?i)(union\\s+select|or\\s+1=1) 或 user-agent:\\s*sqlmap"
              required
            ></textarea>
            <div
              class="rounded-lg bg-slate-50 px-4 py-3 text-xs leading-6 text-slate-500"
            >
              可匹配内容通常包括：请求行 `METHOD /uri`、Header 行、`@metadata`
              元数据和请求体。保存时后端会校验正则是否合法。
            </div>
          </div>

          <label
            class="flex items-center gap-3 rounded-xl border border-slate-200 bg-white/70 p-4"
          >
            <input
              v-model="ruleForm.enabled"
              type="checkbox"
              class="h-4 w-4 accent-blue-600"
            />
            <span class="text-sm text-stone-800"
              >保存后立即启用这条 HTTP 规则</span
            >
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
  </AppLayout>
</template>
