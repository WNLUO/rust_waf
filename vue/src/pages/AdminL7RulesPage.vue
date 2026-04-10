<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import AppLayout from '../components/layout/AppLayout.vue'
import L7SectionNav from '../components/l7/L7SectionNav.vue'
import StatusBadge from '../components/ui/StatusBadge.vue'
import { useFormatters } from '../composables/useFormatters'
import { createRule, deleteRule, fetchRulesList, updateRule } from '../lib/api'
import type { RuleDraft, RuleItem } from '../lib/types'
import { Check, Edit3, Plus, RefreshCw, Save, Search, Trash2, X } from 'lucide-vue-next'

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

const l7Rules = computed(() => rules.value.filter((rule) => rule.layer === 'l7'))
const filteredRules = computed(() =>
  l7Rules.value.filter((rule) => {
    if (filters.action !== 'all' && rule.action !== filters.action) return false
    if (filters.severity !== 'all' && rule.severity !== filters.severity) return false
    if (filters.status !== 'all' && rule.enabled !== (filters.status === 'enabled')) return false
    if (!filters.search.trim()) return true
    const keyword = filters.search.trim().toLowerCase()
    return (
      rule.name.toLowerCase().includes(keyword) ||
      rule.id.toLowerCase().includes(keyword) ||
      rule.pattern.toLowerCase().includes(keyword)
    )
  }),
)

const enabledCount = computed(() => l7Rules.value.filter((rule) => rule.enabled).length)
const blockCount = computed(() => l7Rules.value.filter((rule) => rule.action === 'block').length)

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
    description: '利用 inspection string 中的头部信息匹配伪造来源行为。',
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
    error.value = e instanceof Error ? e.message : '读取 L7 规则失败'
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
      successMessage.value = `L7 规则 ${payload.id} 已更新。`
    } else {
      await createRule(payload)
      successMessage.value = `L7 规则 ${payload.id} 已创建。`
    }

    isRuleModalOpen.value = false
    await loadRules()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '保存 L7 规则失败'
  } finally {
    saving.value = false
  }
}

const toggleRuleStatus = async (rule: RuleItem) => {
  error.value = ''
  successMessage.value = ''
  try {
    await updateRule({ ...rule, enabled: !rule.enabled, layer: 'l7' })
    successMessage.value = `L7 规则 ${rule.id} 已${rule.enabled ? '停用' : '启用'}。`
    await loadRules()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '更新 L7 规则状态失败'
  }
}

const removeRule = async (id: string) => {
  if (!window.confirm(`确认删除 L7 规则 ${id} 吗？`)) return
  error.value = ''
  successMessage.value = ''
  try {
    await deleteRule(id)
    successMessage.value = `L7 规则 ${id} 已删除。`
    await loadRules()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '删除 L7 规则失败'
  }
}

onMounted(loadRules)
</script>

<template>
  <AppLayout>
    <template #header-extra>
      <button
        @click="loadRules"
        class="inline-flex items-center gap-2 rounded-full border border-cyber-border bg-white/70 px-4 py-1.5 text-xs text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong disabled:opacity-60"
        :disabled="loading"
      >
        <RefreshCw :size="14" :class="{ 'animate-spin': loading }" />
        刷新规则
      </button>
    </template>

    <div class="space-y-6">
      <L7SectionNav />

      <section class="rounded-[34px] border border-white/85 bg-[linear-gradient(140deg,rgba(255,250,244,0.92),rgba(244,239,231,0.96))] p-7 shadow-[0_26px_80px_rgba(90,60,30,0.10)]">
        <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p class="text-sm tracking-[0.22em] text-cyber-accent-strong">L7 规则</p>
            <h2 class="mt-3 font-display text-4xl font-semibold text-stone-900">七层规则编排与启停控制</h2>
            <p class="mt-4 max-w-2xl text-sm leading-7 text-stone-700">
              L7 规则匹配的是统一请求字符串，包含方法、URI、Header、元数据和 Body。适合做路径访问控制、请求特征拦截和应用层告警。
            </p>
          </div>
          <button
            @click="openCreateRule"
            class="inline-flex items-center gap-2 self-start rounded-full bg-cyber-accent px-5 py-3 text-sm font-semibold text-white shadow-cyber transition hover:-translate-y-0.5"
          >
            <Plus :size="16" />
            新建 L7 规则
          </button>
        </div>
      </section>

      <section class="grid gap-4 md:grid-cols-3">
        <div class="rounded-[28px] border border-white/80 bg-white/75 p-5 shadow-[0_16px_44px_rgba(90,60,30,0.08)]">
          <p class="text-xs tracking-[0.2em] text-cyber-muted">L7 规则总数</p>
          <p class="mt-3 text-3xl font-semibold text-stone-900">{{ l7Rules.length }}</p>
        </div>
        <div class="rounded-[28px] border border-white/80 bg-white/75 p-5 shadow-[0_16px_44px_rgba(90,60,30,0.08)]">
          <p class="text-xs tracking-[0.2em] text-cyber-muted">已启用规则</p>
          <p class="mt-3 text-3xl font-semibold text-stone-900">{{ enabledCount }}</p>
        </div>
        <div class="rounded-[28px] border border-white/80 bg-white/75 p-5 shadow-[0_16px_44px_rgba(90,60,30,0.08)]">
          <p class="text-xs tracking-[0.2em] text-cyber-muted">拦截动作规则</p>
          <p class="mt-3 text-3xl font-semibold text-stone-900">{{ blockCount }}</p>
        </div>
      </section>

      <div
        v-if="error"
        class="rounded-[24px] border border-cyber-error/25 bg-cyber-error/8 px-5 py-4 text-sm text-cyber-error shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

      <div
        v-if="successMessage"
        class="rounded-[24px] border border-emerald-300/60 bg-emerald-50 px-5 py-4 text-sm text-emerald-800 shadow-[0_14px_30px_rgba(16,185,129,0.08)]"
      >
        {{ successMessage }}
      </div>

      <div class="flex flex-wrap gap-3 rounded-[28px] border border-white/70 bg-white/60 p-4">
        <label class="flex min-w-[220px] flex-1 items-center gap-2 rounded-[20px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-cyber-muted">
          <Search :size="14" />
          <input
            v-model="filters.search"
            type="text"
            class="w-full bg-transparent text-stone-800 outline-none"
            placeholder="搜索名称 / ID / 匹配内容"
          />
        </label>
        <select v-model="filters.action" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <option value="all">全部动作</option>
          <option value="block">拦截</option>
          <option value="allow">放行</option>
          <option value="alert">告警</option>
        </select>
        <select v-model="filters.severity" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <option value="all">全部级别</option>
          <option value="low">低</option>
          <option value="medium">中</option>
          <option value="high">高</option>
          <option value="critical">紧急</option>
        </select>
        <select v-model="filters.status" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <option value="all">全部状态</option>
          <option value="enabled">启用</option>
          <option value="disabled">停用</option>
        </select>
      </div>

      <div class="overflow-hidden rounded-[30px] border border-white/80 bg-white/78 shadow-[0_16px_44px_rgba(90,60,30,0.08)]">
        <div class="overflow-x-auto">
          <table class="min-w-full border-collapse text-left">
            <thead class="bg-cyber-surface-strong text-sm text-cyber-muted">
              <tr>
                <th class="px-6 py-4 font-medium">状态</th>
                <th class="px-6 py-4 font-medium">规则 ID</th>
                <th class="px-6 py-4 font-medium">规则名称</th>
                <th class="px-6 py-4 font-medium">级别</th>
                <th class="px-6 py-4 font-medium">动作</th>
                <th class="px-6 py-4 font-medium">匹配内容</th>
                <th class="px-6 py-4 text-right font-medium">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="rule in filteredRules"
                :key="rule.id"
                class="border-t border-cyber-border/50 text-sm text-stone-800 transition hover:bg-[#fff8ef]"
              >
                <td class="px-6 py-4">
                  <StatusBadge :text="rule.enabled ? '启用' : '停用'" :type="rule.enabled ? 'success' : 'muted'" compact />
                </td>
                <td class="px-6 py-4 font-mono text-xs text-cyber-muted">{{ rule.id }}</td>
                <td class="px-6 py-4 font-semibold">{{ rule.name }}</td>
                <td class="px-6 py-4">{{ severityLabel(rule.severity) }}</td>
                <td class="px-6 py-4">{{ actionLabel(rule.action) }}</td>
                <td class="max-w-[420px] px-6 py-4 font-mono text-xs text-cyber-muted">{{ rule.pattern }}</td>
                <td class="px-6 py-4">
                  <div class="flex justify-end gap-2">
                    <button
                      @click="openEditRule(rule)"
                      class="inline-flex items-center gap-1 rounded-full border border-cyber-border px-3 py-2 text-xs text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong"
                    >
                      <Edit3 :size="14" />
                      编辑
                    </button>
                    <button
                      @click="toggleRuleStatus(rule)"
                      class="inline-flex items-center gap-1 rounded-full border border-cyber-border px-3 py-2 text-xs text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong"
                    >
                      <Check :size="14" />
                      {{ rule.enabled ? '停用' : '启用' }}
                    </button>
                    <button
                      @click="removeRule(rule.id)"
                      class="inline-flex items-center gap-1 rounded-full border border-cyber-error/20 px-3 py-2 text-xs text-cyber-error transition hover:bg-cyber-error/8"
                    >
                      <Trash2 :size="14" />
                      删除
                    </button>
                  </div>
                </td>
              </tr>
              <tr v-if="!filteredRules.length && !loading">
                <td colspan="7" class="px-6 py-10 text-center text-sm text-cyber-muted">当前还没有可显示的 L7 规则。</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div v-if="isRuleModalOpen" class="fixed inset-0 z-[100] flex items-stretch justify-end">
      <div class="absolute inset-0 bg-stone-950/35 backdrop-blur-sm" @click="isRuleModalOpen = false"></div>
      <div class="relative h-full w-full max-w-xl overflow-y-auto border-l border-cyber-border/70 bg-[#fffaf4] p-8 shadow-[0_24px_80px_rgba(60,40,20,0.24)]">
        <div class="flex items-center justify-between">
          <div>
            <p class="text-sm tracking-[0.18em] text-cyber-accent-strong">{{ editingId ? '编辑 L7 规则' : '新建 L7 规则' }}</p>
            <h3 class="mt-2 text-3xl font-semibold text-stone-900">{{ editingId ? '调整七层检测策略' : '创建新的七层检测策略' }}</h3>
          </div>
          <button
            @click="isRuleModalOpen = false"
            class="flex h-10 w-10 items-center justify-center rounded-full border border-cyber-border bg-white/75 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong"
          >
            <X :size="18" />
          </button>
        </div>

        <form @submit.prevent="saveRule" class="mt-8 space-y-6">
          <div class="space-y-3 rounded-[24px] border border-cyber-border/70 bg-white/70 p-4">
            <div>
              <p class="text-sm font-medium text-stone-900">快速模板</p>
              <p class="mt-1 text-xs leading-5 text-cyber-muted">L7 规则匹配的是统一 inspection string，常见内容包括 `GET /path`、`header: value`、`@network.client_ip: 1.2.3.4` 和请求体。</p>
            </div>
            <div class="grid gap-3">
              <button
                v-for="template in l7RuleTemplates"
                :key="template.label"
                type="button"
                @click="applyTemplate(template)"
                class="rounded-[18px] border border-cyber-border/70 bg-white px-4 py-3 text-left transition hover:border-cyber-accent/40 hover:bg-[#fff8ef]"
              >
                <div class="flex items-center justify-between gap-3">
                  <span class="text-sm font-medium text-stone-900">{{ template.label }}</span>
                  <span class="text-xs text-cyber-muted">{{ severityLabel(template.severity) }} / {{ actionLabel(template.action) }}</span>
                </div>
                <p class="mt-1 text-xs leading-5 text-cyber-muted">{{ template.description }}</p>
                <p class="mt-2 font-mono text-[11px] text-cyber-muted">{{ template.pattern }}</p>
              </button>
            </div>
          </div>

          <div class="space-y-2">
            <label class="text-sm text-cyber-muted">规则 ID</label>
            <input
              v-model="ruleForm.id"
              type="text"
              class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 font-mono outline-none transition focus:border-cyber-accent"
              placeholder="例如 l7-block-admin-path"
              :disabled="Boolean(editingId)"
              required
            />
          </div>

          <div class="space-y-2">
            <label class="text-sm text-cyber-muted">规则名称</label>
            <input v-model="ruleForm.name" type="text" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" required />
          </div>

          <div class="grid gap-4 md:grid-cols-2">
            <div class="space-y-2">
              <label class="text-sm text-cyber-muted">级别</label>
              <select v-model="ruleForm.severity" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent">
                <option value="low">低</option>
                <option value="medium">中</option>
                <option value="high">高</option>
                <option value="critical">紧急</option>
              </select>
            </div>

            <div class="space-y-2">
              <label class="text-sm text-cyber-muted">动作</label>
              <select v-model="ruleForm.action" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent">
                <option value="block">拦截</option>
                <option value="allow">放行</option>
                <option value="alert">告警</option>
              </select>
            </div>
          </div>

          <div class="space-y-2">
            <label class="text-sm text-cyber-muted">匹配内容</label>
            <textarea
              v-model="ruleForm.pattern"
              rows="7"
              class="w-full rounded-[24px] border border-cyber-border bg-white px-4 py-3 font-mono text-sm outline-none transition focus:border-cyber-accent"
              placeholder="例如 (?i)(union\\s+select|or\\s+1=1) 或 user-agent:\\s*sqlmap"
              required
            ></textarea>
            <div class="rounded-[20px] bg-cyber-surface-strong px-4 py-3 text-xs leading-6 text-cyber-muted">
              可匹配内容通常包括：请求行 `METHOD /uri`、Header 行、`@metadata` 元数据和请求体。保存时后端会校验正则是否合法。
            </div>
          </div>

          <label class="flex items-center gap-3 rounded-[24px] border border-cyber-border/70 bg-white/70 p-4">
            <input v-model="ruleForm.enabled" type="checkbox" class="h-4 w-4 accent-[var(--color-cyber-accent)]" />
            <span class="text-sm text-stone-800">保存后立即启用这条 L7 规则</span>
          </label>

          <button
            type="submit"
            class="inline-flex w-full items-center justify-center gap-2 rounded-full bg-cyber-accent px-6 py-4 text-base font-semibold text-white shadow-cyber transition hover:-translate-y-0.5 disabled:opacity-60"
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
