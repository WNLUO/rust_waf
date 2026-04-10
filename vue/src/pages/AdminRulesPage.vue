<script setup lang="ts">
import { computed, reactive, ref, onMounted } from 'vue'
import { createRule, deleteRule, fetchRulesList, updateRule } from '../lib/api'
import type { RuleDraft, RuleItem, RulesResponse } from '../lib/types'
import AppLayout from '../components/layout/AppLayout.vue'
import StatusBadge from '../components/ui/StatusBadge.vue'
import { useFormatters } from '../composables/useFormatters'
import { Plus, Edit3, Trash2, Check, Save, Search, RefreshCw, X } from 'lucide-vue-next'

const { severityLabel, actionLabel, layerLabel } = useFormatters()

const loading = ref(true)
const saving = ref(false)
const error = ref('')
const rulesPayload = ref<RulesResponse>({ rules: [] })
const isRuleModalOpen = ref(false)

const ruleForm = reactive<RuleDraft>({
  id: '',
  name: '',
  enabled: true,
  layer: 'l7',
  pattern: '',
  action: 'block',
  severity: 'high',
})

const ruleFilters = reactive({
  search: '',
  layer: 'all',
  action: 'all',
  severity: 'all',
  status: 'all',
})

const filteredRules = computed(() =>
  rulesPayload.value.rules.filter((rule) => {
    if (ruleFilters.layer !== 'all' && rule.layer !== ruleFilters.layer) return false
    if (ruleFilters.action !== 'all' && rule.action !== ruleFilters.action) return false
    if (ruleFilters.severity !== 'all' && rule.severity !== ruleFilters.severity) return false
    if (ruleFilters.status !== 'all' && rule.enabled !== (ruleFilters.status === 'enabled')) return false
    if (!ruleFilters.search.trim()) return true
    const keyword = ruleFilters.search.trim().toLowerCase()
    return (
      rule.name.toLowerCase().includes(keyword) ||
      rule.id.toLowerCase().includes(keyword) ||
      rule.pattern.toLowerCase().includes(keyword)
    )
  }),
)

const loadRules = async () => {
  loading.value = true
  try {
    rulesPayload.value = await fetchRulesList()
    error.value = ''
  } catch (e) {
    error.value = e instanceof Error ? e.message : '读取规则失败'
  } finally {
    loading.value = false
  }
}

const openCreateRule = () => {
  Object.assign(ruleForm, {
    id: '',
    name: '',
    enabled: true,
    layer: 'l7',
    pattern: '',
    action: 'block',
    severity: 'high',
  })
  isRuleModalOpen.value = true
}

const openEditRule = (rule: RuleItem) => {
  Object.assign(ruleForm, rule)
  isRuleModalOpen.value = true
}

const handleCreateOrUpdateRule = async () => {
  saving.value = true
  try {
    if (ruleForm.id) {
      await updateRule(ruleForm)
    } else {
      await createRule(ruleForm)
    }
    isRuleModalOpen.value = false
    await loadRules()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '规则保存失败'
  } finally {
    saving.value = false
  }
}

const toggleRuleStatus = async (rule: RuleItem) => {
  try {
    await updateRule({ ...rule, enabled: !rule.enabled })
    await loadRules()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '更新规则状态失败'
  }
}

const handleDeleteRule = async (id: string) => {
  if (!window.confirm('确认删除这条规则吗？')) return
  try {
    await deleteRule(id)
    await loadRules()
  } catch (e) {
    error.value = e instanceof Error ? e.message : '规则删除失败'
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
      <section class="rounded-2xl border border-cyber-border/60 bg-white p-6 shadow-sm">
        <div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p class="text-sm tracking-[0.22em] text-cyber-accent-strong">规则中心</p>
            <h2 class="mt-3 font-display text-4xl font-semibold text-stone-900">策略编排与启停控制</h2>
            <p class="mt-4 max-w-2xl text-sm leading-7 text-stone-700">
              这里专门处理四层和七层规则，不再和总览混在一起，便于你专注做筛选、编辑和启停操作。
            </p>
          </div>
          <button
            @click="openCreateRule"
            class="inline-flex items-center gap-2 self-start rounded-full bg-cyber-accent px-5 py-3 text-sm font-semibold text-white transition hover:bg-cyber-accent/90"
          >
            <Plus :size="16" />
            新建规则
          </button>
        </div>
      </section>

      <div
        v-if="error"
        class="rounded-[24px] border border-cyber-error/25 bg-cyber-error/8 px-5 py-4 text-sm text-cyber-error shadow-[0_14px_30px_rgba(166,30,77,0.08)]"
      >
        {{ error }}
      </div>

      <div class="flex flex-wrap gap-3 rounded-[28px] border border-white/70 bg-white/60 p-4">
        <label class="flex flex-1 min-w-[200px] items-center gap-2 rounded-[20px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-cyber-muted">
          <Search :size="14" />
          <input
            v-model="ruleFilters.search"
            type="text"
            class="w-full bg-transparent text-stone-800 outline-none"
            placeholder="搜索名称 / ID / 匹配内容"
          />
        </label>
        <select v-model="ruleFilters.layer" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <option value="all">全部层级</option>
          <option value="l4">四层</option>
          <option value="l7">七层</option>
        </select>
        <select v-model="ruleFilters.action" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <option value="all">全部动作</option>
          <option value="block">拦截</option>
          <option value="allow">放行</option>
          <option value="alert">告警</option>
          <option value="log">记录</option>
        </select>
        <select v-model="ruleFilters.severity" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
          <option value="all">全部级别</option>
          <option value="low">低</option>
          <option value="medium">中</option>
          <option value="high">高</option>
          <option value="critical">紧急</option>
        </select>
        <select v-model="ruleFilters.status" class="rounded-[18px] border border-cyber-border/70 bg-white px-3 py-2 text-sm text-stone-700">
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
                <th class="px-6 py-4 font-medium">规则名称</th>
                <th class="px-6 py-4 font-medium">层级</th>
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
                <td class="px-6 py-4 font-semibold">{{ rule.name }}</td>
                <td class="px-6 py-4">{{ layerLabel(rule.layer) }}</td>
                <td class="px-6 py-4">{{ severityLabel(rule.severity) }}</td>
                <td class="px-6 py-4">{{ actionLabel(rule.action) }}</td>
                <td class="max-w-[360px] px-6 py-4 font-mono text-xs text-cyber-muted">{{ rule.pattern }}</td>
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
                      @click="handleDeleteRule(rule.id)"
                      class="inline-flex items-center gap-1 rounded-full border border-cyber-error/20 px-3 py-2 text-xs text-cyber-error transition hover:bg-cyber-error/8"
                    >
                      <Trash2 :size="14" />
                      删除
                    </button>
                  </div>
                </td>
              </tr>
              <tr v-if="!filteredRules.length && !loading">
                <td colspan="7" class="px-6 py-10 text-center text-sm text-cyber-muted">当前还没有可显示的规则。</td>
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
            <p class="text-sm tracking-[0.18em] text-cyber-accent-strong">{{ ruleForm.id ? '编辑规则' : '新建规则' }}</p>
            <h3 class="mt-2 text-3xl font-semibold text-stone-900">{{ ruleForm.id ? '调整现有策略' : '创建新的防护策略' }}</h3>
          </div>
          <button
            @click="isRuleModalOpen = false"
            class="flex h-10 w-10 items-center justify-center rounded-full border border-cyber-border bg-white/75 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong"
          >
            <X :size="18" />
          </button>
        </div>

        <form @submit.prevent="handleCreateOrUpdateRule" class="mt-8 space-y-6">
          <div class="space-y-2">
            <label class="text-sm text-cyber-muted">规则名称</label>
            <input v-model="ruleForm.name" type="text" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent" required />
          </div>

          <div class="grid gap-4 md:grid-cols-3">
            <div class="space-y-2">
              <label class="text-sm text-cyber-muted">层级</label>
              <select v-model="ruleForm.layer" class="w-full rounded-[20px] border border-cyber-border bg-white px-4 py-3 outline-none transition focus:border-cyber-accent">
                <option value="l4">四层</option>
                <option value="l7">七层</option>
              </select>
            </div>

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
                <option value="log">记录</option>
              </select>
            </div>
          </div>

          <div class="space-y-2">
            <label class="text-sm text-cyber-muted">匹配内容</label>
            <textarea
              v-model="ruleForm.pattern"
              rows="6"
              class="w-full rounded-[24px] border border-cyber-border bg-white px-4 py-3 font-mono text-sm outline-none transition focus:border-cyber-accent"
              required
            ></textarea>
          </div>

          <label class="flex items-center gap-3 rounded-[24px] border border-cyber-border/70 bg-white/70 p-4">
            <input v-model="ruleForm.enabled" type="checkbox" class="h-4 w-4 accent-[var(--color-cyber-accent)]" />
            <span class="text-sm text-stone-800">保存后立即启用这条规则</span>
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
