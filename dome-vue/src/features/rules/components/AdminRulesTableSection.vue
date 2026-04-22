<script setup lang="ts">
import { Check, Edit3, Trash2 } from 'lucide-vue-next'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import type { RuleItem } from '@/shared/types'

defineProps<{
  displayActionLabel: (rule: RuleItem) => string
  filteredRules: RuleItem[]
  layerLabel: (value: string) => string
  loading: boolean
  severityLabel: (value: string) => string
}>()

defineEmits<{
  delete: [id: string]
  edit: [rule: RuleItem]
  toggle: [rule: RuleItem]
}>()
</script>

<template>
  <div
    class="overflow-hidden rounded-xl border border-white/80 bg-white/78 shadow-[0_16px_44px_rgba(90,60,30,0.08)]"
  >
    <div class="overflow-x-auto">
      <table class="min-w-full border-collapse text-left">
        <thead class="bg-slate-50 text-sm text-slate-500">
          <tr>
            <th class="px-4 py-3 font-medium">状态</th>
            <th class="px-4 py-3 font-medium">规则名称</th>
            <th class="px-4 py-3 font-medium">层级</th>
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
            <td class="px-4 py-3 font-semibold">{{ rule.name }}</td>
            <td class="px-4 py-3">{{ layerLabel(rule.layer) }}</td>
            <td class="px-4 py-3">{{ severityLabel(rule.severity) }}</td>
            <td class="px-4 py-3">{{ displayActionLabel(rule) }}</td>
            <td
              class="max-w-[360px] px-4 py-3 font-mono text-xs text-slate-500"
            >
              {{ rule.pattern }}
            </td>
            <td class="px-4 py-3">
              <div class="flex justify-end gap-2">
                <button
                  class="inline-flex items-center gap-1 rounded-full border border-slate-200 px-3 py-2 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                  @click="$emit('edit', rule)"
                >
                  <Edit3 :size="14" />
                  编辑
                </button>
                <button
                  class="inline-flex items-center gap-1 rounded-full border border-slate-200 px-3 py-2 text-xs text-stone-700 transition hover:border-blue-500/40 hover:text-blue-700"
                  @click="$emit('toggle', rule)"
                >
                  <Check :size="14" />
                  {{ rule.enabled ? '停用' : '启用' }}
                </button>
                <button
                  class="inline-flex items-center gap-1 rounded-full border border-red-500/20 px-3 py-2 text-xs text-red-600 transition hover:bg-red-500/8"
                  @click="$emit('delete', rule.id)"
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
              当前还没有可显示的规则。
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
