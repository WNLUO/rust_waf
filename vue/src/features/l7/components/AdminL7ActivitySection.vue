<script setup lang="ts">
import CyberCard from '@/shared/ui/CyberCard.vue'
import StatusBadge from '@/shared/ui/StatusBadge.vue'
import type { RuleItem, SecurityEventItem } from '@/shared/types'

defineProps<{
  actionLabel: (value: string) => string
  blockL7Rules: number
  enabledL7Rules: number
  events: SecurityEventItem[]
  formatNumber: (value?: number) => string
  formatTimestamp: (timestamp?: number | null) => string
  l7Rules: RuleItem[]
}>()
</script>

<template>
  <section class="grid gap-4 xl:grid-cols-[1fr_1fr]">
    <CyberCard title="最近 HTTP 事件" sub-title="只展示请求侧策略事件">
      <div class="space-y-4">
        <div
          v-for="event in events"
          :key="event.id"
          class="rounded-xl border border-slate-200 bg-white/75 p-4"
        >
          <div
            class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
          >
            <div class="flex items-center gap-3">
              <StatusBadge
                :text="actionLabel(event.action)"
                :type="event.action === 'block' ? 'error' : 'warning'"
              />
              <p class="text-sm font-medium text-stone-900">
                {{ event.reason }}
              </p>
            </div>
            <span class="text-xs text-slate-500">{{
              formatTimestamp(event.created_at)
            }}</span>
          </div>
          <div class="mt-3 grid gap-2 text-sm text-stone-700 md:grid-cols-2">
            <p>来源：{{ event.source_ip }}:{{ event.source_port }}</p>
            <p>目标：{{ event.dest_ip }}:{{ event.dest_port }}</p>
            <p>请求：{{ event.http_method || '-' }} {{ event.uri || '' }}</p>
            <p>版本：{{ event.http_version || '-' }}</p>
            <p v-if="event.provider_event_id" class="md:col-span-2">
              事件号：{{ event.provider_event_id }}
            </p>
          </div>
        </div>
        <p v-if="!events.length" class="text-sm text-slate-500">
          暂无 HTTP 事件。
        </p>
      </div>
      <template #header-action>
        <RouterLink
          to="/admin/events"
          class="inline-flex items-center gap-2 text-sm text-blue-700 transition hover:text-blue-600"
        >
          查看全部
        </RouterLink>
      </template>
    </CyberCard>

    <CyberCard title="HTTP 规则摘要" sub-title="规则中心中的请求侧策略概览">
      <div class="grid gap-4 md:grid-cols-3">
        <div class="rounded-xl bg-slate-50 p-4">
          <p class="text-xs tracking-wide text-slate-500">HTTP 规则总数</p>
          <p class="mt-3 text-3xl font-semibold text-stone-900">
            {{ formatNumber(l7Rules.length) }}
          </p>
        </div>
        <div class="rounded-xl bg-slate-50 p-4">
          <p class="text-xs tracking-wide text-slate-500">已启用规则</p>
          <p class="mt-3 text-3xl font-semibold text-stone-900">
            {{ formatNumber(enabledL7Rules) }}
          </p>
        </div>
        <div class="rounded-xl bg-slate-50 p-4">
          <p class="text-xs tracking-wide text-slate-500">拦截动作规则</p>
          <p class="mt-3 text-3xl font-semibold text-stone-900">
            {{ formatNumber(blockL7Rules) }}
          </p>
        </div>
      </div>

      <div class="mt-3 space-y-3">
        <div
          v-for="rule in l7Rules.slice(0, 5)"
          :key="rule.id"
          class="rounded-lg border border-slate-200 bg-white/70 px-4 py-3"
        >
          <div
            class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between"
          >
            <div>
              <p class="font-medium text-stone-900">{{ rule.name }}</p>
              <p class="mt-1 font-mono text-xs text-slate-500">
                {{ rule.pattern }}
              </p>
            </div>
            <div class="flex flex-wrap gap-2">
              <StatusBadge
                :text="rule.enabled ? '启用' : '停用'"
                :type="rule.enabled ? 'success' : 'muted'"
                compact
              />
              <StatusBadge
                :text="actionLabel(rule.action)"
                :type="rule.action === 'block' ? 'error' : 'warning'"
                compact
              />
            </div>
          </div>
        </div>
        <p v-if="!l7Rules.length" class="text-sm text-slate-500">
          当前还没有 HTTP 规则。
        </p>
      </div>
    </CyberCard>
  </section>
</template>
