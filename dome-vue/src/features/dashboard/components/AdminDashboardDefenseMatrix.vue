<script setup lang="ts">
import StatusBadge from '@/shared/ui/StatusBadge.vue'

type BadgeType = 'success' | 'warning' | 'error' | 'muted' | 'info'

type DefenseStat = {
  label: string
  value: string
  class?: string
}

export type DefenseMatrixItem = {
  label: string
  badge: string
  type: BadgeType
  primaryStats: DefenseStat[]
  secondaryStats: DefenseStat[]
}

defineProps<{
  items: DefenseMatrixItem[]
}>()
</script>

<template>
  <div class="grid grid-cols-1 gap-2 md:grid-cols-2">
    <div
      v-for="item in items"
      :key="item.label"
      class="relative min-h-[8.25rem] min-w-0 overflow-hidden rounded-xl border border-slate-200 bg-white px-3 py-2.5 shadow-sm"
    >
      <div class="flex min-w-0 items-start justify-between gap-2">
        <p class="truncate text-xs font-semibold text-slate-900">
          {{ item.label }}
        </p>
        <StatusBadge :text="item.badge" :type="item.type" compact />
      </div>

      <div class="mt-2 grid grid-cols-2 gap-2">
        <div
          v-for="stat in item.primaryStats"
          :key="stat.label"
          class="flex min-w-0 items-baseline justify-between gap-2 border-l border-slate-200 pl-2 first:border-l-0 first:pl-0"
        >
          <p class="shrink-0 truncate text-[10px] text-slate-500">
            {{ stat.label }}
          </p>
          <p
            class="min-w-0 truncate text-right text-base font-semibold leading-5 text-slate-950"
            :class="stat.class"
            :title="stat.value"
          >
            {{ stat.value }}
          </p>
        </div>
      </div>

      <div
        class="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 border-t border-slate-100 pt-2"
      >
        <div
          v-for="stat in item.secondaryStats"
          :key="stat.label"
          class="flex min-w-0 items-baseline justify-between gap-2 text-[11px]"
        >
          <span class="shrink-0 text-slate-500">{{ stat.label }}</span>
          <span
            class="min-w-0 truncate text-right font-semibold text-slate-900"
            :class="stat.class"
            :title="stat.value"
          >
            {{ stat.value }}
          </span>
        </div>
      </div>
    </div>
  </div>
</template>
