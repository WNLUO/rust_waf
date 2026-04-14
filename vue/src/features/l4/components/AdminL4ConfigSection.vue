<script setup lang="ts">
import type { L4ConfigForm } from '@/features/l4/utils/adminL4'
import type { L4StatsPayload } from '@/shared/types'
import AdminL4ConfigFormCard from './AdminL4ConfigFormCard.vue'
import AdminL4RuntimeInsightsSection from './AdminL4RuntimeInsightsSection.vue'

defineProps<{
  bloomPanels: Array<{
    label: string
    value: {
      filter_size: number
      hash_functions: number
      insert_count: number
      hit_count: number
      hit_rate: number
    }
  }>
  falsePositivePanels: Array<{
    label: string
    value: number
  }>
  form: L4ConfigForm
  formatNumber: (value?: number) => string
  formatBytes: (value?: number) => string
  meta: {
    runtime_enabled: boolean
    bloom_enabled: boolean
    bloom_false_positive_verification: boolean
    runtime_profile: string
    adaptive_managed_fields: boolean
    adaptive_runtime: import('@/shared/types').AdaptiveProtectionRuntimePayload | null
  }
  stats: L4StatsPayload | null
  topPorts: L4StatsPayload['per_port_stats']
  totalProcessedBytes: number
  blockedCapacityLabel: string
  blockedCapacityTone: 'success' | 'warning' | 'error'
}>()

defineEmits<{
  'update:form': [value: L4ConfigForm]
}>()
</script>

<template>
  <section class="grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
    <AdminL4ConfigFormCard
      :form="form"
      @update:form="$emit('update:form', $event)"
    />

    <AdminL4RuntimeInsightsSection
      :bloom-panels="bloomPanels"
      :false-positive-panels="falsePositivePanels"
      :format-number="formatNumber"
      :format-bytes="formatBytes"
      :meta="meta"
      :config-form="form"
      :stats="stats"
      :top-ports="topPorts"
      :total-processed-bytes="totalProcessedBytes"
      :blocked-capacity-label="blockedCapacityLabel"
      :blocked-capacity-tone="blockedCapacityTone"
    />
  </section>
</template>
