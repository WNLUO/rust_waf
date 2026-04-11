<script setup lang="ts">
import type { L4ConfigForm } from '../../lib/adminL4'
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
  meta: {
    runtime_enabled: boolean
    bloom_enabled: boolean
    bloom_false_positive_verification: boolean
    runtime_profile: string
  }
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
      :meta="meta"
    />
  </section>
</template>
