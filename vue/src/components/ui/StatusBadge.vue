<script setup lang="ts">
import { AlertCircle, CheckCircle2, XCircle, Info } from 'lucide-vue-next'

const props = defineProps<{
  type?: 'success' | 'error' | 'warning' | 'info' | 'muted'
  text: string
  compact?: boolean
}>()

const iconMap = {
  success: CheckCircle2,
  error: XCircle,
  warning: AlertCircle,
  info: Info,
  muted: Info
}

const styles = {
  success: 'bg-cyber-success/10 border-cyber-success/30 text-cyber-success',
  error: 'bg-cyber-error/10 border-cyber-error/30 text-cyber-error',
  warning: 'bg-amber-500/10 border-amber-500/30 text-amber-700',
  info: 'bg-cyber-accent/10 border-cyber-accent/30 text-cyber-accent-strong',
  muted: 'bg-stone-500/5 border-stone-300 text-cyber-muted',
}
</script>

<template>
  <div
    class="inline-flex max-w-full items-center gap-2 rounded-full border px-3 py-1 text-xs transition-colors"
    :class="[styles[type || 'info'], compact ? 'max-w-[16rem] px-2 py-0.5' : '']"
    :title="text"
  >
    <component :is="iconMap[type || 'info']" v-if="!compact" :size="12" />
    <span class="min-w-0" :class="compact ? 'truncate' : 'break-all'">{{ text }}</span>
  </div>
</template>
