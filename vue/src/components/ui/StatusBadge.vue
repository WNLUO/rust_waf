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
  warning: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-500',
  info: 'bg-cyber-accent/10 border-cyber-accent/30 text-cyber-accent',
  muted: 'bg-white/5 border-white/10 text-cyber-muted',
}
</script>

<template>
  <div 
    class="inline-flex items-center gap-2 px-3 py-1 rounded-full border text-[11px] font-mono uppercase tracking-wider transition-all duration-300"
    :class="[styles[type || 'info'], compact ? 'px-2 py-0.5' : '']"
  >
    <component :is="iconMap[type || 'info']" v-if="!compact" :size="12" />
    <span>{{ text }}</span>
  </div>
</template>
