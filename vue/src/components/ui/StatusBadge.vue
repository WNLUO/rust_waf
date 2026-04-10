<script setup lang="ts">
import { AlertCircle, CheckCircle2, XCircle, Info } from "lucide-vue-next";

const props = defineProps<{
  type?: "success" | "error" | "warning" | "info" | "muted";
  text: string;
  compact?: boolean;
}>();

const iconMap = {
  success: CheckCircle2,
  error: XCircle,
  warning: AlertCircle,
  info: Info,
  muted: Info,
};

const styles = {
  success: "bg-emerald-50 border-emerald-200 text-emerald-700",
  error: "bg-red-50 border-red-200 text-red-700",
  warning: "bg-amber-50 border-amber-200 text-amber-700",
  info: "bg-blue-50 border-blue-200 text-blue-700",
  muted: "bg-slate-50 border-slate-200 text-slate-600",
};
</script>

<template>
  <div
    class="inline-flex max-w-full items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs transition-colors font-medium"
    :class="[styles[type || 'info'], compact ? 'max-w-[16rem] px-2 py-0' : '']"
    :title="text"
  >
    <component :is="iconMap[type || 'info']" v-if="!compact" :size="12" />
    <span class="min-w-0" :class="compact ? 'truncate' : 'break-all'">{{
      text
    }}</span>
  </div>
</template>
