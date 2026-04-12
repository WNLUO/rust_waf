<script setup lang="ts">
import { AlertCircle, CheckCircle2, Info, TriangleAlert, X } from 'lucide-vue-next'
import { computed } from 'vue'
import { useNotifications, type NotificationItem } from '../../composables/useNotifications'

const { notifications, removeNotification } = useNotifications()

function toneClass(item: NotificationItem) {
  switch (item.tone) {
    case 'success':
      return 'border-emerald-200 bg-white text-emerald-900'
    case 'error':
      return 'border-rose-200 bg-white text-rose-900'
    case 'warning':
      return 'border-amber-200 bg-white text-amber-900'
    default:
      return 'border-sky-200 bg-white text-slate-900'
  }
}

function iconClass(item: NotificationItem) {
  switch (item.tone) {
    case 'success':
      return 'text-emerald-600'
    case 'error':
      return 'text-rose-600'
    case 'warning':
      return 'text-amber-600'
    default:
      return 'text-sky-600'
  }
}

function toneIcon(item: NotificationItem) {
  switch (item.tone) {
    case 'success':
      return CheckCircle2
    case 'error':
      return AlertCircle
    case 'warning':
      return TriangleAlert
    default:
      return Info
  }
}

const hasNotifications = computed(() => notifications.length > 0)
</script>

<template>
  <div
    class="pointer-events-none fixed right-4 top-4 z-[200] flex w-[min(92vw,24rem)] flex-col gap-3"
    aria-live="polite"
    aria-atomic="true"
  >
    <TransitionGroup name="toast">
      <div
        v-for="item in notifications"
        :key="item.id"
        class="pointer-events-auto overflow-hidden rounded-2xl border shadow-[0_18px_45px_rgba(15,23,42,0.12)] backdrop-blur"
        :class="toneClass(item)"
      >
        <div class="flex items-start gap-3 px-4 py-3">
          <component :is="toneIcon(item)" :size="18" class="mt-0.5 shrink-0" :class="iconClass(item)" />
          <div class="min-w-0 flex-1">
            <p class="text-sm font-semibold">{{ item.title }}</p>
            <p class="mt-1 break-words text-sm leading-5 text-slate-600">
              {{ item.message }}
            </p>
          </div>
          <button
            class="rounded-full p-1 text-slate-400 transition hover:bg-slate-100 hover:text-slate-700"
            @click="removeNotification(item.id)"
          >
            <X :size="14" />
          </button>
        </div>
      </div>
    </TransitionGroup>
    <div v-if="!hasNotifications" class="hidden"></div>
  </div>
</template>

<style scoped>
.toast-enter-active,
.toast-leave-active {
  transition: all 0.28s ease;
}

.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translate3d(0, -12px, 0) scale(0.98);
}

.toast-move {
  transition: transform 0.28s ease;
}
</style>
