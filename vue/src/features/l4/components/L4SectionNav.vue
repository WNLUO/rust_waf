<script setup lang="ts">
import { RouterLink, useRoute } from 'vue-router'
import { LayoutDashboard } from 'lucide-vue-next'

const route = useRoute()

const item = { name: 'L4 总览', path: '/admin/l4', icon: LayoutDashboard }

const isActive = (path: string) =>
  route.path === path || route.path.startsWith(`${path}/`)
</script>

<template>
  <RouterLink
    :to="item.path"
    class="inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm transition-colors"
    :class="
      isActive(item.path)
        ? 'border-blue-500/20 bg-blue-600/8 text-blue-700'
        : 'border-slate-200 bg-white text-stone-700 hover:border-blue-500/40 hover:text-blue-700'
    "
  >
    <component :is="item.icon" :size="15" />
    <span>{{ item.name }}</span>
  </RouterLink>
</template>
