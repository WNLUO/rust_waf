<script setup lang="ts">
import { RouterLink, useRoute } from 'vue-router'
import { Ban, LayoutDashboard, Network, Shield } from 'lucide-vue-next'

const route = useRoute()

const items = [
  { name: 'L4 总览', path: '/admin/l4', icon: LayoutDashboard },
  { name: 'L4 规则', path: '/admin/l4/rules', icon: Shield },
  { name: 'L4 黑名单', path: '/admin/l4/blocklist', icon: Ban },
  { name: '端口画像', path: '/admin/l4/ports', icon: Network },
]

const isActive = (path: string) => route.path === path || route.path.startsWith(`${path}/`)
</script>

<template>
  <div class="flex flex-wrap gap-3 rounded-2xl border border-cyber-border/60 bg-white p-3 shadow-sm">
    <RouterLink
      v-for="item in items"
      :key="item.path"
      :to="item.path"
      class="inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm transition-colors"
      :class="isActive(item.path)
        ? 'border-cyber-accent/20 bg-cyber-accent/8 text-cyber-accent-strong'
        : 'border-cyber-border/70 bg-white text-stone-700 hover:border-cyber-accent/40 hover:text-cyber-accent-strong'"
    >
      <component :is="item.icon" :size="15" />
      <span>{{ item.name }}</span>
    </RouterLink>
  </div>
</template>
