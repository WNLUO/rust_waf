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
  <div class="flex flex-wrap gap-3 rounded-[28px] border border-white/70 bg-white/65 p-3 shadow-[0_12px_30px_rgba(90,60,30,0.05)]">
    <RouterLink
      v-for="item in items"
      :key="item.path"
      :to="item.path"
      class="inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm transition"
      :class="isActive(item.path)
        ? 'border-cyber-accent/30 bg-cyber-accent/10 text-cyber-accent-strong shadow-[0_12px_24px_rgba(179,84,30,0.08)]'
        : 'border-cyber-border/70 bg-white/80 text-stone-700 hover:border-cyber-accent/40 hover:text-cyber-accent-strong'"
    >
      <component :is="item.icon" :size="15" />
      <span>{{ item.name }}</span>
    </RouterLink>
  </div>
</template>
