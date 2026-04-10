<script setup lang="ts">
import { RouterLink, useRoute } from "vue-router";
import { LayoutDashboard, Shield } from "lucide-vue-next";

const route = useRoute();

const items = [
  { name: "L7 总览", path: "/admin/l7", icon: LayoutDashboard },
  { name: "L7 规则", path: "/admin/l7/rules", icon: Shield },
];

const isActive = (path: string) =>
  route.path === path || route.path.startsWith(`${path}/`);
</script>

<template>
  <div
    class="flex flex-wrap gap-3 rounded-2xl border border-slate-200 bg-white p-3 shadow-sm"
  >
    <RouterLink
      v-for="item in items"
      :key="item.path"
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
  </div>
</template>
