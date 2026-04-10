<script setup lang="ts">
import { RouterLink } from 'vue-router'
import { LayoutDashboard, Shield, ListFilter, Ban, Activity, Cpu, Settings, Link2 } from 'lucide-vue-next'

const navItems = [
  { name: '总览', path: '/admin', icon: LayoutDashboard },
  { name: '规则中心', path: '/admin/rules', icon: Shield },
  { name: '事件记录', path: '/admin/events', icon: Activity },
  { name: '封禁名单', path: '/admin/blocked', icon: Ban },
  { name: '雷池联动', path: '/admin/safeline', icon: Link2 },
  { name: '系统设置', path: '/admin/settings', icon: Settings },
]
</script>

<template>
  <div class="min-h-screen bg-transparent text-stone-900 lg:flex">
    <aside class="border-b border-cyber-border/80 bg-white/70 backdrop-blur lg:fixed lg:flex lg:h-full lg:w-72 lg:flex-col lg:border-b-0 lg:border-r">
      <div class="flex items-center gap-3 border-b border-cyber-border/70 px-6 py-6">
        <div class="flex h-12 w-12 items-center justify-center rounded-2xl bg-cyber-accent text-white shadow-cyber">
          <Cpu :size="22" />
        </div>
        <div>
          <h1 class="font-display text-2xl font-semibold tracking-[0.1em] text-cyber-accent-strong">玄枢控制台</h1>
          <p class="mt-1 text-xs tracking-[0.2em] text-cyber-muted">安全网关运行面板</p>
        </div>
      </div>

      <nav class="grid gap-2 px-4 py-5 lg:flex-1 lg:content-start">
        <RouterLink
          v-for="item in navItems"
          :key="item.path"
          :to="item.path"
          class="flex items-center gap-3 rounded-[20px] border px-4 py-3 transition-all duration-200"
          :class="[
            $route.path === item.path
              ? 'border-cyber-accent/30 bg-cyber-accent/10 text-cyber-accent-strong shadow-[0_12px_30px_rgba(179,84,30,0.10)]'
              : 'border-transparent text-cyber-muted hover:border-cyber-border hover:bg-white/70 hover:text-stone-900'
          ]"
        >
          <component :is="item.icon" :size="18" />
          <span class="text-sm font-medium">{{ item.name }}</span>
        </RouterLink>
      </nav>

      <div class="space-y-4 border-t border-cyber-border/70 px-6 py-6">
        <RouterLink to="/" class="flex items-center gap-2 text-sm text-cyber-muted transition-colors hover:text-cyber-accent-strong">
          <ListFilter :size="14" />
          <span>返回首页</span>
        </RouterLink>
      </div>
    </aside>

    <main class="min-h-screen flex-1 lg:ml-72">
      <header class="sticky top-0 z-50 flex items-center justify-between gap-4 border-b border-cyber-border/70 bg-[#f8f1e8]/85 px-6 py-4 backdrop-blur md:px-8">
        <div class="flex-1"></div>
        <div class="flex flex-wrap items-center gap-4 md:gap-6">
          <slot name="header-extra"></slot>
        </div>
      </header>

      <div class="px-6 py-6 md:px-8 md:py-8">
        <slot></slot>
      </div>
    </main>
  </div>
</template>
