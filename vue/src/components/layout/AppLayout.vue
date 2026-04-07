<script setup lang="ts">
import { RouterLink } from 'vue-router'
import { LayoutDashboard, Shield, ListFilter, Ban, Activity, Cpu } from 'lucide-vue-next'

const navItems = [
  { name: 'Dashboard', path: '/admin', icon: LayoutDashboard },
  { name: 'Rules', path: '/admin/rules', icon: Shield },
  { name: 'Events', path: '/admin/events', icon: Activity },
  { name: 'Blocked IPs', path: '/admin/blocked', icon: Ban },
]
</script>

<template>
  <div class="flex min-h-screen bg-cyber-bg text-gray-200">
    <!-- Sidebar -->
    <aside class="w-64 bg-cyber-surface border-r border-cyber-border flex flex-col fixed h-full transition-all duration-300">
      <div class="p-6 flex items-center gap-3 border-b border-cyber-border">
        <div class="p-2 bg-cyber-accent rounded-cyber shadow-cyber">
          <Cpu :size="24" class="text-white" />
        </div>
        <div>
          <h1 class="font-bold text-lg tracking-tight uppercase">Rust WAF</h1>
          <p class="text-[10px] text-cyber-muted tracking-widest font-mono">CORE v0.9.0</p>
        </div>
      </div>

      <nav class="flex-1 p-4 space-y-2 mt-4">
        <RouterLink 
          v-for="item in navItems" 
          :key="item.path" 
          :to="item.path"
          class="flex items-center gap-3 px-4 py-3 rounded-cyber transition-all duration-200 group"
          :class="[
            $route.path === item.path 
              ? 'bg-cyber-accent/10 border border-cyber-accent/30 text-cyber-accent' 
              : 'hover:bg-white/5 text-cyber-muted hover:text-gray-200 border border-transparent'
          ]"
        >
          <component :is="item.icon" :size="18" />
          <span class="font-medium text-sm">{{ item.name }}</span>
        </RouterLink>
      </nav>

      <div class="p-6 border-t border-cyber-border space-y-4">
        <RouterLink to="/" class="flex items-center gap-2 text-xs text-cyber-muted hover:text-cyber-accent transition-colors">
          <ListFilter :size="14" />
          <span>返回门户网站</span>
        </RouterLink>
      </div>
    </aside>

    <!-- Main Content -->
    <main class="flex-1 ml-64 min-h-screen">
      <header class="h-16 border-b border-cyber-border bg-cyber-surface/50 backdrop-blur-md sticky top-0 z-50 flex items-center justify-between px-8">
        <div class="flex items-center gap-2">
          <div class="w-2 h-2 rounded-full bg-cyber-success animate-pulse"></div>
          <span class="text-xs font-mono uppercase tracking-widest text-cyber-success">Gateway Status: Online</span>
        </div>
        
        <div class="flex items-center gap-6">
          <div class="flex flex-col items-end">
            <span class="text-[10px] text-cyber-muted uppercase font-mono">System Load</span>
            <div class="w-24 h-1 bg-cyber-border rounded-full mt-1 overflow-hidden">
              <div class="h-full bg-cyber-accent w-[35%]"></div>
            </div>
          </div>
        </div>
      </header>

      <div class="p-8">
        <slot></slot>
      </div>
    </main>
  </div>
</template>
