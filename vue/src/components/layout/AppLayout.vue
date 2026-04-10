<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import {
  LayoutDashboard,
  Shield,
  ListFilter,
  Ban,
  Activity,
  Cpu,
  Settings,
  Link2,
  ServerCog,
  Globe,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  X,
} from 'lucide-vue-next'

const navItems = [
  { name: '总览', path: '/admin', icon: LayoutDashboard },
  { name: '规则中心', path: '/admin/rules', icon: Shield },
  { name: 'L4管理', path: '/admin/l4', icon: ServerCog },
  { name: 'L7管理', path: '/admin/l7', icon: Globe },
  { name: '事件记录', path: '/admin/events', icon: Activity },
  { name: '封禁名单', path: '/admin/blocked', icon: Ban },
  { name: '雷池联动', path: '/admin/safeline', icon: Link2 },
  { name: '系统设置', path: '/admin/settings', icon: Settings },
]

const route = useRoute()
const DESKTOP_BREAKPOINT = 1024
const SIDEBAR_STORAGE_KEY = 'waf-admin-sidebar-collapsed'

const isDesktop = ref(false)
const desktopCollapsed = ref(false)
const mobileMenuOpen = ref(false)

const isRouteActive = (path: string) =>
  route.path === path || route.path.startsWith(`${path}/`)

const syncViewport = () => {
  const nextIsDesktop = window.innerWidth >= DESKTOP_BREAKPOINT
  isDesktop.value = nextIsDesktop

  if (nextIsDesktop) {
    mobileMenuOpen.value = false
  }
}

const toggleSidebar = () => {
  if (isDesktop.value) {
    desktopCollapsed.value = !desktopCollapsed.value
    return
  }
  mobileMenuOpen.value = !mobileMenuOpen.value
}

const shouldShowNav = computed(() => isDesktop.value || mobileMenuOpen.value)
const sidebarExpanded = computed(() => !isDesktop.value || !desktopCollapsed.value)
const currentPageName = computed(
  () => navItems.find((item) => isRouteActive(item.path))?.name ?? '控制台',
)
const sidebarWidth = computed(() =>
  desktopCollapsed.value ? '5.5rem' : 'clamp(15.5rem, 20vw, 18rem)',
)
const layoutStyle = computed(() => ({
  '--sidebar-width': isDesktop.value ? sidebarWidth.value : '100%',
}))
const toggleLabel = computed(() => {
  if (isDesktop.value) {
    return desktopCollapsed.value ? '展开侧边栏' : '收起侧边栏'
  }
  return mobileMenuOpen.value ? '收起导航' : '展开导航'
})
const toggleIcon = computed(() => {
  if (isDesktop.value) {
    return desktopCollapsed.value ? PanelLeftOpen : PanelLeftClose
  }
  return mobileMenuOpen.value ? X : Menu
})

onMounted(() => {
  desktopCollapsed.value = window.localStorage.getItem(SIDEBAR_STORAGE_KEY) === 'true'
  syncViewport()
  window.addEventListener('resize', syncViewport)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', syncViewport)
})

watch(desktopCollapsed, (collapsed) => {
  if (typeof window === 'undefined') return
  window.localStorage.setItem(SIDEBAR_STORAGE_KEY, String(collapsed))
})

watch(
  () => route.fullPath,
  () => {
    mobileMenuOpen.value = false
  },
)
</script>

<template>
  <div class="min-h-screen bg-transparent text-stone-900 lg:flex" :style="layoutStyle">
    <aside
      class="border-b border-cyber-border/80 bg-[#fbf7f1] transition-[width] duration-300 ease-out lg:fixed lg:inset-y-0 lg:left-0 lg:z-40 lg:flex lg:w-[var(--sidebar-width)] lg:flex-col lg:border-b-0 lg:border-r"
    >
      <div
        class="flex items-center gap-3 border-b border-cyber-border/70 px-4 py-5 transition-[padding] duration-300 md:px-6 md:py-6"
        :class="sidebarExpanded ? 'justify-start' : 'lg:justify-center lg:px-3'"
      >
        <div class="flex h-12 w-12 items-center justify-center rounded-xl bg-cyber-accent text-white">
          <Cpu :size="22" />
        </div>
        <div v-if="sidebarExpanded" class="min-w-0">
          <h1 class="font-display text-2xl font-semibold tracking-[0.1em] text-cyber-accent-strong">控制台</h1>
          <p class="mt-1 text-xs tracking-[0.2em] text-cyber-muted">安全网关运行面板</p>
        </div>
      </div>

      <nav
        v-show="shouldShowNav"
        class="grid gap-2 px-3 py-5 lg:flex-1 lg:content-start"
        :class="sidebarExpanded ? 'md:px-4' : 'lg:px-3'"
      >
        <RouterLink
          v-for="item in navItems"
          :key="item.path"
          :to="item.path"
          class="flex items-center rounded-2xl border transition-colors duration-200"
          :title="sidebarExpanded ? '' : item.name"
          :aria-label="item.name"
          :class="[
            sidebarExpanded
              ? 'gap-3 px-4 py-3'
              : 'justify-center px-3 py-3 lg:min-h-[52px]',
            isRouteActive(item.path)
              ? 'border-cyber-accent/20 bg-cyber-accent/8 text-cyber-accent-strong'
              : 'border-transparent text-cyber-muted hover:border-cyber-border hover:bg-white hover:text-stone-900'
          ]"
        >
          <component :is="item.icon" :size="18" />
          <span v-if="sidebarExpanded" class="text-sm font-medium">{{ item.name }}</span>
        </RouterLink>
      </nav>

      <div
        v-show="shouldShowNav"
        class="space-y-4 border-t border-cyber-border/70 px-4 py-5 md:px-6 md:py-6"
        :class="sidebarExpanded ? '' : 'lg:px-3'"
      >
        <RouterLink
          to="/"
          class="flex items-center text-sm text-cyber-muted transition-colors hover:text-cyber-accent-strong"
          :class="sidebarExpanded ? 'gap-2' : 'justify-center'"
          :title="sidebarExpanded ? '' : '返回首页'"
          aria-label="返回首页"
        >
          <ListFilter :size="14" />
          <span v-if="sidebarExpanded">返回首页</span>
        </RouterLink>
      </div>
    </aside>

    <main class="min-h-screen min-w-0 flex-1 transition-[margin] duration-300 ease-out lg:ml-[var(--sidebar-width)]">
      <header class="sticky top-0 z-50 flex items-center justify-between gap-4 border-b border-cyber-border/70 bg-[#f7f1e8] px-6 py-4 md:px-8">
        <div class="flex min-w-0 flex-1 items-center gap-3">
          <button
            type="button"
            class="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-cyber-border/70 bg-white/80 text-stone-700 transition hover:border-cyber-accent/40 hover:text-cyber-accent-strong"
            :aria-label="toggleLabel"
            :title="toggleLabel"
            @click="toggleSidebar"
          >
            <component :is="toggleIcon" :size="16" />
          </button>
          <div class="min-w-0">
            <p class="text-[11px] tracking-[0.18em] text-cyber-muted">后台导航</p>
            <p class="truncate text-sm font-medium text-stone-800">{{ currentPageName }}</p>
          </div>
        </div>
        <div class="flex flex-wrap items-center gap-4 md:gap-6">
          <slot name="header-extra"></slot>
        </div>
      </header>

      <div class="min-w-0 px-6 py-6 md:px-8 md:py-8">
        <slot></slot>
      </div>
    </main>
  </div>
</template>
