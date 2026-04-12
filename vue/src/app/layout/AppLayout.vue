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
  AppWindow,
  Sparkles,
  KeyRound,
  ChevronDown,
} from 'lucide-vue-next'
import {
  clearAdminApiToken,
  getAdminApiToken,
  setAdminApiToken,
} from '@/shared/api/auth'

interface NavItem {
  name: string
  path?: string
  icon: unknown
  children?: Array<{
    name: string
    path: string
    icon?: unknown
  }>
}

const navItems: NavItem[] = [
  { name: '总览', path: '/admin', icon: LayoutDashboard },
  {
    name: '站点管理',
    icon: AppWindow,
    children: [
      { name: '站点管理', path: '/admin/sites' },
      { name: '全局设置', path: '/admin/global-settings' },
      { name: '证书管理', path: '/admin/certificates' },
    ],
  },
  { name: '规则中心', path: '/admin/rules', icon: Shield },
  { name: '动作中心', path: '/admin/actions', icon: Sparkles },
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
const authPanelOpen = ref(false)
const adminTokenDraft = ref('')

const isRouteActive = (path: string) => {
  if (path === '/admin') return route.path === '/admin'
  return route.path === path || route.path.startsWith(`${path}/`)
}

const isNavItemActive = (item: NavItem) => {
  if (item.path) return isRouteActive(item.path)
  return item.children?.some((child) => isRouteActive(child.path)) ?? false
}

const createInitialNavGroupState = () =>
  Object.fromEntries(
    navItems
      .filter((item) => item.children?.length)
      .map((item) => [item.name, isNavItemActive(item)]),
  )

const navGroupExpanded = ref<Record<string, boolean>>(createInitialNavGroupState())

const isNavGroupExpanded = (item: NavItem) => {
  if (!item.children?.length) return false
  return navGroupExpanded.value[item.name] ?? isNavItemActive(item)
}

const expandActiveNavGroups = () => {
  const nextState = { ...navGroupExpanded.value }
  let changed = false

  for (const item of navItems) {
    if (!item.children?.length || !isNavItemActive(item) || nextState[item.name]) {
      continue
    }

    nextState[item.name] = true
    changed = true
  }

  if (changed) {
    navGroupExpanded.value = nextState
  }
}

const toggleNavGroup = (item: NavItem) => {
  if (!item.children?.length) return

  navGroupExpanded.value = {
    ...navGroupExpanded.value,
    [item.name]: !isNavGroupExpanded(item),
  }
}

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
const sidebarExpanded = computed(
  () => !isDesktop.value || !desktopCollapsed.value,
)
const currentPageName = computed(
  () =>
    navItems
      .flatMap((item) =>
        item.children?.length
          ? item.children.map((child) => ({ name: child.name, path: child.path }))
          : item.path
            ? [{ name: item.name, path: item.path }]
            : [],
      )
      .find((item) => isRouteActive(item.path))?.name ?? '控制台',
)
const sidebarWidth = computed(() => (desktopCollapsed.value ? '4rem' : '12rem'))
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
  desktopCollapsed.value =
    window.localStorage.getItem(SIDEBAR_STORAGE_KEY) === 'true'
  adminTokenDraft.value = getAdminApiToken()
  expandActiveNavGroups()
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
    authPanelOpen.value = false
    expandActiveNavGroups()
  },
)

const saveAdminToken = () => {
  setAdminApiToken(adminTokenDraft.value)
  authPanelOpen.value = false
}

const clearToken = () => {
  clearAdminApiToken()
  adminTokenDraft.value = ''
}
</script>

<template>
  <div
    class="min-h-screen bg-slate-50 text-slate-900 lg:flex"
    :style="layoutStyle"
  >
    <aside
      class="bg-white transition-[width] duration-300 ease-in-out lg:fixed lg:inset-y-0 lg:left-0 lg:z-40 lg:flex lg:w-[var(--sidebar-width)] lg:flex-col lg:border-r lg:border-slate-200"
    >
      <div
        class="flex h-14 shrink-0 items-center gap-3 border-b border-slate-200 px-4 transition-[padding] duration-300"
        :class="sidebarExpanded ? 'justify-start' : 'lg:justify-center lg:px-0'"
      >
        <div
          class="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-blue-600 text-white shadow-sm"
        >
          <Cpu :size="18" />
        </div>
        <div
          v-if="sidebarExpanded"
          class="min-w-0 overflow-hidden whitespace-nowrap"
        >
          <h1 class="text-sm font-semibold tracking-tight text-slate-900">
            安全网关控制台
          </h1>
        </div>
      </div>

      <nav
        v-show="shouldShowNav"
        class="flex-1 overflow-y-auto overflow-x-hidden p-3 space-y-1"
      >
        <div v-for="item in navItems" :key="item.path || item.name" class="space-y-1">
          <RouterLink
            v-if="item.path"
            :to="item.path"
            class="flex items-center rounded-md transition-colors duration-150"
            :title="sidebarExpanded ? '' : item.name"
            :aria-label="item.name"
            :class="[
              sidebarExpanded ? 'gap-3 px-3 py-2' : 'justify-center p-2',
              isNavItemActive(item)
                ? 'bg-blue-50 text-blue-700 font-medium'
                : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900',
            ]"
          >
            <component :is="item.icon" :size="20" class="shrink-0" />
            <span v-if="sidebarExpanded" class="truncate text-sm">{{
              item.name
            }}</span>
          </RouterLink>

          <RouterLink
            v-else-if="!sidebarExpanded"
            :to="item.children?.find((child) => isRouteActive(child.path))?.path || item.children?.[0]?.path || '/admin/sites'"
            class="flex items-center rounded-md transition-colors duration-150"
            :title="item.name"
            :aria-label="item.name"
            :class="[
              'justify-center p-2',
              isNavItemActive(item)
                ? 'bg-blue-50 text-blue-700 font-medium'
                : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900',
            ]"
          >
            <component :is="item.icon" :size="20" class="shrink-0" />
          </RouterLink>

          <div
            v-else
            class="rounded-md"
            :class="
              isNavItemActive(item) && isNavGroupExpanded(item)
                ? 'bg-slate-50'
                : ''
            "
          >
            <button
              type="button"
              class="flex w-full items-center rounded-md transition-colors duration-150 hover:bg-slate-100 hover:text-slate-900"
              :aria-expanded="isNavGroupExpanded(item)"
              :aria-controls="`nav-group-${item.name}`"
              :class="[
                sidebarExpanded ? 'gap-3 px-3 py-2' : 'justify-center p-2',
                isNavItemActive(item)
                  ? 'text-blue-700 font-medium'
                  : 'text-slate-600',
              ]"
              @click="toggleNavGroup(item)"
            >
              <component :is="item.icon" :size="20" class="shrink-0" />
              <template v-if="sidebarExpanded">
                <span class="truncate text-sm">{{ item.name }}</span>
                <ChevronDown
                  :size="16"
                  class="ml-auto shrink-0 text-slate-400 transition-transform duration-200"
                  :class="isNavGroupExpanded(item) ? 'rotate-180' : ''"
                />
              </template>
            </button>

            <div
              v-if="sidebarExpanded && isNavGroupExpanded(item)"
              :id="`nav-group-${item.name}`"
              class="mt-1 space-y-1 px-2 pb-2"
            >
              <RouterLink
                v-for="child in item.children"
                :key="child.path"
                :to="child.path"
                class="flex items-center rounded-md px-3 py-2 text-sm transition-colors duration-150"
                :class="
                  isRouteActive(child.path)
                    ? 'bg-blue-50 font-medium text-blue-700'
                    : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                "
              >
                <span class="truncate">{{ child.name }}</span>
              </RouterLink>
            </div>
          </div>
        </div>
      </nav>

      <div
        v-show="shouldShowNav"
        class="shrink-0 border-t border-slate-200 p-3"
      >
        <RouterLink
          to="/"
          class="flex items-center rounded-md text-sm text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-900"
          :class="sidebarExpanded ? 'gap-3 px-3 py-2' : 'justify-center p-2'"
          :title="sidebarExpanded ? '' : '返回首页'"
          aria-label="返回首页"
        >
          <ListFilter :size="20" class="shrink-0" />
          <span v-if="sidebarExpanded" class="truncate">返回首页</span>
        </RouterLink>
      </div>
    </aside>

    <main
      class="flex min-h-screen min-w-0 flex-1 flex-col transition-[margin] duration-300 ease-in-out lg:ml-[var(--sidebar-width)]"
    >
      <header
        class="sticky top-0 z-30 flex h-14 shrink-0 items-center justify-between gap-4 border-b border-slate-200 bg-white px-4 sm:px-6 lg:px-8"
      >
        <div class="flex items-center gap-4">
          <button
            type="button"
            class="text-slate-500 hover:text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 rounded-md"
            :aria-label="toggleLabel"
            :title="toggleLabel"
            @click="toggleSidebar"
          >
            <component :is="toggleIcon" :size="20" />
          </button>
          <h2 class="text-sm font-semibold text-slate-900 sm:text-base">
            {{ currentPageName }}
          </h2>
        </div>
        <div class="flex items-center gap-4">
          <div class="relative">
            <button
              type="button"
              class="inline-flex items-center gap-2 rounded-md border border-slate-200 px-3 py-1.5 text-xs text-slate-600 transition hover:border-blue-300 hover:text-blue-700"
              @click="authPanelOpen = !authPanelOpen"
            >
              <KeyRound :size="14" />
              API 令牌
            </button>
            <div
              v-if="authPanelOpen"
              class="absolute right-0 top-11 z-40 w-72 rounded-xl border border-slate-200 bg-white p-4 shadow-xl"
            >
              <p class="text-sm font-medium text-slate-900">管理 API Bearer Token</p>
              <p class="mt-2 text-xs leading-6 text-slate-500">
                令牌仅保存在当前浏览器本地存储中，用于访问受保护的管理接口。
              </p>
              <input
                v-model="adminTokenDraft"
                type="password"
                class="mt-3 w-full rounded-lg border border-slate-200 px-3 py-2 text-sm outline-none transition focus:border-blue-500"
                placeholder="输入 Bearer Token"
              />
              <div class="mt-3 flex items-center justify-end gap-2">
                <button
                  type="button"
                  class="rounded-md px-3 py-1.5 text-xs text-slate-500 transition hover:bg-slate-100"
                  @click="clearToken"
                >
                  清除
                </button>
                <button
                  type="button"
                  class="rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-blue-700"
                  @click="saveAdminToken"
                >
                  保存
                </button>
              </div>
            </div>
          </div>
          <slot name="header-extra"></slot>
        </div>
      </header>

      <div class="flex-1 p-4 sm:p-6 lg:p-6">
        <div class="mx-auto w-full">
          <slot></slot>
        </div>
      </div>
    </main>
  </div>
</template>
