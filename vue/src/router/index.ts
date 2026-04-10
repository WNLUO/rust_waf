import { createRouter, createWebHistory } from 'vue-router'
import HomePage from '../pages/HomePage.vue'
import AdminPage from '../pages/AdminPage.vue'
import AdminRulesPage from '../pages/AdminRulesPage.vue'
import AdminL4Page from '../pages/AdminL4Page.vue'
import AdminL7Page from '../pages/AdminL7Page.vue'
import AdminL7RulesPage from '../pages/AdminL7RulesPage.vue'
import AdminL4RulesPage from '../pages/AdminL4RulesPage.vue'
import AdminL4BlocklistPage from '../pages/AdminL4BlocklistPage.vue'
import AdminL4PortsPage from '../pages/AdminL4PortsPage.vue'
import AdminEventsPage from '../pages/AdminEventsPage.vue'
import AdminBlockedPage from '../pages/AdminBlockedPage.vue'
import AdminSettingsPage from '../pages/AdminSettingsPage.vue'
import AdminSafeLinePage from '../pages/AdminSafeLinePage.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      name: 'home',
      component: HomePage,
    },
    {
      path: '/admin',
      name: 'admin',
      component: AdminPage,
    },
    {
      path: '/admin/rules',
      name: 'admin-rules',
      component: AdminRulesPage,
    },
    {
      path: '/admin/l4',
      name: 'admin-l4',
      component: AdminL4Page,
    },
    {
      path: '/admin/l7',
      name: 'admin-l7',
      component: AdminL7Page,
    },
    {
      path: '/admin/l7/rules',
      name: 'admin-l7-rules',
      component: AdminL7RulesPage,
    },
    {
      path: '/admin/l4/rules',
      name: 'admin-l4-rules',
      component: AdminL4RulesPage,
    },
    {
      path: '/admin/l4/blocklist',
      name: 'admin-l4-blocklist',
      component: AdminL4BlocklistPage,
    },
    {
      path: '/admin/l4/ports',
      name: 'admin-l4-ports',
      component: AdminL4PortsPage,
    },
    {
      path: '/admin/events',
      name: 'admin-events',
      component: AdminEventsPage,
    },
    {
      path: '/admin/blocked',
      name: 'admin-blocked',
      component: AdminBlockedPage,
    },
    {
      path: '/admin/settings',
      name: 'admin-settings',
      component: AdminSettingsPage,
    },
    {
      path: '/admin/safeline',
      name: 'admin-safeline',
      component: AdminSafeLinePage,
    },
  ],
  scrollBehavior() {
    return { top: 0 }
  },
})

export default router
