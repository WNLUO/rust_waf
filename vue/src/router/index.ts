import { createRouter, createWebHistory } from 'vue-router'
import HomePage from '../pages/HomePage.vue'
import AdminPage from '../pages/AdminPage.vue'
import AdminRulesPage from '../pages/AdminRulesPage.vue'
import AdminEventsPage from '../pages/AdminEventsPage.vue'
import AdminBlockedPage from '../pages/AdminBlockedPage.vue'
import AdminSettingsPage from '../pages/AdminSettingsPage.vue'

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
  ],
  scrollBehavior() {
    return { top: 0 }
  },
})

export default router
