import { createRouter, createWebHistory } from 'vue-router'

const HomePage = () => import('@/features/home/pages/HomePage.vue')
const AdminPage = () => import('@/features/dashboard/pages/AdminPage.vue')
const AdminSitesPage = () => import('@/features/sites/pages/AdminSitesPage.vue')
const AdminCertificatesPage = () =>
  import('@/features/certificates/pages/AdminCertificatesPage.vue')
const AdminRulesPage = () => import('@/features/rules/pages/AdminRulesPage.vue')
const AdminRuleSiteActionPage = () =>
  import('@/features/rules/pages/AdminRuleSiteActionPage.vue')
const AdminActionsPage = () =>
  import('@/features/actions/pages/AdminActionsPage.vue')
const AdminL4Page = () => import('@/features/l4/pages/AdminL4Page.vue')
const AdminL7Page = () => import('@/features/l7/pages/AdminL7Page.vue')
const AdminL7RulesPage = () =>
  import('@/features/rules/pages/AdminL7RulesPage.vue')
const AdminL4RulesPage = () =>
  import('@/features/rules/pages/AdminL4RulesPage.vue')
const AdminEventsPage = () =>
  import('@/features/events/pages/AdminEventsPage.vue')
const AdminBehaviorPage = () =>
  import('@/features/behavior/pages/AdminBehaviorPage.vue')
const AdminIntelligencePage = () =>
  import('@/features/behavior/pages/AdminIntelligencePage.vue')
const AdminBlockedPage = () =>
  import('@/features/blocked/pages/AdminBlockedPage.vue')
const AdminSettingsPage = () =>
  import('@/features/settings/pages/AdminSettingsPage.vue')

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
      path: '/admin/sites',
      name: 'admin-sites',
      component: AdminSitesPage,
    },
    {
      path: '/admin/global-settings',
      name: 'admin-global-settings',
      redirect: '/admin/settings',
    },
    {
      path: '/admin/certificates',
      name: 'admin-certificates',
      component: AdminCertificatesPage,
    },
    {
      path: '/admin/rules',
      name: 'admin-rules',
      component: AdminRulesPage,
    },
    {
      path: '/admin/rules/sites/:id/action',
      name: 'admin-rule-site-action',
      component: AdminRuleSiteActionPage,
    },
    {
      path: '/admin/actions',
      name: 'admin-actions',
      component: AdminActionsPage,
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
      path: '/admin/events',
      name: 'admin-events',
      component: AdminEventsPage,
    },
    {
      path: '/admin/behavior',
      name: 'admin-behavior',
      component: AdminBehaviorPage,
    },
    {
      path: '/admin/intelligence',
      name: 'admin-intelligence',
      component: AdminIntelligencePage,
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
