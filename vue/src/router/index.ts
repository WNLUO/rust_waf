import { createRouter, createWebHistory } from 'vue-router'
import HomePage from '../pages/HomePage.vue'
import AdminPage from '../pages/AdminPage.vue'

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
      component: AdminPage,
    },
    {
      path: '/admin/events',
      name: 'admin-events',
      component: AdminPage,
    },
    {
      path: '/admin/blocked',
      name: 'admin-blocked',
      component: AdminPage,
    },
  ],
  scrollBehavior() {
    return { top: 0 }
  },
})

export default router
