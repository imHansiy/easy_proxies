import { createRouter, createWebHistory } from 'vue-router'
import LoginView from '../views/LoginView.vue'
import MainLayout from '../layouts/MainLayout.vue'
import MonitorView from '../views/MonitorView.vue'
import ManageView from '../views/ManageView.vue'
import DebugView from '../views/DebugView.vue'
import { useAuth } from '../composables/useAuth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: LoginView,
    },
    {
      path: '/',
      component: MainLayout,
      meta: { requiresAuth: true },
      children: [
        { path: '', redirect: '/monitor' },
        {
          path: '/monitor',
          name: 'monitor',
          component: MonitorView,
          meta: { requiresAuth: true },
        },
        {
          path: '/manage',
          name: 'manage',
          component: ManageView,
          meta: { requiresAuth: true },
        },
        {
          path: '/debug',
          name: 'debug',
          component: DebugView,
          meta: { requiresAuth: true },
        },
      ],
    },
  ],
})

router.beforeEach(async (to) => {
  const auth = useAuth()

  if (to.meta.requiresAuth) {
    const ok = await auth.check()
    if (!ok) {
      return {
        name: 'login',
        query: { redirect: to.fullPath },
      }
    }
    return true
  }

  if (to.name === 'login') {
    const ok = await auth.check()
    if (ok) {
      return { name: 'monitor' }
    }
  }

  return true
})

export default router
