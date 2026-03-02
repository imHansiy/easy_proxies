<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  DataAnalysis,
  SetUp,
  Tools,
  Refresh,
  Download,
  SwitchButton,
} from '@element-plus/icons-vue'
import { useAuth } from '../composables/useAuth'
import { exportNodesURL } from '../api/client'

const route = useRoute()
const router = useRouter()
const auth = useAuth()

const reloading = ref(false)
const collapsed = ref(false)

const activeMenu = computed(() => route.path)

const pageTitle = computed(() => {
  if (route.path.startsWith('/monitor')) return '节点监控中心'
  if (route.path.startsWith('/manage')) return '节点与配置管理'
  if (route.path.startsWith('/debug')) return '调试与调用分析'
  return 'Easy Proxies'
})

function navigate(path: string) {
  router.push(path)
}

function toggleCollapse() {
  collapsed.value = !collapsed.value
}

function doLogout() {
  auth.logout()
  router.replace('/login')
}

function exportNodes() {
  window.open(exportNodesURL(), '_blank')
}

function triggerRefresh() {
  reloading.value = true
  window.dispatchEvent(new CustomEvent('ep:refresh'))
  setTimeout(() => {
    reloading.value = false
  }, 600)
}
</script>

<template>
  <el-container style="min-height: 100vh; background: transparent">
    <el-aside
      :width="collapsed ? '72px' : '240px'"
      style="transition: width .25s ease; border-right: 1px solid #e5e7eb; background: rgba(255,255,255,.78); backdrop-filter: blur(12px);"
    >
      <div style="display:flex; align-items:center; justify-content:space-between; padding:14px 12px; border-bottom:1px solid #eef2f7;">
        <div v-if="!collapsed" style="font-weight:700; letter-spacing:.3px;">Easy Proxies</div>
        <el-button :icon="SetUp" text @click="toggleCollapse" />
      </div>
      <el-menu :default-active="activeMenu" :collapse="collapsed" style="border-right: none; background: transparent;" @select="navigate">
        <el-menu-item index="/monitor">
          <el-icon><DataAnalysis /></el-icon>
          <span>节点监控</span>
        </el-menu-item>
        <el-menu-item index="/manage">
          <el-icon><SetUp /></el-icon>
          <span>节点管理</span>
        </el-menu-item>
        <el-menu-item index="/debug">
          <el-icon><Tools /></el-icon>
          <span>调试面板</span>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <el-container>
      <el-header style="height: auto; padding: 14px 22px 10px; border-bottom: 1px solid #e5e7eb; background: rgba(255,255,255,.7); backdrop-filter: blur(12px);">
        <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;">
          <div>
            <div style="font-size: 18px; font-weight: 700;">{{ pageTitle }}</div>
            <div class="muted">前后端分离 UI · Vue 3 + Element Plus</div>
          </div>
          <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <el-button :icon="Refresh" :loading="reloading" @click="triggerRefresh">刷新数据</el-button>
            <el-button :icon="Download" @click="exportNodes">导出可用节点</el-button>
            <el-button type="danger" plain :icon="SwitchButton" @click="doLogout">退出登录</el-button>
          </div>
        </div>
      </el-header>

      <el-main style="padding: 18px 22px 24px;">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>
