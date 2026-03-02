<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { getDebug } from '../api/client'
import type { DebugPayload } from '../types/api'
import { formatRelativeTime } from '../utils/time'

const loading = ref(false)
const payload = ref<DebugPayload>({
  nodes: [],
  total_calls: 0,
  total_success: 0,
  success_rate: 0,
})

let timer: number | undefined

const sortedNodes = computed(() =>
  [...payload.value.nodes].sort((a, b) => {
    const ac = (a.success_count || 0) + (a.failure_count || 0)
    const bc = (b.success_count || 0) + (b.failure_count || 0)
    return bc - ac
  }),
)

async function refresh() {
  loading.value = true
  try {
    payload.value = await getDebug()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '加载调试数据失败')
  } finally {
    loading.value = false
  }
}

function rateOf(node: any): number {
  const total = Number(node.success_count || 0) + Number(node.failure_count || 0)
  if (!total) return 0
  return Math.round((Number(node.success_count || 0) / total) * 1000) / 10
}

function onGlobalRefresh() {
  refresh()
}

onMounted(() => {
  refresh()
  timer = window.setInterval(refresh, 12000)
  window.addEventListener('ep:refresh', onGlobalRefresh)
})

onBeforeUnmount(() => {
  if (timer) window.clearInterval(timer)
  window.removeEventListener('ep:refresh', onGlobalRefresh)
})
</script>

<template>
  <div class="page-wrap">
    <el-row :gutter="12">
      <el-col :xs="12" :sm="8">
        <el-card>
          <div class="muted">总调用次数</div>
          <div style="font-size:26px; font-weight:700;">{{ payload.total_calls }}</div>
        </el-card>
      </el-col>
      <el-col :xs="12" :sm="8">
        <el-card>
          <div class="muted">总成功次数</div>
          <div style="font-size:26px; font-weight:700; color:#16a34a;">{{ payload.total_success }}</div>
        </el-card>
      </el-col>
      <el-col :xs="24" :sm="8">
        <el-card>
          <div class="muted">整体成功率</div>
          <div style="font-size:26px; font-weight:700; color:#0284c7;">{{ payload.success_rate.toFixed(1) }}%</div>
        </el-card>
      </el-col>
    </el-row>

    <el-card>
      <template #header>
        <div class="card-title">
          <h3>节点调用质量</h3>
          <el-button @click="refresh">刷新</el-button>
        </div>
      </template>

      <el-table v-loading="loading" :data="sortedNodes" border stripe>
        <el-table-column prop="name" label="节点" min-width="220">
          <template #default="scope">
            <div style="display:grid; gap:2px;">
              <strong>{{ scope.row.name || scope.row.tag }}</strong>
              <span class="muted monospace">{{ scope.row.tag }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="success_count" label="成功" width="90" />
        <el-table-column prop="failure_count" label="失败" width="90" />
        <el-table-column label="成功率" width="180">
          <template #default="scope">
            <el-progress
              :percentage="rateOf(scope.row)"
              :status="rateOf(scope.row) >= 90 ? 'success' : rateOf(scope.row) >= 70 ? '' : 'exception'"
            />
          </template>
        </el-table-column>
        <el-table-column prop="active_connections" label="活跃连接" width="100" />
        <el-table-column label="最近成功" width="140">
          <template #default="scope">{{ formatRelativeTime(scope.row.last_success) }}</template>
        </el-table-column>
        <el-table-column label="最近失败" width="140">
          <template #default="scope">{{ formatRelativeTime(scope.row.last_failure) }}</template>
        </el-table-column>
        <el-table-column label="最近错误" min-width="260" show-overflow-tooltip>
          <template #default="scope">{{ scope.row.last_error || '-' }}</template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>
