<script setup lang="ts">
import { onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  addSubscription,
  createConfigNode,
  deleteConfigNode,
  deleteSubscription,
  getSettings,
  listConfigNodes,
  listSubscriptions,
  refreshAllSubscriptions,
  refreshSubscription,
  saveSettings,
  subscriptionLogs,
  triggerReload,
  updateConfigNode,
  updateSubscription,
} from '../api/client'
import type { ConfigNode, SettingsPayload, SubscriptionItem, SubscriptionLog } from '../types/api'
import RuntimeConfigEditor from '../components/RuntimeConfigEditor.vue'
import PoolManager from '../components/PoolManager.vue'

const loading = reactive({
  settings: false,
  nodes: false,
  subscriptions: false,
  reload: false,
})

const activeTab = ref('nodes')

const settings = reactive<SettingsPayload>({
  external_ip: '',
  probe_target: '',
  skip_cert_verify: false,
  proxy_username: '',
  proxy_password: '',
})

const nodes = ref<ConfigNode[]>([])

function isSubscriptionNode(node: ConfigNode) {
  return String(node.source || '').toLowerCase() === 'subscription'
}

const subscriptions = ref<SubscriptionItem[]>([])
const subscriptionInput = ref('')
const subscriptionLogsVisible = ref(false)
const logTitle = ref('')
const logs = ref<SubscriptionLog[]>([])

const nodeDialog = reactive({
  visible: false,
  editingName: '',
  form: {
    name: '',
    uri: '',
    port: 0,
  },
})

let refreshListener: (() => void) | undefined

async function loadSettings() {
  loading.settings = true
  try {
    Object.assign(settings, await getSettings())
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '加载设置失败')
  } finally {
    loading.settings = false
  }
}

async function saveSettingsAction() {
  loading.settings = true
  try {
    const result = await saveSettings({ ...settings })
    ElMessage.success(result?.need_reload ? '设置已保存，请重载生效' : '设置已保存')
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '保存设置失败')
  } finally {
    loading.settings = false
  }
}

async function loadNodes() {
  loading.nodes = true
  try {
    nodes.value = await listConfigNodes()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '加载节点配置失败')
  } finally {
    loading.nodes = false
  }
}

async function loadSubscriptions() {
  loading.subscriptions = true
  try {
    const result = await listSubscriptions()
    subscriptions.value = result.items || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '加载订阅失败')
  } finally {
    loading.subscriptions = false
  }
}

function openCreateNode() {
  nodeDialog.visible = true
  nodeDialog.editingName = ''
  nodeDialog.form = { name: '', uri: '', port: 0 }
}

function openEditNode(node: ConfigNode) {
  if (isSubscriptionNode(node)) {
    ElMessage.warning('订阅节点为只读，请在订阅管理中更新')
    return
  }
  nodeDialog.visible = true
  nodeDialog.editingName = node.name
  nodeDialog.form = {
    name: node.name,
    uri: node.uri,
    port: Number(node.port || 0),
  }
}

async function saveNode() {
  if (!nodeDialog.form.uri.trim()) {
    ElMessage.warning('节点 URI 不能为空')
    return
  }

  const payload = {
    name: nodeDialog.form.name.trim(),
    uri: nodeDialog.form.uri.trim(),
    port: Number(nodeDialog.form.port || 0),
  }

  try {
    if (nodeDialog.editingName) {
      await updateConfigNode(nodeDialog.editingName, payload)
      ElMessage.success('节点已更新')
    } else {
      await createConfigNode(payload)
      ElMessage.success('节点已添加')
    }
    nodeDialog.visible = false
    await loadNodes()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '保存节点失败')
  }
}

async function removeNode(node: ConfigNode) {
  if (isSubscriptionNode(node)) {
    ElMessage.warning('订阅节点为只读，请在订阅管理中更新')
    return
  }
  await ElMessageBox.confirm(`确认删除节点 ${node.name || node.uri}？`, '确认删除', {
    type: 'warning',
  })
  try {
    await deleteConfigNode(node.name)
    ElMessage.success('节点已删除')
    await loadNodes()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '删除节点失败')
  }
}

async function addSubscriptionAction() {
  const url = subscriptionInput.value.trim()
  if (!url) {
    ElMessage.warning('请输入订阅链接')
    return
  }
  try {
    const result = await addSubscription(url)
    subscriptionInput.value = ''
    ElMessage.success(result?.message || '订阅已添加')
    await loadSubscriptions()
    await loadNodes()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '添加订阅失败')
  }
}

async function editSubscription(item: SubscriptionItem) {
  const nextURL = window.prompt('编辑订阅链接', item.url)
  if (nextURL == null) return
  const normalized = nextURL.trim()
  if (!normalized) {
    ElMessage.warning('订阅链接不能为空')
    return
  }
  try {
    const result = await updateSubscription(item.index, normalized)
    ElMessage.success(result?.message || '订阅已更新')
    await loadSubscriptions()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '更新订阅失败')
  }
}

async function removeSubscription(item: SubscriptionItem) {
  await ElMessageBox.confirm('确认删除该订阅？', '确认删除', { type: 'warning' })
  try {
    const result = await deleteSubscription(item.index)
    ElMessage.success(result?.message || '订阅已删除')
    await loadSubscriptions()
    await loadNodes()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '删除订阅失败')
  }
}

async function refreshOneSubscription(item: SubscriptionItem) {
  try {
    await refreshSubscription(item.index)
    ElMessage.success('订阅刷新成功')
    await loadNodes()
    await loadSubscriptions()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '刷新订阅失败')
  }
}

async function showLogs(item: SubscriptionItem) {
  try {
    const result = await subscriptionLogs(item.index)
    logTitle.value = result.subscription || item.url
    logs.value = result.logs || []
    subscriptionLogsVisible.value = true
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '加载订阅日志失败')
  }
}

async function refreshAllSubs() {
  try {
    const result = await refreshAllSubscriptions()
    ElMessage.success(result?.message || '订阅刷新成功')
    await loadNodes()
    await loadSubscriptions()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '刷新失败')
  }
}

async function reloadService() {
  await ElMessageBox.confirm('重载会中断现有连接，确定继续？', '重载确认', { type: 'warning' })
  loading.reload = true
  try {
    const result = await triggerReload()
    ElMessage.success(result?.message || '重载成功')
    window.dispatchEvent(new CustomEvent('ep:refresh'))
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '重载失败')
  } finally {
    loading.reload = false
  }
}

async function onGlobalRefresh() {
  await Promise.all([loadSettings(), loadNodes(), loadSubscriptions()])
}

onMounted(() => {
  onGlobalRefresh()
  refreshListener = () => {
    onGlobalRefresh()
  }
  window.addEventListener('ep:refresh', refreshListener)
})

onBeforeUnmount(() => {
  if (refreshListener) {
    window.removeEventListener('ep:refresh', refreshListener)
  }
})
</script>

<template>
  <div class="page-wrap">
    <el-card>
      <div class="card-title">
        <h3>系统设置</h3>
        <el-space>
          <el-button :loading="loading.settings" @click="loadSettings">刷新</el-button>
          <el-button type="primary" :loading="loading.settings" @click="saveSettingsAction">保存设置</el-button>
          <el-button type="warning" :loading="loading.reload" @click="reloadService">重载配置</el-button>
        </el-space>
      </div>
      <el-row :gutter="12">
        <el-col :xs="24" :md="8"><el-form-item label="外部 IP"><el-input v-model="settings.external_ip" placeholder="可选" /></el-form-item></el-col>
        <el-col :xs="24" :md="8"><el-form-item label="探测目标"><el-input v-model="settings.probe_target" placeholder="www.apple.com:80" /></el-form-item></el-col>
        <el-col :xs="24" :md="4"><el-form-item label="代理用户名"><el-input v-model="settings.proxy_username" /></el-form-item></el-col>
        <el-col :xs="24" :md="4"><el-form-item label="代理密码"><el-input v-model="settings.proxy_password" /></el-form-item></el-col>
      </el-row>
      <el-form-item label="跳过证书验证"><el-switch v-model="settings.skip_cert_verify" /></el-form-item>
    </el-card>

    <el-tabs v-model="activeTab" type="border-card">
      <el-tab-pane label="节点管理" name="nodes">
        <div class="card-title" style="margin-bottom:10px;">
          <h3>配置节点</h3>
          <el-button type="primary" @click="openCreateNode">添加节点</el-button>
        </div>
        <div class="muted" style="margin-bottom:8px;">
          显示全部节点（含订阅节点）；来源为 subscription 的节点仅可在「订阅管理」中维护。
        </div>
        <el-table v-loading="loading.nodes" :data="nodes" border stripe>
          <el-table-column prop="name" label="名称" min-width="140" />
          <el-table-column prop="node_ip" label="节点IP" min-width="150">
            <template #default="scope"><span class="monospace">{{ scope.row.node_ip || '-' }}</span></template>
          </el-table-column>
          <el-table-column prop="uri" label="URI" min-width="280">
            <template #default="scope"><span class="monospace">{{ scope.row.uri }}</span></template>
          </el-table-column>
          <el-table-column prop="port" label="端口" width="100" />
          <el-table-column prop="source" label="来源" width="120" />
          <el-table-column label="操作" width="180" fixed="right">
            <template #default="scope">
              <template v-if="isSubscriptionNode(scope.row)">
                <span class="muted">订阅节点（只读）</span>
              </template>
              <el-space v-else>
                <el-button size="small" @click="openEditNode(scope.row)">编辑</el-button>
                <el-button size="small" type="danger" plain @click="removeNode(scope.row)">删除</el-button>
              </el-space>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="订阅管理" name="subscriptions">
        <div class="card-title" style="margin-bottom:10px;">
          <h3>订阅列表</h3>
          <el-space>
            <el-button type="warning" @click="refreshAllSubs">刷新全部订阅</el-button>
          </el-space>
        </div>
        <el-row :gutter="8" style="margin-bottom:10px;">
          <el-col :span="20"><el-input v-model="subscriptionInput" placeholder="https://example.com/sub?token=..." /></el-col>
          <el-col :span="4"><el-button type="primary" style="width:100%;" @click="addSubscriptionAction">添加订阅</el-button></el-col>
        </el-row>

        <el-table v-loading="loading.subscriptions" :data="subscriptions" border stripe>
          <el-table-column prop="index" label="#" width="60" />
          <el-table-column prop="url" label="订阅链接" min-width="360" show-overflow-tooltip />
          <el-table-column prop="node_count" label="节点数" width="100" />
          <el-table-column label="操作" width="320" fixed="right">
            <template #default="scope">
              <el-space wrap>
                <el-button size="small" @click="editSubscription(scope.row)">编辑</el-button>
                <el-button size="small" type="primary" plain @click="refreshOneSubscription(scope.row)">刷新</el-button>
                <el-button size="small" @click="showLogs(scope.row)">日志</el-button>
                <el-button size="small" type="danger" plain @click="removeSubscription(scope.row)">删除</el-button>
              </el-space>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="业务池管理" name="pools">
        <PoolManager />
      </el-tab-pane>

      <el-tab-pane label="运行配置" name="runtime">
        <RuntimeConfigEditor />
      </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="nodeDialog.visible" :title="nodeDialog.editingName ? '编辑节点' : '添加节点'" width="680px">
      <el-form label-position="top">
        <el-row :gutter="12">
          <el-col :span="8"><el-form-item label="名称"><el-input v-model="nodeDialog.form.name" placeholder="可选" /></el-form-item></el-col>
          <el-col :span="16"><el-form-item label="URI"><el-input v-model="nodeDialog.form.uri" placeholder="vless://..." /></el-form-item></el-col>
          <el-col :span="8"><el-form-item label="端口（可选）"><el-input-number v-model="nodeDialog.form.port" :min="0" :max="65535" style="width:100%;" /></el-form-item></el-col>
        </el-row>
      </el-form>
      <template #footer>
        <el-button @click="nodeDialog.visible = false">取消</el-button>
        <el-button type="primary" @click="saveNode">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="subscriptionLogsVisible" width="760px" title="订阅更新日志">
      <div class="muted" style="margin-bottom:8px;">{{ logTitle }}</div>
      <el-empty v-if="logs.length === 0" description="暂无日志" />
      <el-timeline v-else>
        <el-timeline-item v-for="(log, idx) in logs.slice().reverse()" :key="idx" :timestamp="log.time">
          <strong>{{ log.level?.toUpperCase() || 'INFO' }}</strong>
          <div style="margin-top:4px;">{{ log.message }}</div>
        </el-timeline-item>
      </el-timeline>
      <template #footer>
        <el-button @click="subscriptionLogsVisible = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>
