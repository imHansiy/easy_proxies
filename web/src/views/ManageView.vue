<script setup lang="ts">
import { onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  addSubscription,
  createScriptSource,
  createConfigNode,
  deleteConfigNode,
  deleteScriptSource,
  deleteSubscription,
  getSettings,
  listConfigNodes,
  listScriptSources,
  listSubscriptions,
  refreshAllSubscriptions,
  refreshSubscription,
  runScriptSource,
  saveSettings,
  subscriptionLogs,
  testScriptSource,
  triggerReload,
  updateConfigNode,
  updateScriptSource,
  updateSubscription,
} from '../api/client'
import type { ConfigNode, ScriptRunResult, ScriptSource, SettingsPayload, SubscriptionItem, SubscriptionLog } from '../types/api'
import RuntimeConfigEditor from '../components/RuntimeConfigEditor.vue'
import PoolManager from '../components/PoolManager.vue'

const loading = reactive({
  settings: false,
  nodes: false,
  subscriptions: false,
  scripts: false,
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

function isReadonlyNode(node: ConfigNode) {
  const src = String(node.source || '').toLowerCase()
  return src === 'subscription' || src === 'script'
}

const subscriptions = ref<SubscriptionItem[]>([])
const subscriptionInput = ref('')
const subscriptionLogsVisible = ref(false)
const logTitle = ref('')
const logs = ref<SubscriptionLog[]>([])

const scriptSourcesSupported = ref(true)
const scriptSources = ref<ScriptSource[]>([])

const defaultScriptTemplate = `#!/bin/sh
# easy-proxies Script Source Template
#
# Rules:
# - The program may pass a JSON object to stdin (optional)
# - Print ONLY JSON to stdout (no logs)
# - Print logs to stderr (recommended)

INPUT="$(cat)"

echo "script source running (id=$EP_SOURCE_ID name=$EP_SOURCE_NAME)" >&2
BYTES=$(printf %s "$INPUT" | wc -c | tr -d ' ')
echo "stdin bytes: $BYTES" >&2

# TODO: replace with your own logic.
cat <<'JSON'
{
  "nodes": [
    "socks5://user:pass@127.0.0.1:1080#Example-SOCKS",
    {
      "name": "Example-HTTP",
      "uri": "http://user:pass@127.0.0.1:8080#Example-HTTP",
      "region": "jp",
      "country": "Japan"
    }
  ]
}
JSON
`

const pythonScriptTemplate = `#!/usr/bin/env python3
#
# Tip:
# - If you need third-party libs, add them in "Python requirements" (pip).
#   Example requirement: requests
#   Example usage (after adding):
#     import requests
#     print(requests.get("https://example.com").status_code, file=sys.stderr)

import json
import os
import sys

raw = sys.stdin.read() or "{}"
try:
    inp = json.loads(raw)
except Exception:
    inp = {"_raw": raw}

print(f"script source running (id={os.getenv('EP_SOURCE_ID')} name={os.getenv('EP_SOURCE_NAME')})", file=sys.stderr)
print(f"stdin keys: {list(inp.keys())}", file=sys.stderr)

out = {
    "nodes": [
        "socks5://user:pass@127.0.0.1:1080#Example-SOCKS",
        {
            "name": "Example-HTTP",
            "uri": "http://user:pass@127.0.0.1:8080#Example-HTTP",
            "region": "jp",
            "country": "Japan",
        },
    ]
}
sys.stdout.write(json.dumps(out, ensure_ascii=True))
`

const scriptDialog = reactive({
  visible: false,
  editingId: '',
  form: {
    name: '',
    command: 'sh',
    args: '',
    timeout_ms: 15000,
    setup_timeout_ms: 60000,
    max_output_bytes: 262144,
    max_nodes: 2000,
    enabled: true,
    python_requirements: '',
    script: '',
  },
})

function fillScriptTemplate(kind: 'sh' | 'python') {
  if (kind === 'python') {
    scriptDialog.form.command = 'python3'
    scriptDialog.form.args = ''
    scriptDialog.form.setup_timeout_ms = 60000
    scriptDialog.form.python_requirements = ''
    scriptDialog.form.script = pythonScriptTemplate
    return
  }
  scriptDialog.form.command = 'sh'
  scriptDialog.form.args = ''
  scriptDialog.form.python_requirements = ''
  scriptDialog.form.script = defaultScriptTemplate
}

const scriptRunDialog = reactive({
  visible: false,
  source: null as ScriptSource | null,
  apply: true,
  running: false,
  result: null as ScriptRunResult | null,
})

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

function normalizeAxiosError(error: any): string {
  return error?.response?.data?.error || error?.message || '请求失败'
}

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

async function loadScriptSources() {
  if (!scriptSourcesSupported.value) return
  loading.scripts = true
  try {
    scriptSources.value = await listScriptSources()
    scriptSourcesSupported.value = true
  } catch (error: any) {
    const msg = normalizeAxiosError(error)
    if (String(msg).includes('未启用')) {
      scriptSourcesSupported.value = false
      scriptSources.value = []
    } else {
      ElMessage.error(msg || '加载脚本源失败')
    }
  } finally {
    loading.scripts = false
  }
}

function openCreateScriptSource() {
  scriptDialog.visible = true
  scriptDialog.editingId = ''
  scriptDialog.form = {
    name: '',
    command: 'sh',
    args: '',
    timeout_ms: 15000,
    setup_timeout_ms: 60000,
    max_output_bytes: 262144,
    max_nodes: 2000,
    enabled: true,
    python_requirements: '',
    script: defaultScriptTemplate,
  }
}

function openEditScriptSource(src: ScriptSource) {
  scriptDialog.visible = true
  scriptDialog.editingId = src.id
  scriptDialog.form = {
    name: src.name,
    command: src.command,
    args: (src.args || []).join(' '),
    timeout_ms: Number(src.timeout_ms || 15000),
    setup_timeout_ms: Number(src.setup_timeout_ms || 60000),
    max_output_bytes: Number(src.max_output_bytes || 262144),
    max_nodes: Number(src.max_nodes || 2000),
    enabled: !!src.enabled,
    python_requirements: (src.python_requirements || []).join('\n'),
    script: src.script || '',
  }
}

function parseRequirements(text: string): string[] {
  return String(text || '')
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean)
}

function parseArgs(text: string): string[] {
  return String(text || '')
    .split(/\s+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

async function saveScriptSourceAction() {
  const payload = {
    name: scriptDialog.form.name.trim(),
    command: scriptDialog.form.command.trim(),
    args: parseArgs(scriptDialog.form.args),
    timeout_ms: Number(scriptDialog.form.timeout_ms || 0),
    setup_timeout_ms: Number(scriptDialog.form.setup_timeout_ms || 0),
    max_output_bytes: Number(scriptDialog.form.max_output_bytes || 0),
    max_nodes: Number(scriptDialog.form.max_nodes || 0),
    enabled: !!scriptDialog.form.enabled,
    python_requirements: parseRequirements(scriptDialog.form.python_requirements),
    script: scriptDialog.form.script,
  }
  try {
    if (scriptDialog.editingId) {
      await updateScriptSource(scriptDialog.editingId, payload)
      ElMessage.success('脚本源已更新')
    } else {
      await createScriptSource(payload)
      ElMessage.success('脚本源已创建')
    }
    scriptDialog.visible = false
    await loadScriptSources()
  } catch (error: any) {
    ElMessage.error(normalizeAxiosError(error) || '保存脚本源失败')
  }
}

async function removeScriptSourceAction(src: ScriptSource) {
  await ElMessageBox.confirm(
    `确认删除脚本源 ${src.name}？\n（将同时从配置中移除该脚本源生成的节点，需重载生效）`,
    '确认删除',
    { type: 'warning' },
  )
  try {
    await deleteScriptSource(src.id)
    ElMessage.success('脚本源已删除')
    await loadScriptSources()
    await loadNodes()
  } catch (error: any) {
    ElMessage.error(normalizeAxiosError(error) || '删除脚本源失败')
  }
}

function openRunScriptDialog(src: ScriptSource, apply = true) {
  scriptRunDialog.visible = true
  scriptRunDialog.source = src
  scriptRunDialog.apply = apply
  scriptRunDialog.result = null
}

async function runScriptSourceAction() {
  if (!scriptRunDialog.source) return
  scriptRunDialog.running = true
  try {
    const res = await runScriptSource(scriptRunDialog.source.id, scriptRunDialog.apply)
    scriptRunDialog.result = res
    if (res?.error) {
      ElMessage.error(res.error)
    } else {
      ElMessage.success(scriptRunDialog.apply ? '脚本运行并导入成功' : '脚本预览成功')
    }
    if (scriptRunDialog.apply && !res?.error) {
      await loadNodes()
    }
  } catch (error: any) {
    ElMessage.error(normalizeAxiosError(error) || '运行脚本失败')
  } finally {
    scriptRunDialog.running = false
  }
}

async function testCurrentScriptInDialog() {
  scriptRunDialog.running = true
  try {
    const res = await testScriptSource({
      name: scriptDialog.form.name,
      command: scriptDialog.form.command,
      args: parseArgs(scriptDialog.form.args),
      timeout_ms: Number(scriptDialog.form.timeout_ms || 0),
      setup_timeout_ms: Number(scriptDialog.form.setup_timeout_ms || 0),
      max_output_bytes: Number(scriptDialog.form.max_output_bytes || 0),
      max_nodes: Number(scriptDialog.form.max_nodes || 0),
      python_requirements: parseRequirements(scriptDialog.form.python_requirements),
      enabled: !!scriptDialog.form.enabled,
      script: scriptDialog.form.script,
    })
    scriptRunDialog.visible = true
    scriptRunDialog.source = null
    scriptRunDialog.apply = false
    scriptRunDialog.result = res
    if (res?.error) {
      ElMessage.error(res.error)
    } else {
      ElMessage.success('测试成功')
    }
  } catch (error: any) {
    ElMessage.error(normalizeAxiosError(error) || '测试失败')
  } finally {
    scriptRunDialog.running = false
  }
}

function openCreateNode() {
  nodeDialog.visible = true
  nodeDialog.editingName = ''
  nodeDialog.form = { name: '', uri: '', port: 0 }
}

function openEditNode(node: ConfigNode) {
  if (isReadonlyNode(node)) {
    ElMessage.warning('该节点为只读，请在对应来源中更新')
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
  if (isReadonlyNode(node)) {
    ElMessage.warning('该节点为只读，请在对应来源中更新')
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
  await Promise.all([loadSettings(), loadNodes(), loadSubscriptions(), loadScriptSources()])
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
          显示全部节点（含订阅/脚本节点）；来源为 subscription/script 的节点仅可在对应来源中维护。
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
              <template v-if="isReadonlyNode(scope.row)">
                <span class="muted">只读节点</span>
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

      <el-tab-pane label="脚本源" name="scripts">
        <div class="card-title" style="margin-bottom:10px;">
          <h3>脚本源</h3>
          <el-space>
            <el-button :loading="loading.scripts" @click="loadScriptSources">刷新</el-button>
            <el-button type="primary" :disabled="!scriptSourcesSupported" @click="openCreateScriptSource">新增脚本源</el-button>
          </el-space>
        </div>

        <el-alert
          v-if="!scriptSourcesSupported"
          type="info"
          show-icon
          :closable="false"
          title="脚本源管理未启用"
          description="需要启用数据库存储（storage）后才能使用脚本源功能。"
        />

        <template v-else>
          <div class="muted" style="margin-bottom:8px;">
            脚本需在 stdout 输出 JSON，例如：{"nodes":["vless://...", {"name":"xx","uri":"..."}]}；日志请输出到 stderr。
          </div>
          <el-table v-loading="loading.scripts" :data="scriptSources" border stripe>
            <el-table-column prop="name" label="名称" min-width="160" />
            <el-table-column prop="command" label="命令" min-width="160" />
            <el-table-column prop="enabled" label="启用" width="90">
              <template #default="scope">
                <el-tag :type="scope.row.enabled ? 'success' : 'info'">{{ scope.row.enabled ? 'ON' : 'OFF' }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="操作" width="360" fixed="right">
              <template #default="scope">
                <el-space wrap>
                  <el-button size="small" @click="openEditScriptSource(scope.row)">编辑</el-button>
                  <el-button size="small" type="primary" plain @click="openRunScriptDialog(scope.row, true)">运行并导入</el-button>
                  <el-button size="small" @click="openRunScriptDialog(scope.row, false)">预览</el-button>
                  <el-button size="small" type="danger" plain @click="removeScriptSourceAction(scope.row)">删除</el-button>
                </el-space>
              </template>
            </el-table-column>
          </el-table>
        </template>
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

    <el-dialog v-model="scriptDialog.visible" :title="scriptDialog.editingId ? '编辑脚本源' : '新增脚本源'" width="900px">
      <el-form label-position="top">
        <el-row :gutter="12">
          <el-col :xs="24" :md="8"><el-form-item label="名称"><el-input v-model="scriptDialog.form.name" /></el-form-item></el-col>
          <el-col :xs="24" :md="8"><el-form-item label="命令"><el-input v-model="scriptDialog.form.command" placeholder="python3 / node / bash" /></el-form-item></el-col>
          <el-col :xs="24" :md="8"><el-form-item label="参数"><el-input v-model="scriptDialog.form.args" placeholder="-u" /></el-form-item></el-col>
        </el-row>

        <el-space style="margin:0 0 10px 0;">
          <span class="muted">模板：</span>
          <el-button size="small" @click="fillScriptTemplate('sh')">Shell</el-button>
          <el-button size="small" @click="fillScriptTemplate('python')">Python</el-button>
        </el-space>
        <el-row :gutter="12">
          <el-col :xs="12" :md="6">
            <el-form-item label="超时(ms)">
              <el-input-number v-model="scriptDialog.form.timeout_ms" :min="100" :max="300000" style="width:100%;" />
            </el-form-item>
          </el-col>
          <el-col :xs="12" :md="6">
            <el-form-item label="依赖安装超时(ms)">
              <el-input-number v-model="scriptDialog.form.setup_timeout_ms" :min="1000" :max="600000" style="width:100%;" />
            </el-form-item>
          </el-col>
          <el-col :xs="12" :md="6">
            <el-form-item label="输出上限(bytes)">
              <el-input-number v-model="scriptDialog.form.max_output_bytes" :min="1024" :max="4194304" style="width:100%;" />
            </el-form-item>
          </el-col>
          <el-col :xs="12" :md="6">
            <el-form-item label="节点上限">
              <el-input-number v-model="scriptDialog.form.max_nodes" :min="1" :max="20000" style="width:100%;" />
            </el-form-item>
          </el-col>
          <el-col :xs="12" :md="6"><el-form-item label="启用"><el-switch v-model="scriptDialog.form.enabled" /></el-form-item></el-col>
        </el-row>

        <el-form-item label="Python 第三方依赖（每行一个 pip requirement，可选）">
          <el-input v-model="scriptDialog.form.python_requirements" type="textarea" :rows="4" placeholder="requests\npytz==2024.1" />
          <div class="muted" style="margin-top:6px;">
            当 command 是 python/python3 时会自动创建 venv 并安装依赖（带缓存）。如无需依赖可留空。
          </div>
        </el-form-item>

        <el-form-item label="脚本内容">
          <el-input v-model="scriptDialog.form.script" type="textarea" :rows="14" placeholder="# write to stdout JSON" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="scriptDialog.visible = false">取消</el-button>
        <el-button :loading="scriptRunDialog.running" @click="testCurrentScriptInDialog">测试脚本</el-button>
        <el-button type="primary" @click="saveScriptSourceAction">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="scriptRunDialog.visible" width="960px" :title="scriptRunDialog.source ? `运行脚本源：${scriptRunDialog.source.name}` : '运行脚本源'">
      <el-space style="margin-bottom:10px;">
        <el-switch v-model="scriptRunDialog.apply" active-text="导入并应用" inactive-text="仅预览" />
        <el-button type="primary" :loading="scriptRunDialog.running" @click="runScriptSourceAction">运行</el-button>
      </el-space>

      <el-empty v-if="!scriptRunDialog.result" description="点击运行查看输出" />

      <template v-else>
        <div class="muted" style="margin-bottom:8px;">
          exit={{ scriptRunDialog.result.exit_code }} · {{ scriptRunDialog.result.duration_ms }}ms · applied={{ scriptRunDialog.result.applied }}
          <span v-if="scriptRunDialog.result.timed_out"> · timeout</span>
        </div>
        <el-tabs type="border-card">
          <el-tab-pane label="输出">
            <el-form label-position="top">
              <el-form-item label="stdout">
                <el-input :model-value="scriptRunDialog.result.stdout" type="textarea" :rows="8" readonly />
              </el-form-item>
              <el-form-item label="stderr">
                <el-input :model-value="scriptRunDialog.result.stderr" type="textarea" :rows="6" readonly />
              </el-form-item>
              <el-alert v-if="scriptRunDialog.result.error" type="error" show-icon :closable="false" :title="scriptRunDialog.result.error" />
            </el-form>
          </el-tab-pane>
          <el-tab-pane label="节点预览">
            <el-table :data="scriptRunDialog.result.nodes || []" border stripe>
              <el-table-column prop="name" label="名称" min-width="180" />
              <el-table-column prop="uri" label="URI" min-width="360" show-overflow-tooltip>
                <template #default="scope"><span class="monospace">{{ scope.row.uri }}</span></template>
              </el-table-column>
              <el-table-column prop="region" label="Region" width="120" />
              <el-table-column prop="country" label="Country" width="160" />
            </el-table>
          </el-tab-pane>
        </el-tabs>
      </template>

      <template #footer>
        <el-button @click="scriptRunDialog.visible = false">关闭</el-button>
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
