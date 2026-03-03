<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Monitor, Refresh, Search } from '@element-plus/icons-vue'
import { banNode, getNodes, probeAllNodes, probeNode, releaseNode } from '../api/client'
import type { NodeSnapshot, NodesPayload, ProbeEvent } from '../types/api'
import { formatRelativeTime, latencyLabel } from '../utils/time'

const loading = ref(false)
const payload = ref<NodesPayload>({
  nodes: [],
  total_nodes: 0,
  region_stats: {},
  region_healthy: {},
})

const filters = reactive({
  keyword: '',
  region: 'all',
  pool: 'all',
})

const probeDialog = reactive({
  visible: false,
  total: 0,
  current: 0,
  success: 0,
  failed: 0,
  currentLabel: '',
})

const banning = ref(false)
const banDialog = reactive({
  visible: false,
  node_ip: '',
  pool_name: '',
  duration: '2h',
})

let timer: number | undefined

const regions = computed(() => {
  const keys = Object.keys(payload.value.region_stats || {})
  return ['all', ...keys.sort()]
})

const pools = computed(() => {
  const set = new Set<string>()
  for (const node of payload.value.nodes) {
    if (node.pool_name) set.add(node.pool_name)
  }
  return ['all', ...Array.from(set.values()).sort()]
})

const filteredNodes = computed(() => {
  const keyword = filters.keyword.trim().toLowerCase()
  return payload.value.nodes.filter((node) => {
    const realAddress = nodeRealAddress(node)
    if (filters.region !== 'all' && (node.region || 'other') !== filters.region) return false
    if (filters.pool !== 'all' && (node.pool_name || 'default') !== filters.pool) return false
    if (!keyword) return true
    return [node.tag, node.name, node.pool_name, node.region, node.country, realAddress]
      .filter(Boolean)
      .some((item) => String(item).toLowerCase().includes(keyword))
  })
})

const stats = computed(() => {
  const all = payload.value.nodes
  return {
    total: payload.value.total_nodes || all.length,
    healthy: all.filter((n) => n.initial_check_done && n.available && !n.blacklisted).length,
    active: all.reduce((sum, n) => sum + (n.active_connections || 0), 0),
    blacklisted: all.filter((n) => n.blacklisted).length,
  }
})

function statusType(node: NodeSnapshot): 'success' | 'warning' | 'danger' | 'info' {
  if (node.blacklisted) return 'danger'
  if (!node.initial_check_done) return 'info'
  if (!node.available) return 'warning'
  if (node.failure_count > 0) return 'warning'
  return 'success'
}

function statusText(node: NodeSnapshot): string {
  if (node.blacklisted) return '已拉黑'
  if (!node.initial_check_done) return '待检查'
  if (!node.available) return '不可用'
  if (node.failure_count > 0) return '警告'
  return '健康'
}

function decodeBase64Payload(payload: string): string {
  const compact = payload.trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/')
  if (!compact) return ''
  const padded = compact + '='.repeat((4 - (compact.length % 4)) % 4)
  try {
    const binary = atob(padded)
    const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0))
    return new TextDecoder().decode(bytes)
  } catch {
    return ''
  }
}

function splitHostPort(input: string): { host: string; port: string } {
  const value = input.trim()
  if (!value) return { host: '', port: '' }

  if (value.startsWith('[')) {
    const end = value.indexOf(']')
    if (end > 0) {
      const host = value.slice(1, end)
      const rest = value.slice(end + 1)
      const port = rest.startsWith(':') ? rest.slice(1) : ''
      return { host, port }
    }
  }

  const firstColon = value.indexOf(':')
  const lastColon = value.lastIndexOf(':')
  if (firstColon > 0 && firstColon === lastColon) {
    return { host: value.slice(0, lastColon), port: value.slice(lastColon + 1) }
  }

  return { host: value, port: '' }
}

function parseSSAddress(uri: string): { host: string; port: string } {
  const body = uri.slice('ss://'.length).split('#')[0] ?? ''
  if (!body) return { host: '', port: '' }

  if (body.includes('@')) {
    const afterAt = body.slice(body.lastIndexOf('@') + 1).split('?')[0] ?? ''
    return splitHostPort(afterAt)
  }

  const decoded = decodeBase64Payload(body.split('?')[0] ?? '')
  if (!decoded || !decoded.includes('@')) {
    return { host: '', port: '' }
  }
  const afterAt = decoded.slice(decoded.lastIndexOf('@') + 1)
  return splitHostPort(afterAt)
}

function parseVMessAddress(uri: string): { host: string; port: string } {
  const raw = uri.slice('vmess://'.length).split('#')[0] ?? ''
  const decoded = decodeBase64Payload(raw)
  if (!decoded) return { host: '', port: '' }

  try {
    const payload = JSON.parse(decoded) as Record<string, unknown>
    const host = String(payload.add ?? payload.host ?? '').trim()
    const port = String(payload.port ?? '').trim()
    return { host, port }
  } catch {
    return { host: '', port: '' }
  }
}

function parseSSRAddress(uri: string): { host: string; port: string } {
  const raw = uri.slice('ssr://'.length).split('#')[0] ?? ''
  const decoded = decodeBase64Payload(raw)
  if (!decoded) return { host: '', port: '' }

  const endpoint = decoded.split('/')[0] ?? ''
  const parts = endpoint.split(':')
  if (parts.length < 2) return { host: '', port: '' }
  return { host: parts[0] ?? '', port: parts[1] ?? '' }
}

function parseRelayAddress(uri: string): { host: string; port: string } {
  try {
    const parsed = new URL(uri)
    const hops = parsed.searchParams.getAll('hop')
    for (const hop of hops) {
      const decodedHop = decodeBase64Payload(hop)
      if (!decodedHop) continue
      const endpoint = parseAddressFromURI(decodedHop)
      if (endpoint.host) return endpoint
    }
  } catch {
    return { host: '', port: '' }
  }
  return { host: '', port: '' }
}

function parseAddressFromURI(uri: string): { host: string; port: string } {
  const value = uri.trim()
  if (!value) return { host: '', port: '' }

  if (value.startsWith('relay://')) return parseRelayAddress(value)
  if (value.startsWith('vmess://')) return parseVMessAddress(value)
  if (value.startsWith('ssr://')) return parseSSRAddress(value)
  if (value.startsWith('ss://')) return parseSSAddress(value)

  try {
    const parsed = new URL(value)
    return {
      host: parsed.hostname,
      port: parsed.port,
    }
  } catch {
    return { host: '', port: '' }
  }
}

function nodeRealAddress(node: NodeSnapshot): string {
  const nodeIP = String(node.node_ip || '').trim()
  if (nodeIP) return nodeIP

  const { host } = parseAddressFromURI(node.uri || '')
  if (!host) return '-'
  const ipv4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(host)
  const ipv6 = host.includes(':')
  return ipv4 || ipv6 ? host : '-'
}

async function refresh(options: { silent?: boolean } = {}) {
  const silent = options.silent === true
  if (!silent) loading.value = true
  try {
    payload.value = await getNodes()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '加载节点失败')
  } finally {
    if (!silent) loading.value = false
  }
}

async function probe(tag: string) {
  try {
    const ms = await probeNode(tag)
    ElMessage.success(`探测成功，延迟 ${ms}ms`)
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '探测失败')
  }
}

async function release(tag: string) {
  try {
    await releaseNode(tag)
    ElMessage.success('已解除拉黑')
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '解除失败')
  }
}

async function batchProbe() {
  probeDialog.visible = true
  probeDialog.total = 0
  probeDialog.current = 0
  probeDialog.success = 0
  probeDialog.failed = 0
  probeDialog.currentLabel = '准备中...'

  try {
    await probeAllNodes((evt: ProbeEvent) => {
      if (evt.type === 'start') {
        probeDialog.total = evt.total
      }
      if (evt.type === 'progress') {
        probeDialog.current = evt.current
        if (evt.error) {
          probeDialog.failed += 1
          probeDialog.currentLabel = `❌ ${evt.name}: ${evt.error}`
        } else {
          probeDialog.success += 1
          probeDialog.currentLabel = `✅ ${evt.name}: ${evt.latency ?? '-'}ms`
        }
      }
      if (evt.type === 'complete') {
        probeDialog.success = evt.success
        probeDialog.failed = evt.failed
        probeDialog.current = probeDialog.total
        probeDialog.currentLabel = `完成，成功 ${evt.success}，失败 ${evt.failed}`
      }
    })
    ElMessage.success('批量探测完成')
  } catch (error: any) {
    ElMessage.error(error?.message || '批量探测失败')
  } finally {
    await refresh()
  }
}

async function openBanDialog() {
  const nodes = payload.value.nodes
  if (nodes.length === 0) {
    ElMessage.warning('当前没有可封控节点')
    return
  }
  const firstPool = nodes[0]?.pool_name || 'default'
  banDialog.node_ip = ''
  banDialog.pool_name = firstPool
  banDialog.duration = '2h'
  banDialog.visible = true
}

async function submitBan() {
  if (!banDialog.node_ip.trim() || !banDialog.pool_name.trim()) {
    ElMessage.warning('请填写 node_ip 和 pool_name')
    return
  }
  banning.value = true
  try {
    const result = await banNode({
      node_ip: banDialog.node_ip.trim(),
      pool_name: banDialog.pool_name.trim(),
      duration: banDialog.duration.trim(),
    })
    ElMessage.success(`封禁完成，命中 ${result?.matched ?? 0} 个节点`)
    banDialog.visible = false
    await refresh()
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '封禁失败')
  } finally {
    banning.value = false
  }
}

async function confirmRelease(node: NodeSnapshot) {
  await ElMessageBox.confirm(`确认解除节点 ${node.name || node.tag} 的拉黑状态？`, '确认操作', {
    type: 'warning',
  })
  await release(node.tag)
}

function progressPercent() {
  if (!probeDialog.total) return 0
  return Math.min(100, Math.round((probeDialog.current / probeDialog.total) * 100))
}

function onGlobalRefresh() {
  refresh({ silent: true })
}

onMounted(() => {
  refresh()
  timer = window.setInterval(() => {
    refresh({ silent: true })
  }, 10000)
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
      <el-col :xs="12" :sm="6">
        <el-card>
          <div class="muted">总节点</div>
          <div style="font-size:26px; font-weight:700; margin-top:6px;">{{ stats.total }}</div>
        </el-card>
      </el-col>
      <el-col :xs="12" :sm="6">
        <el-card>
          <div class="muted">健康节点</div>
          <div style="font-size:26px; font-weight:700; margin-top:6px; color:#16a34a;">{{ stats.healthy }}</div>
        </el-card>
      </el-col>
      <el-col :xs="12" :sm="6">
        <el-card>
          <div class="muted">活跃连接</div>
          <div style="font-size:26px; font-weight:700; margin-top:6px; color:#0ea5e9;">{{ stats.active }}</div>
        </el-card>
      </el-col>
      <el-col :xs="12" :sm="6">
        <el-card>
          <div class="muted">拉黑节点</div>
          <div style="font-size:26px; font-weight:700; margin-top:6px; color:#dc2626;">{{ stats.blacklisted }}</div>
        </el-card>
      </el-col>
    </el-row>

    <el-card>
      <div class="card-title">
        <h3>节点状态</h3>
        <div style="display:flex; gap:8px; flex-wrap:wrap;">
          <el-button type="primary" :icon="Monitor" @click="batchProbe">批量探测</el-button>
          <el-button type="warning" @click="openBanDialog">主动封控</el-button>
          <el-button :icon="Refresh" @click="refresh">刷新</el-button>
        </div>
      </div>

      <el-row :gutter="8" style="margin-bottom:10px;">
        <el-col :xs="24" :sm="10" :md="8">
          <el-input v-model="filters.keyword" :prefix-icon="Search" placeholder="搜索 tag / 名称 / pool / 地区" clearable />
        </el-col>
        <el-col :xs="12" :sm="7" :md="5">
          <el-select v-model="filters.region" placeholder="筛选地区" style="width:100%;">
            <el-option v-for="region in regions" :key="region" :label="region" :value="region" />
          </el-select>
        </el-col>
        <el-col :xs="12" :sm="7" :md="5">
          <el-select v-model="filters.pool" placeholder="筛选业务池" style="width:100%;">
            <el-option v-for="pool in pools" :key="pool" :label="pool" :value="pool" />
          </el-select>
        </el-col>
      </el-row>

      <el-table v-loading="loading" :data="filteredNodes" row-key="tag" border stripe style="width:100%;">
        <el-table-column prop="name" label="节点" min-width="220">
          <template #default="scope">
            <div style="display:grid; gap:2px;">
              <strong>{{ scope.row.name || scope.row.tag }}</strong>
              <span class="muted monospace">{{ scope.row.tag }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="节点IP" min-width="180">
          <template #default="scope">
            <span class="monospace">{{ nodeRealAddress(scope.row) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="pool_name" label="业务池" min-width="120">
          <template #default="scope">
            <el-tag>{{ scope.row.pool_name || 'default' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="region" label="地区" width="110">
          <template #default="scope">{{ scope.row.region || 'other' }}</template>
        </el-table-column>
        <el-table-column label="延迟" width="120">
          <template #default="scope">
            <div>{{ scope.row.last_latency_ms >= 0 ? `${scope.row.last_latency_ms}ms` : '-' }}</div>
            <div class="muted" style="font-size:12px;">{{ latencyLabel(scope.row.last_latency_ms) }}</div>
          </template>
        </el-table-column>
        <el-table-column prop="active_connections" label="活跃" width="80" />
        <el-table-column prop="failure_count" label="失败" width="80" />
        <el-table-column label="状态" width="110">
          <template #default="scope">
            <el-tag :type="statusType(scope.row)">{{ statusText(scope.row) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="最近成功" width="140">
          <template #default="scope">{{ formatRelativeTime(scope.row.last_success) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="210" fixed="right">
          <template #default="scope">
            <el-space>
              <el-button size="small" @click="probe(scope.row.tag)">探测</el-button>
              <el-button
                v-if="scope.row.blacklisted"
                size="small"
                type="warning"
                @click="confirmRelease(scope.row)"
              >
                解除
              </el-button>
            </el-space>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="probeDialog.visible" title="批量探测进度" width="520px">
      <el-progress :percentage="progressPercent()" :stroke-width="16" />
      <div style="margin-top:12px; display:grid; gap:8px;">
        <div class="muted">{{ probeDialog.current }} / {{ probeDialog.total }}</div>
        <div>
          <el-tag type="success">成功 {{ probeDialog.success }}</el-tag>
          <el-tag type="danger" style="margin-left:8px;">失败 {{ probeDialog.failed }}</el-tag>
        </div>
        <div class="muted">{{ probeDialog.currentLabel }}</div>
      </div>
      <template #footer>
        <el-button @click="probeDialog.visible = false">关闭</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="banDialog.visible" title="主动封控节点" width="520px">
      <el-form label-width="120px">
        <el-form-item label="node_ip / 正则">
          <el-input v-model="banDialog.node_ip" placeholder="例如: 1.2.3.4 或 ^1\\.2\\.3\\..*" />
        </el-form-item>
        <el-form-item label="pool_name">
          <el-select v-model="banDialog.pool_name" filterable allow-create default-first-option style="width:100%;">
            <el-option v-for="pool in pools.filter((p) => p !== 'all')" :key="pool" :label="pool" :value="pool" />
          </el-select>
        </el-form-item>
        <el-form-item label="duration">
          <el-input v-model="banDialog.duration" placeholder="例如: 2h" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="banDialog.visible = false">取消</el-button>
        <el-button type="danger" :loading="banning" @click="submitBan">确认封控</el-button>
      </template>
    </el-dialog>
  </div>
</template>
