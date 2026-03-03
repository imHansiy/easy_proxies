<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { createPool, deletePool, getNodes, listPools, releaseNode, updatePool } from '../api/client'
import type { NamedPoolConfig, NodeSnapshot } from '../types/api'
import { formatDurationNs, formatRelativeTime, parseDurationNs } from '../utils/time'

const loading = ref(false)
const saving = ref(false)
const pools = ref<NamedPoolConfig[]>([])
const nodes = ref<NodeSnapshot[]>([])
const blacklistFilterPool = ref('all')
const activeSubMenu = ref('pool-list')

const dialog = reactive({
  visible: false,
  editing: false,
  editingName: '',
  form: createDefaultPool('default', 2323),
})

type BlacklistedNodeGroup = {
  key: string
  node_ip: string
  pool_names: string[]
  nodes: NodeSnapshot[]
  blacklisted_until: string
  last_error: string
  active_connections: number
  node_count: number
}

function toTimestamp(raw: string): number {
  const value = Date.parse(raw || '')
  return Number.isNaN(value) ? 0 : value
}

function normalizePoolName(poolName?: string): string {
  return (poolName || 'default').trim() || 'default'
}

function createDefaultPool(name: string, port: number): NamedPoolConfig {
  return {
    name,
    listener: {
      address: '0.0.0.0',
      port,
      username: '',
      password: '',
    },
    pool: {
      mode: 'sequential',
      failure_threshold: 3,
      blacklist_duration: 24 * 60 * 60 * 1_000_000_000,
      domain_failure_threshold: 2,
      domain_blacklist_duration: 12 * 60 * 60 * 1_000_000_000,
      domain_recheck_interval: 10 * 60 * 1_000_000_000,
      domain_recheck_timeout: 10 * 1_000_000_000,
    },
  }
}

const blacklistedNodes = computed(() =>
  nodes.value
    .filter((item) => item.blacklisted)
    .sort((a, b) => {
      const ta = toTimestamp(a.blacklisted_until || '')
      const tb = toTimestamp(b.blacklisted_until || '')
      return tb - ta
    }),
)

const groupedBlacklistedNodes = computed<BlacklistedNodeGroup[]>(() => {
  const grouped = new Map<string, BlacklistedNodeGroup>()

  for (const node of blacklistedNodes.value) {
    const ip = String(node.node_ip || '').trim()
    const key = ip ? `ip:${ip}` : `tag:${node.tag}`
    const poolName = normalizePoolName(node.pool_name)

    if (!grouped.has(key)) {
      grouped.set(key, {
        key,
        node_ip: ip || '-',
        pool_names: [],
        nodes: [],
        blacklisted_until: node.blacklisted_until,
        last_error: '',
        active_connections: 0,
        node_count: 0,
      })
    }

    const row = grouped.get(key)!
    row.nodes.push(node)
    row.node_count += 1
    row.active_connections += Number(node.active_connections || 0)
    if (!row.pool_names.includes(poolName)) {
      row.pool_names.push(poolName)
    }
    if (toTimestamp(node.blacklisted_until || '') > toTimestamp(row.blacklisted_until || '')) {
      row.blacklisted_until = node.blacklisted_until
    }
    if (!row.last_error && node.last_error) {
      row.last_error = node.last_error
    }
  }

  const rows = Array.from(grouped.values())
  for (const row of rows) {
    row.pool_names.sort((a, b) => a.localeCompare(b))
    row.nodes.sort((a, b) => toTimestamp(b.blacklisted_until || '') - toTimestamp(a.blacklisted_until || ''))
  }
  rows.sort((a, b) => toTimestamp(b.blacklisted_until || '') - toTimestamp(a.blacklisted_until || ''))
  return rows
})

const blacklistCountByPool = computed(() => {
  const map = new Map<string, number>()
  for (const item of blacklistedNodes.value) {
    const poolName = normalizePoolName(item.pool_name)
    map.set(poolName, (map.get(poolName) || 0) + 1)
  }
  return map
})

const poolFilterOptions = computed(() => {
  const names = Array.from(new Set(pools.value.map((item) => item.name).filter(Boolean)))
  return ['all', ...names]
})

const visibleGroupedBlacklistedNodes = computed(() => {
  if (blacklistFilterPool.value === 'all') {
    return groupedBlacklistedNodes.value
  }
  return groupedBlacklistedNodes.value.filter((item) => item.pool_names.includes(blacklistFilterPool.value))
})

const prettyRows = computed(() =>
  pools.value.map((pool) => ({
    ...pool,
    pool_policy: `${pool.pool.mode} / fail:${pool.pool.failure_threshold}`,
    blacklist_duration_text: formatDurationNs(pool.pool.blacklist_duration),
    blacklisted_count: blacklistCountByPool.value.get(pool.name) || 0,
  })),
)

const formDuration = reactive({
  blacklist: '24h',
  domainBlacklist: '12h',
  domainRecheckInterval: '10m',
  domainRecheckTimeout: '10s',
})

function setForm(pool: NamedPoolConfig) {
  dialog.form = {
    name: pool.name,
    listener: { ...pool.listener },
    pool: { ...pool.pool },
  }
  formDuration.blacklist = formatDurationNs(pool.pool.blacklist_duration)
  formDuration.domainBlacklist = formatDurationNs(pool.pool.domain_blacklist_duration)
  formDuration.domainRecheckInterval = formatDurationNs(pool.pool.domain_recheck_interval)
  formDuration.domainRecheckTimeout = formatDurationNs(pool.pool.domain_recheck_timeout)
}

function toPayloadFromForm(): NamedPoolConfig {
  const source = dialog.form
  return {
    name: String(source.name || '').trim(),
    listener: {
      address: String(source.listener.address || '').trim() || '0.0.0.0',
      port: Number(source.listener.port || 0),
      username: String(source.listener.username || '').trim(),
      password: String(source.listener.password || '').trim(),
    },
    pool: {
      mode: String(source.pool.mode || 'sequential'),
      failure_threshold: Number(source.pool.failure_threshold || 1),
      blacklist_duration: parseDurationNs(formDuration.blacklist, '封禁时长', 24 * 60 * 60 * 1_000_000_000),
      domain_failure_threshold: Number(source.pool.domain_failure_threshold || 1),
      domain_blacklist_duration: parseDurationNs(
        formDuration.domainBlacklist,
        '域名封禁时长',
        12 * 60 * 60 * 1_000_000_000,
      ),
      domain_recheck_interval: parseDurationNs(
        formDuration.domainRecheckInterval,
        '域名复查间隔',
        10 * 60 * 1_000_000_000,
      ),
      domain_recheck_timeout: parseDurationNs(
        formDuration.domainRecheckTimeout,
        '域名复查超时',
        10 * 1_000_000_000,
      ),
    },
  }
}

async function load() {
  loading.value = true
  try {
    const [poolList, nodePayload] = await Promise.all([listPools(), getNodes()])
    pools.value = poolList
    nodes.value = nodePayload.nodes || []
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '加载业务池失败')
  } finally {
    loading.value = false
  }
}

watch(
  () => pools.value.map((item) => item.name),
  (names) => {
    if (blacklistFilterPool.value === 'all') return
    if (!names.includes(blacklistFilterPool.value)) {
      blacklistFilterPool.value = 'all'
    }
  },
)

function pickPoolForBlacklist(poolName: string) {
  blacklistFilterPool.value = poolName || 'all'
  activeSubMenu.value = 'blacklist-list'
}

function formatBlacklistedUntil(raw: string): string {
  if (!raw || raw.startsWith('0001-01-01')) {
    return '-'
  }
  const parsed = new Date(raw)
  if (Number.isNaN(parsed.getTime())) {
    return raw
  }
  return `${parsed.toLocaleString()} (${formatRelativeTime(raw)})`
}

function openCreate() {
  const lastPool = pools.value.length > 0 ? pools.value[pools.value.length - 1] : undefined
  const nextPort = lastPool ? Number(lastPool.listener?.port || 2323) + 1 : 2323
  dialog.editing = false
  dialog.editingName = ''
  setForm(createDefaultPool(`pool-${pools.value.length + 1}`, nextPort))
  dialog.visible = true
}

function openEdit(row: NamedPoolConfig) {
  dialog.editing = true
  dialog.editingName = row.name
  setForm(row)
  dialog.visible = true
}

async function releaseBlacklistedNode(node: NodeSnapshot) {
  const tag = String(node.tag || '').trim()
  if (!tag) return

  const title = String(node.name || node.node_tag || tag).trim()
  try {
    await ElMessageBox.confirm(`确认解除节点 ${title} 的拉黑状态？`, '解除拉黑', { type: 'warning' })
  } catch {
    return
  }

  try {
    await releaseNode(tag)
    ElMessage.success('节点已解封')
    await load()
    window.dispatchEvent(new CustomEvent('ep:refresh'))
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '节点解封失败')
  }
}

async function releaseBlacklistedGroup(row: BlacklistedNodeGroup) {
  const tags = row.nodes.map((item) => String(item.tag || '').trim()).filter(Boolean)
  if (tags.length === 0) {
    ElMessage.warning('没有可解封节点')
    return
  }

  try {
    await ElMessageBox.confirm(`确认解封 IP ${row.node_ip} 下 ${tags.length} 个拉黑节点？`, '批量解封', { type: 'warning' })
  } catch {
    return
  }

  const results = await Promise.allSettled(tags.map((tag) => releaseNode(tag)))
  const success = results.filter((item) => item.status === 'fulfilled').length
  const failed = tags.length - success

  if (failed === 0) {
    ElMessage.success(`已解封 ${success} 个节点`)
  } else if (success === 0) {
    ElMessage.error(`解封失败，共 ${failed} 个节点`)
  } else {
    ElMessage.warning(`部分解封成功：成功 ${success}，失败 ${failed}`)
  }

  await load()
  window.dispatchEvent(new CustomEvent('ep:refresh'))
}

async function save(applyNow: boolean) {
  saving.value = true
  try {
    const payload = toPayloadFromForm()
    if (!payload.name) {
      ElMessage.warning('业务池名称不能为空')
      return
    }
    if (payload.listener.port <= 0 || payload.listener.port > 65535) {
      ElMessage.warning('监听端口无效')
      return
    }

    if (dialog.editing) {
      await updatePool(dialog.editingName, payload, applyNow)
      ElMessage.success(applyNow ? '业务池已更新并重载' : '业务池已更新')
    } else {
      await createPool(payload, applyNow)
      ElMessage.success(applyNow ? '业务池已创建并重载' : '业务池已创建')
    }
    dialog.visible = false
    await load()
    window.dispatchEvent(new CustomEvent('ep:refresh'))
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '保存业务池失败')
  } finally {
    saving.value = false
  }
}

async function remove(row: NamedPoolConfig) {
  await ElMessageBox.confirm(
    `确认删除业务池 ${row.name}？删除后将不再监听端口 ${row.listener.port}。`,
    '删除确认',
    { type: 'warning' },
  )
  try {
    await deletePool(row.name, false)
    ElMessage.success('业务池已删除（如需立即生效请重载）')
    await load()
    window.dispatchEvent(new CustomEvent('ep:refresh'))
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '删除业务池失败')
  }
}

onMounted(load)
</script>

<template>
  <el-card>
    <template #header>
      <div class="card-title">
        <h3>业务池管理（Named Pools）</h3>
        <span class="muted">子菜单中可切换“业务池列表 / 拉黑节点”</span>
      </div>
    </template>

    <el-tabs v-model="activeSubMenu">
      <el-tab-pane label="业务池列表" name="pool-list">
        <div class="card-title" style="margin-bottom: 10px;">
          <h3>业务池列表</h3>
          <el-space>
            <el-button :loading="loading" @click="load">刷新</el-button>
            <el-button type="primary" @click="openCreate">新增业务池</el-button>
          </el-space>
        </div>

        <el-table v-loading="loading" :data="prettyRows" border stripe @row-click="(row:any)=>pickPoolForBlacklist(row.name)">
          <el-table-column prop="name" label="池名称" min-width="140" />
          <el-table-column label="监听" min-width="210">
            <template #default="scope">
              <span class="monospace">{{ scope.row.listener.address }}:{{ scope.row.listener.port }}</span>
            </template>
          </el-table-column>
          <el-table-column label="认证" min-width="160">
            <template #default="scope">
              <span>{{ scope.row.listener.username || '-' }}</span>
            </template>
          </el-table-column>
          <el-table-column prop="pool_policy" label="调度策略" min-width="160" />
          <el-table-column prop="blacklist_duration_text" label="封禁时长" width="110" />
          <el-table-column prop="blacklisted_count" label="当前拉黑" width="110">
            <template #default="scope">
              <el-tag :type="scope.row.blacklisted_count > 0 ? 'danger' : 'success'">{{ scope.row.blacklisted_count }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="220" fixed="right">
            <template #default="scope">
              <el-space>
                <el-button size="small" @click="openEdit(scope.row)">编辑</el-button>
                <el-button size="small" type="danger" plain @click="remove(scope.row)">删除</el-button>
              </el-space>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="拉黑节点" name="blacklist-list">
        <div class="card-title" style="margin-bottom: 10px;">
          <h3>被拉黑节点列表</h3>
          <el-space>
            <el-select v-model="blacklistFilterPool" style="min-width: 180px;" placeholder="按业务池过滤">
              <el-option label="全部业务池" value="all" />
              <el-option
                v-for="item in poolFilterOptions.filter((v) => v !== 'all')"
                :key="item"
                :label="item"
                :value="item"
              />
            </el-select>
            <el-button :loading="loading" @click="load">刷新列表</el-button>
          </el-space>
        </div>

        <el-empty v-if="visibleGroupedBlacklistedNodes.length === 0" description="当前筛选下暂无被拉黑节点" />
        <el-table v-else :data="visibleGroupedBlacklistedNodes" row-key="key" border stripe>
          <el-table-column type="expand" width="56">
            <template #default="scope">
              <el-table :data="scope.row.nodes" size="small" border style="margin: 8px 0; width: 100%;">
                <el-table-column label="业务池" min-width="120">
                  <template #default="inner">
                    <el-tag type="warning">{{ inner.row.pool_name || 'default' }}</el-tag>
                  </template>
                </el-table-column>
                <el-table-column label="节点" min-width="220">
                  <template #default="inner">
                    <div style="display:grid; gap:2px;">
                      <strong>{{ inner.row.name || inner.row.node_tag || inner.row.tag }}</strong>
                      <span class="muted monospace">{{ inner.row.node_tag || inner.row.tag }}</span>
                    </div>
                  </template>
                </el-table-column>
                <el-table-column label="拉黑到期" min-width="220">
                  <template #default="inner">{{ formatBlacklistedUntil(inner.row.blacklisted_until) }}</template>
                </el-table-column>
                <el-table-column label="最近错误" min-width="300" show-overflow-tooltip>
                  <template #default="inner">{{ inner.row.last_error || '-' }}</template>
                </el-table-column>
                <el-table-column label="操作" width="100" fixed="right">
                  <template #default="inner">
                    <el-button size="small" type="primary" plain @click="releaseBlacklistedNode(inner.row)">解封</el-button>
                  </template>
                </el-table-column>
              </el-table>
            </template>
          </el-table-column>
          <el-table-column label="节点IP" min-width="170">
            <template #default="scope">
              <span class="monospace">{{ scope.row.node_ip }}</span>
            </template>
          </el-table-column>
          <el-table-column label="涉及业务池" min-width="220">
            <template #default="scope">
              <el-space wrap>
                <el-tag v-for="pool in scope.row.pool_names" :key="pool" type="warning">{{ pool }}</el-tag>
              </el-space>
            </template>
          </el-table-column>
          <el-table-column label="被拉黑实例" width="110" align="center">
            <template #default="scope">{{ scope.row.node_count }}</template>
          </el-table-column>
          <el-table-column label="节点摘要" min-width="240">
            <template #default="scope">
              <div style="display:grid; gap:2px;">
                <strong>{{ scope.row.nodes.length > 0 ? (scope.row.nodes[0].name || scope.row.nodes[0].node_tag || scope.row.nodes[0].tag) : '-' }}</strong>
                <span class="muted">展开查看 {{ scope.row.node_count }} 条节点记录</span>
              </div>
            </template>
          </el-table-column>
          <el-table-column label="拉黑到期" min-width="230">
            <template #default="scope">{{ formatBlacklistedUntil(scope.row.blacklisted_until) }}</template>
          </el-table-column>
          <el-table-column label="最近错误" min-width="320" show-overflow-tooltip>
            <template #default="scope">{{ scope.row.last_error || '-' }}</template>
          </el-table-column>
          <el-table-column label="活跃连接" width="100" align="center">
            <template #default="scope">{{ scope.row.active_connections || 0 }}</template>
          </el-table-column>
          <el-table-column label="操作" width="120" fixed="right">
            <template #default="scope">
              <el-button size="small" type="primary" @click="releaseBlacklistedGroup(scope.row)">全部解封</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>
  </el-card>

  <el-dialog v-model="dialog.visible" :title="dialog.editing ? '编辑业务池' : '新增业务池'" width="760px">
    <el-form label-position="top">
      <el-divider>基础信息</el-divider>
      <el-row :gutter="12">
        <el-col :xs="24" :sm="6"><el-form-item label="池名称"><el-input v-model="dialog.form.name" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="监听地址"><el-input v-model="dialog.form.listener.address" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="监听端口"><el-input-number v-model="dialog.form.listener.port" :min="1" :max="65535" style="width:100%;" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="调度模式"><el-select v-model="dialog.form.pool.mode"><el-option label="sequential" value="sequential" /><el-option label="random" value="random" /></el-select></el-form-item></el-col>
      </el-row>

      <el-divider>认证配置</el-divider>
      <el-row :gutter="12">
        <el-col :xs="24" :sm="12"><el-form-item label="代理用户名"><el-input v-model="dialog.form.listener.username" /></el-form-item></el-col>
        <el-col :xs="24" :sm="12"><el-form-item label="代理密码"><el-input v-model="dialog.form.listener.password" /></el-form-item></el-col>
      </el-row>

      <el-divider>失败策略</el-divider>
      <el-row :gutter="12">
        <el-col :xs="24" :sm="6"><el-form-item label="失败阈值"><el-input-number v-model="dialog.form.pool.failure_threshold" :min="1" style="width:100%;" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="封禁时长"><el-input v-model="formDuration.blacklist" placeholder="24h" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="域名失败阈值"><el-input-number v-model="dialog.form.pool.domain_failure_threshold" :min="1" style="width:100%;" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="域名封禁时长"><el-input v-model="formDuration.domainBlacklist" placeholder="12h" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="域名复查间隔"><el-input v-model="formDuration.domainRecheckInterval" placeholder="10m" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="域名复查超时"><el-input v-model="formDuration.domainRecheckTimeout" placeholder="10s" /></el-form-item></el-col>
      </el-row>
      <div class="muted">提示：时长支持 30s / 10m / 2h / 1d。</div>
    </el-form>

    <template #footer>
      <el-button @click="dialog.visible = false">取消</el-button>
      <el-button type="primary" :loading="saving" @click="save(false)">保存</el-button>
      <el-button type="warning" :loading="saving" @click="save(true)">保存并重载</el-button>
    </template>
  </el-dialog>
</template>
