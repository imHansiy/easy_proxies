<script setup lang="ts">
import { onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { getRuntimeConfig, saveRuntimeConfig } from '../api/client'
import type { RuntimeConfig } from '../types/api'
import { formatDurationNs, parseDurationNs } from '../utils/time'

const loading = ref(false)
const saving = ref(false)
const available = ref(true)
const unavailableMessage = ref('')

const form = reactive<any>({})

function defaultPoolPolicy() {
  return {
    mode: 'sequential',
    failure_threshold: 3,
    blacklist_duration: 24 * 60 * 60 * 1_000_000_000,
    domain_failure_threshold: 2,
    domain_blacklist_duration: 12 * 60 * 60 * 1_000_000_000,
    domain_recheck_interval: 10 * 60 * 1_000_000_000,
    domain_recheck_timeout: 10 * 1_000_000_000,
  }
}

function defaultConfig(): RuntimeConfig {
  return {
    mode: 'pool',
    listener: {
      address: '0.0.0.0',
      port: 2323,
      username: '',
      password: '',
    },
    named_pools: [
      {
        name: 'default',
        listener: {
          address: '0.0.0.0',
          port: 2323,
          username: '',
          password: '',
        },
        pool: defaultPoolPolicy(),
      },
    ],
    multi_port: {
      address: '0.0.0.0',
      base_port: 28000,
      username: '',
      password: '',
    },
    pool: defaultPoolPolicy(),
    management_enabled: true,
    management_listen: '127.0.0.1:9090',
    management_password: '',
    management_frontend_dist: 'web/dist',
    management_allowed_origins: [],
    subscription_refresh: {
      enabled: true,
      interval: 1 * 60 * 60 * 1_000_000_000,
      timeout: 30 * 1_000_000_000,
      health_check_timeout: 60 * 1_000_000_000,
      drain_timeout: 30 * 1_000_000_000,
      min_available_nodes: 1,
    },
    geoip: {
      enabled: false,
      database_path: '',
      listen: '',
      port: 0,
      auto_update_enabled: false,
      auto_update_interval: 24 * 60 * 60 * 1_000_000_000,
    },
    nodes_file: '',
    log_level: 'info',
  }
}

function resetForm(cfg: RuntimeConfig) {
  const merged: RuntimeConfig = {
    ...defaultConfig(),
    ...cfg,
    listener: { ...defaultConfig().listener, ...(cfg.listener || {}) },
    multi_port: { ...defaultConfig().multi_port, ...(cfg.multi_port || {}) },
    pool: { ...defaultPoolPolicy(), ...(cfg.pool || {}) },
    subscription_refresh: { ...defaultConfig().subscription_refresh, ...(cfg.subscription_refresh || {}) },
    geoip: { ...defaultConfig().geoip, ...(cfg.geoip || {}) },
    named_pools:
      Array.isArray(cfg.named_pools) && cfg.named_pools.length > 0
        ? cfg.named_pools.map((pool, idx) => ({
            name: pool.name || (idx === 0 ? 'default' : `pool-${idx + 1}`),
            listener: { ...defaultConfig().listener, ...(pool.listener || {}) },
            pool: { ...defaultPoolPolicy(), ...(pool.pool || {}) },
          }))
        : defaultConfig().named_pools,
  }

  Object.assign(form, {
    mode: merged.mode,
    log_level: merged.log_level,
    nodes_file: merged.nodes_file,
    listener: { ...merged.listener },
    pool: {
      ...merged.pool,
      blacklist_duration_text: formatDurationNs(merged.pool.blacklist_duration),
      domain_blacklist_duration_text: formatDurationNs(merged.pool.domain_blacklist_duration),
      domain_recheck_interval_text: formatDurationNs(merged.pool.domain_recheck_interval),
      domain_recheck_timeout_text: formatDurationNs(merged.pool.domain_recheck_timeout),
    },
    named_pools: merged.named_pools.map((pool) => ({
      ...pool,
      listener: { ...pool.listener },
      pool: {
        ...pool.pool,
        blacklist_duration_text: formatDurationNs(pool.pool.blacklist_duration),
        domain_blacklist_duration_text: formatDurationNs(pool.pool.domain_blacklist_duration),
        domain_recheck_interval_text: formatDurationNs(pool.pool.domain_recheck_interval),
        domain_recheck_timeout_text: formatDurationNs(pool.pool.domain_recheck_timeout),
      },
    })),
    multi_port: { ...merged.multi_port },
    management_enabled: merged.management_enabled,
    management_listen: merged.management_listen,
    management_password: merged.management_password,
    management_frontend_dist: merged.management_frontend_dist,
    management_allowed_origins_text: (merged.management_allowed_origins || []).join('\n'),
    subscription_refresh: {
      ...merged.subscription_refresh,
      interval_text: formatDurationNs(merged.subscription_refresh.interval),
      timeout_text: formatDurationNs(merged.subscription_refresh.timeout),
      health_check_timeout_text: formatDurationNs(merged.subscription_refresh.health_check_timeout),
      drain_timeout_text: formatDurationNs(merged.subscription_refresh.drain_timeout),
    },
    geoip: {
      ...merged.geoip,
      auto_update_interval_text: formatDurationNs(merged.geoip.auto_update_interval),
    },
  })
}

function toInt(value: any, fallback = 0) {
  const n = Number(value)
  return Number.isFinite(n) ? Math.trunc(n) : fallback
}

function buildPayload(): RuntimeConfig {
  const base = defaultConfig()
  return {
    mode: form.mode || base.mode,
    log_level: form.log_level || base.log_level,
    nodes_file: String(form.nodes_file || ''),
    listener: {
      address: String(form.listener?.address || base.listener.address),
      port: toInt(form.listener?.port, base.listener.port),
      username: String(form.listener?.username || ''),
      password: String(form.listener?.password || ''),
    },
    pool: {
      mode: String(form.pool?.mode || base.pool.mode),
      failure_threshold: toInt(form.pool?.failure_threshold, base.pool.failure_threshold),
      blacklist_duration: parseDurationNs(form.pool?.blacklist_duration_text, '默认池封禁时长', base.pool.blacklist_duration),
      domain_failure_threshold: toInt(form.pool?.domain_failure_threshold, base.pool.domain_failure_threshold),
      domain_blacklist_duration: parseDurationNs(form.pool?.domain_blacklist_duration_text, '默认池域名封禁时长', base.pool.domain_blacklist_duration),
      domain_recheck_interval: parseDurationNs(form.pool?.domain_recheck_interval_text, '默认池域名复查间隔', base.pool.domain_recheck_interval),
      domain_recheck_timeout: parseDurationNs(form.pool?.domain_recheck_timeout_text, '默认池域名复查超时', base.pool.domain_recheck_timeout),
    },
    named_pools: (form.named_pools || []).map((pool: any, idx: number) => ({
      name: String(pool?.name || (idx === 0 ? 'default' : `pool-${idx + 1}`)),
      listener: {
        address: String(pool?.listener?.address || form.listener?.address || '0.0.0.0'),
        port: toInt(pool?.listener?.port, toInt(form.listener?.port, 2323) + idx),
        username: String(pool?.listener?.username || ''),
        password: String(pool?.listener?.password || ''),
      },
      pool: {
        mode: String(pool?.pool?.mode || form.pool?.mode || 'sequential'),
        failure_threshold: toInt(pool?.pool?.failure_threshold, toInt(form.pool?.failure_threshold, 3)),
        blacklist_duration: parseDurationNs(pool?.pool?.blacklist_duration_text, `业务池 ${pool?.name || idx + 1} 封禁时长`, base.pool.blacklist_duration),
        domain_failure_threshold: toInt(pool?.pool?.domain_failure_threshold, toInt(form.pool?.domain_failure_threshold, 2)),
        domain_blacklist_duration: parseDurationNs(pool?.pool?.domain_blacklist_duration_text, `业务池 ${pool?.name || idx + 1} 域名封禁时长`, base.pool.domain_blacklist_duration),
        domain_recheck_interval: parseDurationNs(pool?.pool?.domain_recheck_interval_text, `业务池 ${pool?.name || idx + 1} 域名复查间隔`, base.pool.domain_recheck_interval),
        domain_recheck_timeout: parseDurationNs(pool?.pool?.domain_recheck_timeout_text, `业务池 ${pool?.name || idx + 1} 域名复查超时`, base.pool.domain_recheck_timeout),
      },
    })),
    multi_port: {
      address: String(form.multi_port?.address || base.multi_port.address),
      base_port: toInt(form.multi_port?.base_port, base.multi_port.base_port),
      username: String(form.multi_port?.username || ''),
      password: String(form.multi_port?.password || ''),
    },
    management_enabled: !!form.management_enabled,
    management_listen: String(form.management_listen || base.management_listen),
    management_password: String(form.management_password || ''),
    management_frontend_dist: String(form.management_frontend_dist || ''),
    management_allowed_origins: String(form.management_allowed_origins_text || '')
      .split(/\r?\n|,/)
      .map((item) => item.trim())
      .filter((item, idx, arr) => item && arr.indexOf(item) === idx),
    subscription_refresh: {
      enabled: !!form.subscription_refresh?.enabled,
      interval: parseDurationNs(form.subscription_refresh?.interval_text, '订阅刷新间隔', base.subscription_refresh.interval),
      timeout: parseDurationNs(form.subscription_refresh?.timeout_text, '订阅刷新超时', base.subscription_refresh.timeout),
      health_check_timeout: parseDurationNs(
        form.subscription_refresh?.health_check_timeout_text,
        '订阅健康检查超时',
        base.subscription_refresh.health_check_timeout,
      ),
      drain_timeout: parseDurationNs(form.subscription_refresh?.drain_timeout_text, '排空超时', base.subscription_refresh.drain_timeout),
      min_available_nodes: toInt(form.subscription_refresh?.min_available_nodes, base.subscription_refresh.min_available_nodes),
    },
    geoip: {
      enabled: !!form.geoip?.enabled,
      database_path: String(form.geoip?.database_path || ''),
      listen: String(form.geoip?.listen || ''),
      port: toInt(form.geoip?.port, 0),
      auto_update_enabled: !!form.geoip?.auto_update_enabled,
      auto_update_interval: parseDurationNs(form.geoip?.auto_update_interval_text, 'GeoIP 更新间隔', base.geoip.auto_update_interval),
    },
  }
}

async function load() {
  loading.value = true
  try {
    const cfg = await getRuntimeConfig()
    resetForm(cfg)
    available.value = true
    unavailableMessage.value = ''
  } catch (error: any) {
    available.value = false
    unavailableMessage.value = error?.response?.data?.error || error?.message || '运行配置不可用'
  } finally {
    loading.value = false
  }
}

async function save(applyNow: boolean) {
  saving.value = true
  try {
    const payload = buildPayload()
    const result = await saveRuntimeConfig(payload, applyNow)
    if (result?.runtime_config) {
      resetForm(result.runtime_config as RuntimeConfig)
    }
    if (result?.reloaded) {
      ElMessage.success('运行配置已保存并重载成功')
    } else {
      ElMessage.success('运行配置已保存到数据库')
    }
    window.dispatchEvent(new CustomEvent('ep:refresh'))
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.error || error?.message || '保存运行配置失败')
  } finally {
    saving.value = false
  }
}

function onGlobalRefresh() {
  load()
}

onMounted(() => {
  load()
  window.addEventListener('ep:refresh', onGlobalRefresh)
})

onBeforeUnmount(() => {
  window.removeEventListener('ep:refresh', onGlobalRefresh)
})
</script>

<template>
  <el-card>
    <template #header>
      <div class="card-title">
        <h3>运行配置（数据库）</h3>
        <el-space>
          <el-button :loading="loading" @click="load">重新加载</el-button>
          <el-button type="primary" :loading="saving" @click="save(false)">保存到数据库</el-button>
          <el-button type="warning" :loading="saving" @click="save(true)">保存并重载</el-button>
        </el-space>
      </div>
    </template>

    <el-alert
      v-if="!available"
      :title="unavailableMessage"
      type="warning"
      show-icon
      :closable="false"
    />

    <el-form v-else label-position="top" :disabled="loading || saving">
      <el-row :gutter="12">
        <el-col :xs="24" :sm="8"><el-form-item label="运行模式"><el-select v-model="form.mode"><el-option label="pool" value="pool" /><el-option label="multi-port" value="multi-port" /><el-option label="hybrid" value="hybrid" /></el-select></el-form-item></el-col>
        <el-col :xs="24" :sm="8"><el-form-item label="日志级别"><el-select v-model="form.log_level"><el-option label="debug" value="debug" /><el-option label="info" value="info" /><el-option label="warn" value="warn" /><el-option label="error" value="error" /></el-select></el-form-item></el-col>
        <el-col :xs="24" :sm="8"><el-form-item label="nodes_file"><el-input v-model="form.nodes_file" /></el-form-item></el-col>
      </el-row>

      <el-divider>默认入口监听</el-divider>
      <el-row :gutter="12">
        <el-col :xs="24" :sm="6"><el-form-item label="监听地址"><el-input v-model="form.listener.address" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="监听端口"><el-input-number v-model="form.listener.port" :min="1" :max="65535" style="width:100%;" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="代理用户名"><el-input v-model="form.listener.username" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="代理密码"><el-input v-model="form.listener.password" /></el-form-item></el-col>
      </el-row>

      <el-divider>默认节点池策略</el-divider>
      <el-row :gutter="12">
        <el-col :xs="24" :sm="6"><el-form-item label="调度模式"><el-select v-model="form.pool.mode"><el-option label="sequential" value="sequential" /><el-option label="random" value="random" /></el-select></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="失败阈值"><el-input-number v-model="form.pool.failure_threshold" :min="1" style="width:100%;" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="封禁时长"><el-input v-model="form.pool.blacklist_duration_text" placeholder="24h" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="域名失败阈值"><el-input-number v-model="form.pool.domain_failure_threshold" :min="1" style="width:100%;" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="域名封禁时长"><el-input v-model="form.pool.domain_blacklist_duration_text" placeholder="12h" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="域名复查间隔"><el-input v-model="form.pool.domain_recheck_interval_text" placeholder="10m" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="域名复查超时"><el-input v-model="form.pool.domain_recheck_timeout_text" placeholder="10s" /></el-form-item></el-col>
      </el-row>

      <el-divider>Multi-Port</el-divider>
      <el-row :gutter="12">
        <el-col :xs="24" :sm="6"><el-form-item label="监听地址"><el-input v-model="form.multi_port.address" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="起始端口"><el-input-number v-model="form.multi_port.base_port" :min="1" :max="65535" style="width:100%;" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="认证用户名"><el-input v-model="form.multi_port.username" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="认证密码"><el-input v-model="form.multi_port.password" /></el-form-item></el-col>
      </el-row>

      <el-divider>管理面板</el-divider>
      <el-row :gutter="12">
        <el-col :xs="24" :sm="6"><el-form-item label="启用管理"><el-switch v-model="form.management_enabled" /></el-form-item></el-col>
        <el-col :xs="24" :sm="9"><el-form-item label="管理监听地址"><el-input v-model="form.management_listen" /></el-form-item></el-col>
        <el-col :xs="24" :sm="9"><el-form-item label="管理密码"><el-input v-model="form.management_password" /></el-form-item></el-col>
        <el-col :xs="24" :sm="12"><el-form-item label="前端 dist 目录"><el-input v-model="form.management_frontend_dist" placeholder="例如: web/dist" /></el-form-item></el-col>
        <el-col :xs="24" :sm="12"><el-form-item label="允许跨域 Origin 列表"><el-input v-model="form.management_allowed_origins_text" type="textarea" :rows="3" placeholder="一行一个或逗号分隔，例如:&#10;http://localhost:5173" /></el-form-item></el-col>
      </el-row>

      <el-divider>订阅刷新</el-divider>
      <el-row :gutter="12">
        <el-col :xs="24" :sm="6"><el-form-item label="启用"><el-switch v-model="form.subscription_refresh.enabled" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="刷新间隔"><el-input v-model="form.subscription_refresh.interval_text" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="刷新超时"><el-input v-model="form.subscription_refresh.timeout_text" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="健康检查超时"><el-input v-model="form.subscription_refresh.health_check_timeout_text" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="排空超时"><el-input v-model="form.subscription_refresh.drain_timeout_text" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="最少可用节点"><el-input-number v-model="form.subscription_refresh.min_available_nodes" :min="0" style="width:100%;" /></el-form-item></el-col>
      </el-row>

      <el-divider>GeoIP</el-divider>
      <el-row :gutter="12">
        <el-col :xs="24" :sm="6"><el-form-item label="启用 GeoIP"><el-switch v-model="form.geoip.enabled" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="自动更新"><el-switch v-model="form.geoip.auto_update_enabled" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="数据库路径"><el-input v-model="form.geoip.database_path" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="监听地址"><el-input v-model="form.geoip.listen" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="监听端口"><el-input-number v-model="form.geoip.port" :min="0" :max="65535" style="width:100%;" /></el-form-item></el-col>
        <el-col :xs="24" :sm="6"><el-form-item label="更新间隔"><el-input v-model="form.geoip.auto_update_interval_text" /></el-form-item></el-col>
      </el-row>

      <div class="muted">提示：所有时长字段支持 30s / 10m / 2h / 1d 格式。</div>
    </el-form>
  </el-card>
</template>
