export interface TimelineEvent {
  time: string
  success: boolean
  latency_ms: number
  error?: string
}

export interface DomainBlock {
  domain: string
  blacklisted_until: string
}

export interface NodeSnapshot {
  tag: string
  node_tag?: string
  node_ip?: string
  pool_name?: string
  name: string
  uri: string
  mode: string
  listen_address?: string
  port?: number
  region?: string
  country?: string
  failure_count: number
  success_count: number
  blacklisted: boolean
  blacklisted_until: string
  active_connections: number
  last_error?: string
  last_failure?: string
  last_success?: string
  last_probe_latency?: number
  last_latency_ms: number
  available: boolean
  initial_check_done: boolean
  timeline?: TimelineEvent[]
  domain_blacklist?: DomainBlock[]
}

export interface NodesPayload {
  nodes: NodeSnapshot[]
  total_nodes: number
  region_stats: Record<string, number>
  region_healthy: Record<string, number>
}

export interface DebugNode {
  tag: string
  name: string
  mode: string
  port: number
  failure_count: number
  success_count: number
  active_connections: number
  last_latency_ms: number
  last_success?: string
  last_failure?: string
  last_error?: string
  blacklisted: boolean
  domain_blacklist?: DomainBlock[]
  timeline?: TimelineEvent[]
}

export interface DebugPayload {
  nodes: DebugNode[]
  total_calls: number
  total_success: number
  success_rate: number
}

export interface SettingsPayload {
  external_ip: string
  probe_target: string
  skip_cert_verify: boolean
  proxy_username: string
  proxy_password: string
}

export interface SubscriptionStatus {
  enabled: boolean
  last_refresh?: string
  next_refresh?: string
  node_count?: number
  last_error?: string
  refresh_count?: number
  is_refreshing?: boolean
}

export interface SubscriptionItem {
  index: number
  url: string
  node_count: number
}

export interface SubscriptionListPayload {
  subscriptions: string[]
  items: SubscriptionItem[]
}

export interface SubscriptionLog {
  time: string
  subscription: string
  trigger: string
  level: string
  message: string
  node_count?: number
  duration_ms?: number
}

export interface ConfigNode {
  name: string
  uri: string
  node_ip?: string
  port?: number
  username?: string
  password?: string
  region?: string
  country?: string
  source?: string
  source_ref?: string
}

export interface ScriptSource {
  id: string
  name: string
  command: string
  args?: string[]
  script: string
  timeout_ms?: number
  setup_timeout_ms?: number
  max_output_bytes?: number
  max_nodes?: number
  python_requirements?: string[]
  enabled: boolean
  created_at?: string
  updated_at?: string
}

export interface ScriptRunResult {
  source_id: string
  exit_code: number
  duration_ms: number
  timed_out?: boolean
  stdout: string
  stdout_truncated?: boolean
  stderr: string
  stderr_truncated?: boolean
  error?: string
  nodes?: ConfigNode[]
  applied: boolean
  replaced_count?: number
  imported_count?: number
}

export interface RuntimeConfig {
  mode: string
  listener: {
    address: string
    port: number
    username?: string
    password?: string
  }
  named_pools: NamedPoolConfig[]
  multi_port: {
    address: string
    base_port: number
    username?: string
    password?: string
  }
  pool: PoolPolicy
  management_enabled: boolean
  management_listen: string
  management_password: string
  management_frontend_dist: string
  management_allowed_origins: string[]
  subscription_refresh: {
    enabled: boolean
    interval: number
    timeout: number
    health_check_timeout: number
    drain_timeout: number
    min_available_nodes: number
  }
  geoip: {
    enabled: boolean
    database_path: string
    listen: string
    port: number
    auto_update_enabled: boolean
    auto_update_interval: number
  }
  nodes_file: string
  log_level: string
}

export interface PoolPolicy {
  mode: string
  failure_threshold: number
  blacklist_duration: number
  domain_failure_threshold: number
  domain_blacklist_duration: number
  domain_recheck_interval: number
  domain_recheck_timeout: number
}

export interface NamedPoolConfig {
  name: string
  listener: {
    address: string
    port: number
    username?: string
    password?: string
  }
  pool: PoolPolicy
}

export interface ProbeEventStart {
  type: 'start'
  total: number
}

export interface ProbeEventProgress {
  type: 'progress'
  current: number
  total: number
  progress: number
  name: string
  latency?: number
  error?: string
}

export interface ProbeEventComplete {
  type: 'complete'
  success: number
  failed: number
}

export interface ProbeEventError {
  type: 'error'
  message: string
}

export type ProbeEvent =
  | ProbeEventStart
  | ProbeEventProgress
  | ProbeEventComplete
  | ProbeEventError
