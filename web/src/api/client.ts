import { apiBaseURL, http, setStoredToken } from './http'
import type {
  ConfigNode,
  DebugPayload,
  NamedPoolConfig,
  NodesPayload,
  ProbeEvent,
  RuntimeConfig,
  SettingsPayload,
  SubscriptionListPayload,
  SubscriptionLog,
  SubscriptionStatus,
} from '../types/api'

export async function authLogin(password: string): Promise<{ noPassword?: boolean }> {
  const { data } = await http.post('/api/auth', { password })
  if (data?.token) {
    setStoredToken(String(data.token))
  }
  return { noPassword: !!data?.no_password }
}

export async function getNodes(): Promise<NodesPayload> {
  const { data } = await http.get('/api/nodes')
  return data
}

export async function probeNode(tag: string): Promise<number> {
  const { data } = await http.post(`/api/nodes/${encodeURIComponent(tag)}/probe`)
  if (data?.error) throw new Error(data.error)
  return Number(data?.latency_ms || 0)
}

export async function releaseNode(tag: string): Promise<void> {
  const { data } = await http.post(`/api/nodes/${encodeURIComponent(tag)}/release`)
  if (data?.error) throw new Error(data.error)
}

export async function banNode(payload: { node_ip: string; pool_name: string; duration: string }): Promise<any> {
  const { data } = await http.post('/api/nodes/ban', payload)
  if (data?.error) throw new Error(data.error)
  return data
}

export async function getDebug(): Promise<DebugPayload> {
  const { data } = await http.get('/api/debug')
  return data
}

export async function getBlacklist(): Promise<any> {
  const { data } = await http.get('/api/blacklist')
  return data
}

export async function getSettings(): Promise<SettingsPayload> {
  const { data } = await http.get('/api/settings')
  return data
}

export async function saveSettings(payload: SettingsPayload): Promise<any> {
  const { data } = await http.put('/api/settings', payload)
  if (data?.error) throw new Error(data.error)
  return data
}

export async function getRuntimeConfig(): Promise<RuntimeConfig> {
  const { data } = await http.get('/api/runtime-config')
  if (data?.error) throw new Error(data.error)
  return data.config as RuntimeConfig
}

export async function saveRuntimeConfig(config: RuntimeConfig, applyNow: boolean): Promise<any> {
  const { data } = await http.put('/api/runtime-config', {
    config,
    apply_now: applyNow,
  })
  if (data?.error) throw new Error(data.error)
  return data
}

export async function listPools(): Promise<NamedPoolConfig[]> {
  const { data } = await http.get('/api/pools')
  if (data?.error) throw new Error(data.error)
  return data.pools || []
}

export async function createPool(pool: NamedPoolConfig, applyNow = false): Promise<any> {
  const { data } = await http.post('/api/pools', { pool, apply_now: applyNow })
  if (data?.error) throw new Error(data.error)
  return data
}

export async function updatePool(poolName: string, pool: NamedPoolConfig, applyNow = false): Promise<any> {
  const { data } = await http.put(`/api/pools/${encodeURIComponent(poolName)}`, { pool, apply_now: applyNow })
  if (data?.error) throw new Error(data.error)
  return data
}

export async function deletePool(poolName: string, applyNow = false): Promise<any> {
  const url = `/api/pools/${encodeURIComponent(poolName)}${applyNow ? '?apply_now=true' : ''}`
  const { data } = await http.delete(url)
  if (data?.error) throw new Error(data.error)
  return data
}

export async function listSubscriptions(): Promise<SubscriptionListPayload> {
  const { data } = await http.get('/api/subscriptions')
  return data
}

export async function addSubscription(url: string): Promise<any> {
  const { data } = await http.post('/api/subscriptions', { url })
  if (data?.error) throw new Error(data.error)
  return data
}

export async function updateSubscription(index: number, url: string): Promise<any> {
  const { data } = await http.put(`/api/subscriptions/${index}`, { url })
  if (data?.error) throw new Error(data.error)
  return data
}

export async function deleteSubscription(index: number): Promise<any> {
  const { data } = await http.delete(`/api/subscriptions/${index}`)
  if (data?.error) throw new Error(data.error)
  return data
}

export async function refreshSubscription(index: number): Promise<any> {
  const { data } = await http.post(`/api/subscriptions/${index}/refresh`)
  if (data?.error) throw new Error(data.error)
  return data
}

export async function subscriptionLogs(index: number): Promise<{ subscription: string; logs: SubscriptionLog[] }> {
  const { data } = await http.get(`/api/subscriptions/${index}/logs`)
  return data
}

export async function globalSubscriptionStatus(): Promise<SubscriptionStatus> {
  const { data } = await http.get('/api/subscription/status')
  return data
}

export async function refreshAllSubscriptions(): Promise<any> {
  const { data } = await http.post('/api/subscription/refresh')
  if (data?.error) throw new Error(data.error)
  return data
}

export async function listConfigNodes(): Promise<ConfigNode[]> {
  const { data } = await http.get('/api/nodes/config')
  return data.nodes || []
}

export async function createConfigNode(payload: Partial<ConfigNode>): Promise<any> {
  const { data } = await http.post('/api/nodes/config', payload)
  if (data?.error) throw new Error(data.error)
  return data
}

export async function updateConfigNode(name: string, payload: Partial<ConfigNode>): Promise<any> {
  const { data } = await http.put(`/api/nodes/config/${encodeURIComponent(name)}`, payload)
  if (data?.error) throw new Error(data.error)
  return data
}

export async function deleteConfigNode(name: string): Promise<any> {
  const { data } = await http.delete(`/api/nodes/config/${encodeURIComponent(name)}`)
  if (data?.error) throw new Error(data.error)
  return data
}

export async function triggerReload(): Promise<any> {
  const { data } = await http.post('/api/reload')
  if (data?.error) throw new Error(data.error)
  return data
}

export function exportNodesURL(): string {
  return `${apiBaseURL()}/api/export`
}

export async function probeAllNodes(
  onEvent: (event: ProbeEvent) => void,
): Promise<void> {
  const token = localStorage.getItem('easy_proxies_session_token')
  const headers: Record<string, string> = {}
  if (token) headers.Authorization = `Bearer ${token}`

  const response = await fetch(`${apiBaseURL()}/api/nodes/probe-all`, {
    method: 'POST',
    headers,
    credentials: 'include',
  })

  if (!response.ok || !response.body) {
    throw new Error(`批量探测失败 (${response.status})`)
  }

  const reader = response.body.getReader()
  const decoder = new TextDecoder('utf-8')
  let buffer = ''

  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop() || ''
    for (const line of lines) {
      if (!line.startsWith('data: ')) continue
      const json = line.slice(6).trim()
      if (!json) continue
      try {
        const evt = JSON.parse(json) as ProbeEvent
        onEvent(evt)
      } catch {
        // ignore malformed chunk
      }
    }
  }
}
