const NS_MS = 1_000_000
const NS_S = 1_000_000_000
const NS_M = 60 * NS_S
const NS_H = 60 * NS_M
const NS_D = 24 * NS_H

export function formatDurationNs(input: number | string | undefined | null): string {
  const value = Number(input)
  if (!Number.isFinite(value) || value <= 0) return ''
  if (value % NS_D === 0) return `${value / NS_D}d`
  if (value % NS_H === 0) return `${value / NS_H}h`
  if (value % NS_M === 0) return `${value / NS_M}m`
  if (value % NS_S === 0) return `${value / NS_S}s`
  if (value % NS_MS === 0) return `${value / NS_MS}ms`
  return `${Math.trunc(value)}`
}

export function parseDurationNs(raw: string, fieldLabel: string, fallback = 0): number {
  const text = String(raw || '').trim()
  if (!text) return fallback
  if (/^\d+$/.test(text)) {
    return Number(text)
  }

  const source = text.toLowerCase().replace(/\s+/g, '')
  const re = /(\d+(?:\.\d+)?)(ms|s|m|h|d)/g
  let total = 0
  let cursor = 0
  while (true) {
    const match = re.exec(source)
    if (!match) break
    if (match.index !== cursor) {
      throw new Error(`${fieldLabel} 格式错误，示例: 30s / 10m / 2h / 1d`)
    }
    const amount = Number(match[1])
    const unit = match[2]
    if (unit === 'ms') total += amount * NS_MS
    else if (unit === 's') total += amount * NS_S
    else if (unit === 'm') total += amount * NS_M
    else if (unit === 'h') total += amount * NS_H
    else if (unit === 'd') total += amount * NS_D
    cursor = re.lastIndex
  }

  if (cursor !== source.length || total <= 0) {
    throw new Error(`${fieldLabel} 格式错误，示例: 30s / 10m / 2h / 1d`)
  }
  return Math.round(total)
}

export function formatRelativeTime(raw?: string): string {
  if (!raw || raw === '0001-01-01T00:00:00Z') return '从未'
  const date = new Date(raw)
  if (Number.isNaN(date.getTime())) return raw
  const diffSec = Math.floor((Date.now() - date.getTime()) / 1000)
  if (diffSec < 60) return `${diffSec} 秒前`
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)} 分钟前`
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)} 小时前`
  return `${Math.floor(diffSec / 86400)} 天前`
}

export function latencyLabel(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '未测试'
  if (ms < 100) return '优秀'
  if (ms < 200) return '良好'
  if (ms < 500) return '一般'
  return '较慢'
}
