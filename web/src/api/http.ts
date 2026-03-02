import axios from 'axios'

const TOKEN_KEY = 'easy_proxies_session_token'

export function getStoredToken(): string {
  return localStorage.getItem(TOKEN_KEY) || ''
}

export function setStoredToken(token: string): void {
  if (!token) {
    localStorage.removeItem(TOKEN_KEY)
    return
  }
  localStorage.setItem(TOKEN_KEY, token)
}

export const http = axios.create({
  baseURL: import.meta.env.VITE_API_BASE || '',
  timeout: 30000,
  withCredentials: true,
})

http.interceptors.request.use((config) => {
  const token = getStoredToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

export function apiBaseURL(): string {
  return import.meta.env.VITE_API_BASE || ''
}
