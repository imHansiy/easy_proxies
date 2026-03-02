import { reactive } from 'vue'
import { AxiosError } from 'axios'
import { authLogin, getNodes } from '../api/client'
import { setStoredToken } from '../api/http'

type AuthStatus = 'unknown' | 'authenticated' | 'unauthenticated'

const state = reactive({
  status: 'unknown' as AuthStatus,
  checking: false,
})

export function useAuth() {
  async function check(): Promise<boolean> {
    if (state.status === 'authenticated') return true
    if (state.checking) return false
    state.checking = true
    try {
      await getNodes()
      state.status = 'authenticated'
      return true
    } catch (error) {
      if ((error as AxiosError).response?.status === 401) {
        state.status = 'unauthenticated'
      }
      return false
    } finally {
      state.checking = false
    }
  }

  async function login(password: string): Promise<void> {
    await authLogin(password)
    state.status = 'authenticated'
  }

  function logout(): void {
    setStoredToken('')
    state.status = 'unauthenticated'
  }

  return {
    state,
    check,
    login,
    logout,
  }
}
