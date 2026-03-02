<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { Lock } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { useAuth } from '../composables/useAuth'

const router = useRouter()
const route = useRoute()
const auth = useAuth()

const loading = ref(false)
const form = reactive({ password: '' })

const redirectPath = computed(() => {
  const redirect = String(route.query.redirect || '/monitor')
  return redirect.startsWith('/') ? redirect : '/monitor'
})

async function submit() {
  loading.value = true
  try {
    await auth.login(form.password)
    ElMessage.success('登录成功')
    router.replace(redirectPath.value)
  } catch (error: any) {
    const message = error?.response?.data?.error || error?.message || '登录失败'
    ElMessage.error(message)
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  const ok = await auth.check()
  if (ok) {
    router.replace(redirectPath.value)
  }
})
</script>

<template>
  <div
    style="min-height: 100vh; display:flex; align-items:center; justify-content:center; padding: 20px;"
  >
    <el-card style="width: min(420px, 100%); border-radius: 18px;">
      <template #header>
        <div>
          <div style="font-size: 20px; font-weight: 700;">Easy Proxies</div>
          <div class="muted" style="margin-top: 4px;">管理面板登录</div>
        </div>
      </template>

      <el-form @submit.prevent="submit">
        <el-form-item label="访问密码">
          <el-input
            v-model="form.password"
            type="password"
            show-password
            :prefix-icon="Lock"
            placeholder="请输入管理密码"
            @keyup.enter="submit"
          />
        </el-form-item>
        <el-button type="primary" :loading="loading" style="width:100%;" @click="submit">
          登录
        </el-button>
      </el-form>
    </el-card>
  </div>
</template>
