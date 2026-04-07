<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, RouterView, useRoute } from 'vue-router'

const route = useRoute()

const isAdminRoute = computed(() => route.path.startsWith('/admin'))
</script>

<template>
  <div class="app-shell" :data-mode="isAdminRoute ? 'admin' : 'site'">
    <header class="topbar">
      <RouterLink class="brand" to="/">
        <span class="brand-mark">RW</span>
        <span>
          <strong>Rust WAF</strong>
          <small>Security Gateway</small>
        </span>
      </RouterLink>

      <nav class="topnav">
        <RouterLink to="/" class="topnav-link">前台首页</RouterLink>
        <RouterLink to="/admin" class="topnav-link">后台控制台</RouterLink>
      </nav>
    </header>

    <RouterView />
  </div>
</template>
