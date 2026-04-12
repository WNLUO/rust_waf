<script setup lang="ts">
import { RouterView } from 'vue-router'
import AppNotifications from './components/ui/AppNotifications.vue'
</script>

<template>
  <!-- Main entry point, layout is handled per-page or in AppLayout component -->
  <RouterView />
  <AppNotifications />
</template>
