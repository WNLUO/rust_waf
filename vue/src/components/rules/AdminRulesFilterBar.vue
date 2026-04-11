<script setup lang="ts">
import { Plus, Search } from 'lucide-vue-next'

defineProps<{
  filters: {
    search: string
    layer: string
    action: string
    severity: string
    status: string
  }
}>()

defineEmits<{
  create: []
  'update:filters': [
    value: {
      search: string
      layer: string
      action: string
      severity: string
      status: string
    },
  ]
}>()
</script>

<template>
  <div
    class="flex flex-wrap gap-3 rounded-[28px] border border-white/70 bg-white/60 p-4"
  >
    <label
      class="flex min-w-[200px] flex-1 items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-500"
    >
      <Search :size="14" />
      <input
        :value="filters.search"
        type="text"
        class="w-full bg-transparent text-stone-800 outline-none"
        placeholder="搜索名称 / ID / 匹配内容"
        @input="
          $emit('update:filters', {
            ...filters,
            search: ($event.target as HTMLInputElement).value,
          })
        "
      />
    </label>
    <select
      :value="filters.layer"
      class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
      @change="
        $emit('update:filters', {
          ...filters,
          layer: ($event.target as HTMLSelectElement).value,
        })
      "
    >
      <option value="all">全部层级</option>
      <option value="l4">四层</option>
      <option value="l7">七层</option>
    </select>
    <select
      :value="filters.action"
      class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
      @change="
        $emit('update:filters', {
          ...filters,
          action: ($event.target as HTMLSelectElement).value,
        })
      "
    >
      <option value="all">全部动作</option>
      <option value="block">拦截</option>
      <option value="allow">放行</option>
      <option value="alert">告警</option>
      <option value="respond">自定义响应</option>
    </select>
    <select
      :value="filters.severity"
      class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
      @change="
        $emit('update:filters', {
          ...filters,
          severity: ($event.target as HTMLSelectElement).value,
        })
      "
    >
      <option value="all">全部级别</option>
      <option value="low">低</option>
      <option value="medium">中</option>
      <option value="high">高</option>
      <option value="critical">紧急</option>
    </select>
    <select
      :value="filters.status"
      class="rounded-[18px] border border-slate-200 bg-white px-3 py-2 text-sm text-stone-700"
      @change="
        $emit('update:filters', {
          ...filters,
          status: ($event.target as HTMLSelectElement).value,
        })
      "
    >
      <option value="all">全部状态</option>
      <option value="enabled">启用</option>
      <option value="disabled">停用</option>
    </select>
    <button
      class="ml-auto inline-flex shrink-0 items-center gap-2 rounded-[18px] bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-600/90"
      @click="$emit('create')"
    >
      <Plus :size="16" />
      新建规则
    </button>
  </div>
</template>
