<script lang="ts">
  import type { Component, Snippet } from 'svelte';
  import { Inbox } from '@lucide/svelte';

  let { title, body = '', icon = Inbox, compact = false, children }: {
    title: string;
    body?: string;
    icon?: Component<any>;
    compact?: boolean;
    children?: Snippet;
  } = $props();
  const Icon = $derived(icon);
</script>

<div class="empty-state" class:compact>
  <div class="badge-icon"><Icon size={compact ? 18 : 22} /></div>
  <div class="title">{title}</div>
  {#if body}<p class="muted">{body}</p>{/if}
  {#if children}<div class="actions">{@render children()}</div>{/if}
</div>

<style>
  .empty-state { display: flex; flex-direction: column; align-items: center; text-align: center; gap: 8px; padding: 48px 20px; }
  .compact { padding: 24px 12px; }
  .badge-icon {
    width: 46px; height: 46px; border-radius: 14px; display: grid; place-items: center;
    background: var(--surface-3); color: var(--text-3); border: 1px solid var(--border); margin-bottom: 4px;
  }
  .compact .badge-icon { width: 36px; height: 36px; border-radius: 10px; }
  .title { font-weight: 600; }
  p { max-width: 420px; font-size: 0.9rem; }
  .actions { margin-top: 8px; display: flex; gap: 8px; }
</style>
