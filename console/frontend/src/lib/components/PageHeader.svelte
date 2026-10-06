<script lang="ts">
  import type { Snippet } from 'svelte';

  let { title, subtitle = '', eyebrow = '', actions, filters, children }: {
    title: string;
    subtitle?: string;
    eyebrow?: string;
    actions?: Snippet;
    filters?: Snippet;
    children?: Snippet;
  } = $props();
</script>

<header class="page-header">
  <div class="top">
    <div class="titles">
      {#if eyebrow}<div class="eyebrow">{eyebrow}</div>{/if}
      <h1>{title}</h1>
      {#if subtitle}<p class="subtitle">{subtitle}</p>{/if}
      {#if children}{@render children()}{/if}
    </div>
    {#if actions}<div class="actions">{@render actions()}</div>{/if}
  </div>
  {#if filters}<div class="filters">{@render filters()}</div>{/if}
</header>

<style>
  .page-header { display: flex; flex-direction: column; gap: 14px; margin-bottom: 20px; }
  .top { display: flex; align-items: flex-end; gap: 16px; flex-wrap: wrap; }
  .titles { flex: 1; min-width: 240px; display: flex; flex-direction: column; gap: 5px; }
  .eyebrow { font-size: 0.78rem; font-weight: 600; color: var(--accent-text); letter-spacing: 0.01em; }
  .subtitle { color: var(--text-3); font-size: 0.94rem; max-width: 760px; }
  .actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .filters { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
</style>
