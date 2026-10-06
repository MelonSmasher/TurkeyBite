<script lang="ts">
  import { Globe } from '@lucide/svelte';
  import { timeRange } from '../stores/timerange.svelte';

  let { domain, icon = true }: { domain: string | null | undefined; icon?: boolean } = $props();
  const href = $derived(domain
    ? `/domains/${encodeURIComponent(domain)}?from=${encodeURIComponent(timeRange.from)}&to=${encodeURIComponent(timeRange.to)}`
    : '#');
</script>

{#if domain}
  <a class="domain" {href} title={domain}>
    {#if icon}<Globe size={12} />{/if}<span class="truncate">{domain}</span>
  </a>
{:else}
  <span class="muted">–</span>
{/if}

<style>
  .domain { display: inline-flex; align-items: center; gap: 5px; min-width: 0; max-width: 100%;
    color: var(--text); font-family: var(--font-mono); font-size: 0.85em; }
  .domain:hover { color: var(--accent-text); text-decoration: none; }
  .domain :global(svg) { color: var(--text-4); flex: none; }
</style>
