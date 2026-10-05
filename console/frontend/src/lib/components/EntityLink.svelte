<script lang="ts">
  // A person or machine, linked to their profile. Masked in privacy mode.
  import { Laptop, Network, Server, User } from '@lucide/svelte';
  import { who } from '../privacy';
  import { prefs } from '../stores/prefs.svelte';
  import { timeRange } from '../stores/timerange.svelte';

  let { field, value, plain = false, size = 'md' }: {
    field: string | null | undefined;
    value: string | null | undefined;
    plain?: boolean;
    size?: 'sm' | 'md';
  } = $props();

  const icon = $derived(
    field === 'bite.client_user' ? User
      : field === 'bite.client' || field === 'bite.client_ips' ? Network
      : field?.includes('hosts') || field === 'bite.ptr' ? Server : Laptop);
  const Icon = $derived(icon);
  const shown = $derived(value ? (prefs.privacy ? who(value) : value) : '–');
  const href = $derived(field && value
    ? `/entities/${encodeURIComponent(field)}/${encodeURIComponent(value)}?from=${encodeURIComponent(timeRange.from)}&to=${encodeURIComponent(timeRange.to)}`
    : null);
</script>

{#if !value}
  <span class="muted">{field ? '–' : 'Network-wide'}</span>
{:else if plain || !href}
  <span class="entity {size}" class:masked={prefs.privacy}><Icon size={size === 'sm' ? 12 : 13} /><span class="truncate">{shown}</span></span>
{:else}
  <a class="entity {size}" class:masked={prefs.privacy} {href}><Icon size={size === 'sm' ? 12 : 13} /><span class="truncate">{shown}</span></a>
{/if}

<style>
  .entity {
    display: inline-flex; align-items: center; gap: 5px; max-width: 100%; min-width: 0;
    font-weight: 550; color: var(--text); font-size: 0.92em;
  }
  a.entity:hover { color: var(--accent-text); text-decoration: none; }
  .entity :global(svg) { color: var(--text-3); flex: none; }
  .masked { font-family: var(--font-mono); font-size: 0.86em; letter-spacing: -0.01em; }
  .sm { font-size: 0.84em; }
</style>
