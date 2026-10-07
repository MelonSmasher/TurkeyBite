<script lang="ts">
  // An address that looks the device up in the system an admin linked, in a
  // new tab. In privacy mode a button, so the address is in no link to see
  import { ExternalLink } from '@lucide/svelte';
  import { lookupHost, lookupHref } from '../devicelookup';
  import { who } from '../privacy';
  import { prefs } from '../stores/prefs.svelte';
  import { session } from '../stores/session.svelte';
  import { tip } from './tooltip';

  let { value, label = null, button = false }: { value: string; label?: string | null; button?: boolean } = $props();
  const href = $derived(lookupHref(session.me?.device_lookup_url, value));
  const host = $derived(lookupHost(session.me?.device_lookup_url));
  const text = $derived(label ?? who(value, 'bite.client'));
  const hint = $derived(`Look this device up at ${host}`);

  function open() {
    if (href) window.open(href, '_blank', 'noopener,noreferrer');
  }
</script>

{#if href}
  {#if prefs.privacy}
    <button type="button" class={button ? 'btn' : 'lookup mono'} onclick={open} use:tip={hint}>
      {text}<ExternalLink size={button ? 14 : 12} aria-hidden="true" /><span class="sr-only">({hint}, in a new tab)</span>
    </button>
  {:else}
    <a class={button ? 'btn' : 'lookup mono'} {href} target="_blank" rel="noopener noreferrer" use:tip={hint}>
      {text}<ExternalLink size={button ? 14 : 12} aria-hidden="true" /><span class="sr-only">({hint}, in a new tab)</span>
    </a>
  {/if}
{/if}

<style>
  .lookup {
    display: inline-flex; align-items: center; gap: 4px; padding: 0; border: 0; background: none; cursor: pointer;
    font: inherit; color: var(--accent-text); text-decoration: none;
  }
  .lookup:hover { text-decoration: underline; }
  .btn { gap: 6px; }
</style>
