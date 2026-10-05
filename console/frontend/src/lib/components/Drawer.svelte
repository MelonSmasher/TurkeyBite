<script lang="ts">
  import { X } from '@lucide/svelte';
  import type { Snippet } from 'svelte';
  import { trap } from './focus';

  let { open = $bindable(false), title, subtitle = '', width = 620, onclose, children, actions, header }: {
    open?: boolean;
    title: string;
    subtitle?: string;
    width?: number;
    onclose?: () => void;
    children: Snippet;
    actions?: Snippet;
    header?: Snippet;
  } = $props();

  function close() {
    open = false;
    onclose?.();
  }
</script>

<svelte:window onkeydown={(e) => { if (open && e.key === 'Escape') close(); }} />

{#if open}
  <div class="backdrop" role="presentation" onclick={close}></div>
  <div class="drawer" role="dialog" aria-modal="true" aria-label={title} style:width="min({width}px, 100vw)" use:trap>
    <header>
      <div class="titles">
        {#if header}{@render header()}{:else}
          <h2 class="truncate">{title}</h2>
          {#if subtitle}<p class="muted truncate">{subtitle}</p>{/if}
        {/if}
      </div>
      {#if actions}<div class="row">{@render actions()}</div>{/if}
      <button class="btn btn-ghost btn-icon btn-sm" onclick={close} aria-label="Close"><X size={16} /></button>
    </header>
    <div class="body">{@render children()}</div>
  </div>
{/if}

<style>
  .backdrop { position: fixed; inset: 0; z-index: 70; background: rgba(10, 12, 18, 0.28); animation: fade var(--med) var(--ease); }
  .drawer {
    position: fixed; top: 0; right: 0; bottom: 0; z-index: 71;
    background: var(--surface); border-left: 1px solid var(--border-strong);
    box-shadow: var(--shadow-lg); display: flex; flex-direction: column;
    animation: slide 260ms var(--ease);
  }
  header {
    display: flex; align-items: center; gap: 10px; padding: 16px 18px;
    border-bottom: 1px solid var(--divider);
  }
  .titles { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 3px; }
  .titles p { font-size: 0.86rem; }
  .body { flex: 1; overflow: auto; padding: 18px; }
  .drawer:focus { outline: none; }
  @keyframes fade { from { opacity: 0; } }
  @keyframes slide { from { transform: translateX(24px); opacity: 0; } }
</style>
