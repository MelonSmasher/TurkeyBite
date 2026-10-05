<script lang="ts">
  import type { Snippet } from 'svelte';

  let { trigger, children, align = 'end', width = 220, label = 'Menu' }: {
    trigger: Snippet<[{ toggle: () => void; open: boolean }]>;
    children: Snippet<[{ close: () => void }]>;
    align?: 'start' | 'end';
    width?: number;
    label?: string;
  } = $props();

  let open = $state(false);
  let root: HTMLDivElement | undefined = $state();

  function toggle() {
    open = !open;
  }
  function close() {
    open = false;
  }

  function onwindowclick(event: MouseEvent) {
    if (open && root && !root.contains(event.target as Node)) close();
  }
</script>

<svelte:window onclick={onwindowclick} onkeydown={(e) => { if (e.key === 'Escape') close(); }} />

<div class="menu" bind:this={root}>
  {@render trigger({ toggle, open })}
  {#if open}
    <div class="pop" class:start={align === 'start'} role="menu" aria-label={label} style:width="{width}px">
      {@render children({ close })}
    </div>
  {/if}
</div>

<style>
  .menu { position: relative; display: inline-flex; }
  .pop {
    position: absolute; top: calc(100% + 6px); right: 0; z-index: 60;
    background: var(--surface); border: 1px solid var(--border-strong);
    border-radius: var(--radius-lg); box-shadow: var(--shadow-lg); padding: 5px;
    animation: pop 140ms var(--ease);
  }
  .pop.start { right: auto; left: 0; }
  .pop :global(.menu-item) {
    display: flex; align-items: center; gap: 9px; width: 100%;
    padding: 7px 9px; border-radius: var(--radius-sm); border: 0; background: none;
    font-size: 0.9rem; color: var(--text-2); cursor: pointer; text-align: left; text-decoration: none;
  }
  .pop :global(.menu-item:hover) { background: var(--surface-hover); color: var(--text); text-decoration: none; }
  .pop :global(.menu-item.danger) { color: var(--sev-critical); }
  .pop :global(.menu-sep) { height: 1px; background: var(--divider); margin: 5px 2px; }
  .pop :global(.menu-label) { padding: 6px 9px 4px; font-size: 0.72rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-4); }
  @keyframes pop { from { opacity: 0; transform: translateY(-4px); } }
</style>
