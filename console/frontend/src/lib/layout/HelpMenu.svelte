<script lang="ts">
  // Help, in the account menu: a submenu of the documentation site's pages,
  // which opens beside the menu, or in place on a narrow screen. Made each
  // time the account menu opens, so it always starts closed.
  import { ChevronLeft, LifeBuoy } from '@lucide/svelte';
  import { DOCS_WINDOW, HELP_LINKS } from '../docs';

  let { onchoose }: { onchoose: () => void } = $props();

  let open = $state(false);
  // Opened by the pointer passing over it rather than by a click. The click
  // that usually follows keeps it open instead of closing it again.
  let hovered = false;
  let button: HTMLButtonElement | undefined = $state();
  let menu: HTMLDivElement | undefined = $state();

  function show(focusFirst: boolean) {
    open = true;
    if (focusFirst) queueMicrotask(() => menu?.querySelector<HTMLElement>('a')?.focus());
  }

  function hide() {
    open = false;
    button?.focus();
  }

  function onclick() {
    if (open && !hovered) hide();
    else show(true);
    hovered = false;
  }

  function onenter() {
    if (!open) hovered = true;
    show(false);
  }

  // It opens to the left of the menu, so the left arrow goes into it and
  // the right arrow comes back out
  function onbuttonkey(event: KeyboardEvent) {
    if (event.key === 'ArrowLeft') {
      event.preventDefault();
      show(true);
    } else if (event.key === 'ArrowRight' && open) {
      event.preventDefault();
      hide();
    }
  }

  function onlinkkey(event: KeyboardEvent) {
    if (event.key === 'ArrowRight') {
      event.preventDefault();
      hide();
    }
  }
</script>

<div class="help" role="none" onmouseenter={onenter} onmouseleave={() => { open = false; hovered = false; }}>
  <button class="menu-item" bind:this={button} aria-haspopup="true" aria-expanded={open}
          {onclick} onkeydown={onbuttonkey}>
    <LifeBuoy size={15} /> Help <ChevronLeft size={15} class="chevron" />
  </button>
  {#if open}
    <div class="sub" role="group" aria-label="Help" bind:this={menu}>
      {#each HELP_LINKS as link (link.href)}
        <a class="menu-item" href={link.href} target={DOCS_WINDOW} onkeydown={onlinkkey}
           onclick={onchoose}><link.icon size={15} /> {link.label}</a>
      {/each}
    </div>
  {/if}
</div>

<style>
  .help { position: relative; }
  .help :global(.chevron) { margin-left: auto; color: var(--text-4); }
  .sub {
    position: absolute; top: -6px; right: calc(100% + 10px); width: 236px; z-index: 61;
    background: var(--surface); border: 1px solid var(--border-strong);
    border-radius: var(--radius-lg); box-shadow: var(--shadow-lg); padding: 5px;
    animation: pop 140ms var(--ease);
  }
  /* A bridge across the gap, so the pointer can reach the submenu */
  .sub::after { content: ''; position: absolute; top: 0; bottom: 0; left: 100%; width: 12px; }
  .sub :global(.menu-item) {
    display: flex; align-items: center; gap: 9px; width: 100%;
    padding: 7px 9px; border-radius: var(--radius-sm); font-size: 0.9rem; color: var(--text-2); text-decoration: none;
  }
  .sub :global(.menu-item:hover) { background: var(--surface-hover); color: var(--text); text-decoration: none; }
  @keyframes pop { from { opacity: 0; transform: translateX(4px); } }
  /* No room beside the menu on a narrow screen: it opens in place instead */
  @media (max-width: 640px) {
    .sub { position: static; width: auto; box-shadow: none; border: 0; padding: 0 0 0 14px; animation: none; }
    .sub::after { display: none; }
  }
</style>
