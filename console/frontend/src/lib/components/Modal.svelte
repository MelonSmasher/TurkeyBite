<script lang="ts">
  import { X } from '@lucide/svelte';
  import type { Snippet } from 'svelte';

  let { open = $bindable(false), title, subtitle = '', width = 520, onclose, children, footer }: {
    open?: boolean;
    title: string;
    subtitle?: string;
    width?: number;
    onclose?: () => void;
    children: Snippet;
    footer?: Snippet;
  } = $props();

  let panel: HTMLDivElement | undefined = $state();
  let previous: Element | null = null;

  function close() {
    open = false;
    onclose?.();
  }

  function onkeydown(event: KeyboardEvent) {
    if (!open) return;
    if (event.key === 'Escape') {
      event.stopPropagation();
      close();
    }
    if (event.key === 'Tab' && panel) {
      // Keep focus inside the dialog while it is open
      const focusable = panel.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  }

  $effect(() => {
    if (open) {
      previous = document.activeElement;
      queueMicrotask(() => {
        const target = panel?.querySelector<HTMLElement>('[autofocus], input, select, textarea, button.btn-primary');
        (target ?? panel)?.focus();
      });
    } else if (previous instanceof HTMLElement) {
      previous.focus();
      previous = null;
    }
  });
</script>

<svelte:window {onkeydown} />

{#if open}
  <div class="backdrop" role="presentation" onclick={close}></div>
  <div class="wrap" role="presentation">
    <div bind:this={panel} class="panel" role="dialog" aria-modal="true" aria-label={title}
         tabindex="-1" style:max-width="{width}px">
      <header>
        <div class="titles">
          <h2>{title}</h2>
          {#if subtitle}<p class="muted">{subtitle}</p>{/if}
        </div>
        <button class="btn btn-ghost btn-icon btn-sm" onclick={close} aria-label="Close"><X size={16} /></button>
      </header>
      <div class="body">{@render children()}</div>
      {#if footer}<footer>{@render footer()}</footer>{/if}
    </div>
  </div>
{/if}

<style>
  .backdrop {
    position: fixed; inset: 0; z-index: 80;
    background: rgba(10, 12, 18, 0.42);
    backdrop-filter: blur(3px);
    animation: fade var(--med) var(--ease);
  }
  .wrap {
    position: fixed; inset: 0; z-index: 81; display: grid; place-items: start center;
    padding: 10vh 16px 16px; pointer-events: none; overflow: auto;
  }
  .panel {
    pointer-events: auto; width: 100%;
    background: var(--surface); border: 1px solid var(--border-strong);
    border-radius: var(--radius-xl); box-shadow: var(--shadow-lg);
    animation: pop var(--med) var(--ease);
    outline: none;
  }
  header { display: flex; align-items: flex-start; gap: 12px; padding: 18px 20px 6px; }
  .titles { flex: 1; display: flex; flex-direction: column; gap: 4px; }
  .titles p { font-size: 0.88rem; }
  .body { padding: 12px 20px 20px; }
  footer {
    display: flex; justify-content: flex-end; gap: 8px;
    padding: 14px 20px; border-top: 1px solid var(--divider);
    background: var(--surface-2); border-radius: 0 0 var(--radius-xl) var(--radius-xl);
  }
  @keyframes fade { from { opacity: 0; } }
  @keyframes pop { from { opacity: 0; transform: translateY(6px) scale(0.985); } }
</style>
