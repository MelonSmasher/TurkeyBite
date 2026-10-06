<script lang="ts">
  import { CircleCheck, CircleX, Info, X } from '@lucide/svelte';
  import { toasts } from '../stores/toasts.svelte';
</script>

<div class="toasts" aria-live="polite">
  {#each toasts.items as toast (toast.id)}
    <div class="toast {toast.kind}" role={toast.kind === 'error' ? 'alert' : 'status'}>
      <span class="icon">
        {#if toast.kind === 'success'}<CircleCheck size={17} />{:else if toast.kind === 'error'}<CircleX size={17} />{:else}<Info size={17} />{/if}
      </span>
      <div class="text">
        <div class="title">{toast.title}</div>
        {#if toast.body}<div class="body">{toast.body}</div>{/if}
        {#if toast.action}<a href={toast.action.href}>{toast.action.label}</a>{/if}
      </div>
      <button class="btn btn-ghost btn-icon btn-sm" aria-label="Dismiss" onclick={() => toasts.dismiss(toast.id)}><X size={14} /></button>
    </div>
  {/each}
</div>

<style>
  .toasts { position: fixed; right: 18px; bottom: 18px; z-index: 120; display: flex; flex-direction: column; gap: 10px; width: min(380px, calc(100vw - 36px)); }
  .toast {
    display: flex; gap: 10px; align-items: flex-start; padding: 12px 10px 12px 14px;
    background: var(--surface); border: 1px solid var(--border-strong); border-radius: var(--radius-lg);
    box-shadow: var(--shadow-lg); animation: in 260ms var(--ease);
  }
  .icon { margin-top: 1px; }
  .success .icon { color: var(--good); }
  .error .icon { color: var(--sev-critical); }
  .info .icon { color: var(--accent); }
  .text { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 3px; }
  .title { font-weight: 600; font-size: 0.92rem; }
  .body { color: var(--text-2); font-size: 0.86rem; word-break: break-word; }
  @keyframes in { from { opacity: 0; transform: translateY(8px); } }
</style>
