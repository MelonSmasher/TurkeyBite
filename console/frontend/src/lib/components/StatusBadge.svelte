<script lang="ts">
  import { STATUS_LABEL } from '../format';

  let { status }: { status: string } = $props();
</script>

<span class="status status-{status}">
  <span class="ring"></span>{STATUS_LABEL[status] ?? status}
</span>

<style>
  .status {
    display: inline-flex; align-items: center; gap: 6px; font-size: 0.82rem; font-weight: 550;
    color: var(--text-2); white-space: nowrap;
  }
  .ring { width: 9px; height: 9px; border-radius: 999px; border: 2px solid var(--c); background: var(--fill, transparent); }
  .status-new { --c: var(--accent); --fill: var(--accent); }
  .status-acknowledged { --c: #f59f00; }
  .status-in_progress { --c: #3b82f6; --fill: color-mix(in srgb, #3b82f6 45%, transparent); }
  .status-resolved { --c: var(--good); --fill: var(--good); }
  .status-false_positive { --c: var(--text-4); }
</style>
