<script lang="ts">
  let { checked = $bindable(false), label = '', disabled = false, onchange, size = 'md' }: {
    checked?: boolean;
    label?: string;
    disabled?: boolean;
    onchange?: (value: boolean) => void;
    size?: 'sm' | 'md';
  } = $props();

  function toggle(event: MouseEvent) {
    event.stopPropagation();
    if (disabled) return;
    checked = !checked;
    onchange?.(checked);
  }
</script>

<button type="button" role="switch" aria-checked={checked} aria-label={label} class="switch {size}"
        class:on={checked} {disabled} onclick={toggle}>
  <span class="knob"></span>
</button>

<style>
  .switch {
    position: relative; width: 34px; height: 20px; border-radius: 999px; flex: none;
    background: var(--surface-sunken); border: 1px solid var(--border-strong); cursor: pointer; padding: 0;
    transition: background var(--med) var(--ease), border-color var(--med);
  }
  .switch.sm { width: 28px; height: 16px; }
  .knob {
    position: absolute; top: 2px; left: 2px; width: 14px; height: 14px; border-radius: 999px;
    background: #fff; box-shadow: 0 1px 2px rgba(0, 0, 0, 0.25);
    transition: transform var(--med) var(--ease);
  }
  .sm .knob { width: 10px; height: 10px; }
  .on { background: var(--accent); border-color: transparent; }
  .on .knob { transform: translateX(14px); }
  .sm.on .knob { transform: translateX(12px); }
  :global(:root[data-theme='dark']) .on .knob { background: var(--text-on-accent, #fff); }
  .switch:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
