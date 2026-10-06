<script lang="ts" generics="T extends string">
  import type { Component } from 'svelte';

  let { value = $bindable(), options, onchange, size = 'md', label = '' }: {
    value: T;
    options: { value: T; label: string; icon?: Component<any>; title?: string }[];
    onchange?: (value: T) => void;
    size?: 'sm' | 'md';
    label?: string;
  } = $props();
</script>

<div class="seg {size}" role="radiogroup" aria-label={label}>
  {#each options as option (option.value)}
    <button type="button" role="radio" aria-checked={value === option.value} class:on={value === option.value}
            aria-label={option.label ? undefined : option.title} title={option.label ? undefined : option.title}
            onclick={() => { value = option.value; onchange?.(option.value); }}>
      {#if option.icon}<option.icon size={14} />{/if}
      {#if option.label}<span>{option.label}</span>{/if}
    </button>
  {/each}
</div>

<style>
  .seg {
    display: inline-flex; padding: 2px; gap: 2px; border-radius: var(--radius);
    background: var(--surface-sunken); border: 1px solid var(--border);
  }
  button {
    display: inline-flex; align-items: center; gap: 6px; height: 28px; padding: 0 10px;
    border: 0; border-radius: 6px; background: transparent; color: var(--text-3);
    font-size: 0.86rem; font-weight: 500; cursor: pointer; white-space: nowrap;
    transition: background var(--fast), color var(--fast);
  }
  .sm button { height: 24px; padding: 0 8px; font-size: 0.8rem; }
  button:hover { color: var(--text); }
  button.on { background: var(--surface); color: var(--text); box-shadow: var(--shadow-sm); }
  :global(:root[data-theme='dark']) button.on { background: var(--surface-3); }
</style>
