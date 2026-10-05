<script lang="ts">
  // Ranked magnitudes: one series, so one colour for every bar, and the
  // value beside each so nothing hides behind a hover.
  import type { Snippet } from 'svelte';
  import { num } from '../format';
  import { barPath } from './util';

  interface Item {
    key: string;
    // Unique where keys may repeat: the same name under two fields
    id?: string;
    value: number;
    label?: string;
    href?: string;
    color?: string;
    sub?: string;
  }

  let { items, color = 'var(--s1)', format = num, max = undefined, label, empty = 'Nothing to show',
        onselect }: {
    items: Item[];
    color?: string;
    format?: (n: number) => string;
    max?: number;
    label?: Snippet<[Item]>;
    empty?: string;
    onselect?: (item: Item) => void;
  } = $props();

  const top = $derived(max ?? Math.max(1, ...items.map((i) => i.value)));
  let width = $state(300);
</script>

{#if !items.length}
  <div class="muted empty">{empty}</div>
{:else}
  <ul class="bar-list" bind:clientWidth={width}>
    {#each items as item (item.id ?? item.key)}
      {@const w = Math.max(2, ((width - 4) * item.value) / top)}
      <li>
        <svelte:element this={item.href ? 'a' : onselect ? 'button' : 'div'} class="row" href={item.href}
                        type={!item.href && onselect ? 'button' : undefined}
                        role={!item.href && !onselect ? 'listitem' : undefined}
                        onclick={onselect && !item.href ? () => onselect(item) : undefined}>
          <span class="label truncate">
            {#if label}{@render label(item)}{:else}{item.label ?? item.key}{/if}
            {#if item.sub}<span class="sub">{item.sub}</span>{/if}
          </span>
          <span class="value tabular">{format(item.value)}</span>
          <svg class="bar" width={width} height="6" aria-hidden="true">
            <path d={barPath(0, 0, w, 6, 3)} fill={item.color ?? color} />
          </svg>
        </svelte:element>
      </li>
    {/each}
  </ul>
{/if}

<style>
  .bar-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 2px; }
  .row {
    display: grid; grid-template-columns: minmax(0, 1fr) auto; grid-template-rows: auto 6px;
    column-gap: 12px; row-gap: 5px; padding: 6px 8px; margin: 0 -8px; border-radius: var(--radius-sm);
    color: var(--text); text-decoration: none; border: 0; background: none; width: calc(100% + 16px);
    text-align: left; font: inherit; cursor: default;
  }
  a.row, button.row { cursor: pointer; }
  a.row:hover, button.row:hover { background: var(--surface-hover); text-decoration: none; }
  .label { font-size: 0.88rem; display: flex; align-items: center; gap: 8px; min-width: 0; }
  .sub { color: var(--text-4); font-size: 0.8rem; }
  .value { font-size: 0.86rem; font-weight: 600; color: var(--text-2); }
  .bar { grid-column: 1 / -1; display: block; max-width: 100%; }
  .empty { padding: 18px 0; font-size: 0.88rem; }
</style>
