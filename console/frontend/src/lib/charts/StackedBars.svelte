<script lang="ts">
  // Part-to-whole per row: horizontal, so long names have room. Segments are
  // separated by a surface gap; the legend names every colour.
  import { num } from '../format';
  import { barPath, slot } from './util';

  let { rows, columns, format = num, labelFor = (k: string) => k, hrefFor }: {
    rows: { key: string; id?: string; label?: string; value: number; cells: Record<string, number> }[];
    columns: string[];
    format?: (n: number) => string;
    labelFor?: (key: string) => string;
    hrefFor?: (key: string) => string | undefined;
  } = $props();

  let width = $state(400);
  let hover = $state<{ row: string; col: string; v: number } | null>(null);
  const top = $derived(Math.max(1, ...rows.map((r) => r.value)));
  const shown = $derived(columns.slice(0, 8));
</script>

<div class="stacked">
  <ul class="legend">
    {#each shown as c, i (c)}<li><span class="key" style:background={slot(i)}></span>{labelFor(c)}</li>{/each}
    {#if columns.length > 8 || rows.some((r) => r.value > Object.values(r.cells).reduce((a, b) => a + b, 0))}
      <li><span class="key" style:background="var(--deemph)"></span>Other</li>
    {/if}
  </ul>
  <div class="rows" bind:clientWidth={width}>
    {#each rows as r (r.id ?? r.key)}
      {@const segs = shown.map((c, i) => ({ c, v: r.cells[c] ?? 0, color: slot(i) }))}
      {@const rest = Math.max(0, r.value - segs.reduce((a, s) => a + s.v, 0))}
      {@const scale = (width - 4) / top}
      <svelte:element this={hrefFor?.(r.key) ? 'a' : 'div'} href={hrefFor?.(r.key)} class="row">
        <span class="label truncate">{r.label ?? r.key}</span>
        <span class="value tabular">{format(r.value)}</span>
        <svg width={width} height="10" class="bar" role="img" aria-label="{r.label ?? r.key}: {format(r.value)}">
          {#each [...segs, { c: 'Other', v: rest, color: 'var(--deemph)' }] as s, i (s.c)}
            {@const x = [...segs, { v: rest }].slice(0, i).reduce((a, p) => a + p.v * scale, 0)}
            {@const w = s.v * scale - 2}
            {#if w > 0.5}
              {@const last = [...segs, { v: rest }].slice(i + 1).every((p) => p.v * scale - 2 <= 0.5)}
              <path d={last ? barPath(x, 0, w, 10, 3) : `M${x},0h${w}v10h${-w}Z`} fill={s.color} role="graphics-symbol"
                    aria-label="{labelFor(s.c)}: {format(s.v)}"
                    onpointerenter={() => (hover = { row: r.key, col: s.c, v: s.v })} onpointerleave={() => (hover = null)}
                    opacity={hover && (hover.row !== r.key || hover.col !== s.c) ? 0.55 : 1} />
            {/if}
          {/each}
        </svg>
      </svelte:element>
    {/each}
  </div>
  <div class="readout muted">
    {#if hover}<strong class="tabular">{format(hover.v)}</strong> {labelFor(hover.col)} in {hover.row}{:else}Hover a segment for its value{/if}
  </div>
</div>

<style>
  .legend { list-style: none; display: flex; flex-wrap: wrap; gap: 4px 14px; padding: 0; margin: 0 0 10px; font-size: 0.8rem; color: var(--text-2); }
  .legend li { display: flex; align-items: center; gap: 6px; }
  .key { width: 10px; height: 10px; border-radius: 3px; }
  .rows { display: flex; flex-direction: column; gap: 2px; }
  .row { display: grid; grid-template-columns: minmax(0, 1fr) auto; grid-template-rows: auto 10px; column-gap: 12px; row-gap: 5px;
    padding: 6px 8px; margin: 0 -8px; border-radius: var(--radius-sm); text-decoration: none; color: var(--text); }
  a.row:hover { background: var(--surface-hover); text-decoration: none; }
  .label { font-size: 0.88rem; }
  .value { font-size: 0.86rem; font-weight: 600; color: var(--text-2); }
  .bar { grid-column: 1 / -1; display: block; max-width: 100%; }
  .readout { font-size: 0.8rem; margin-top: 8px; min-height: 18px; }
</style>
