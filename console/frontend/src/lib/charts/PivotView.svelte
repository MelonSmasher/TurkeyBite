<script lang="ts">
  // A pivot's result, drawn as the chosen view. Shared by the analytics
  // workbench and dashboard widgets, so a widget looks as it did when built.
  import { compact, num } from '../format';
  import { fields } from '../stores/fields.svelte';
  import type { PivotResult, PivotSpec } from '../types';
  import BarList from './BarList.svelte';
  import { pivotLabel } from './labels';
  import StackedBars from './StackedBars.svelte';
  import TimeChart from './TimeChart.svelte';
  import { intervalMsOf, RISK_COLOR, slot } from './util';

  let { result, spec, viz = 'bar', height = 240, hrefFor, onrange }: {
    result: PivotResult;
    spec: PivotSpec;
    viz?: string;
    height?: number;
    hrefFor?: (key: string, field?: string | null) => string | undefined;
    onrange?: (start: number, end: number) => void;
  } = $props();

  const labelOf = pivotLabel;

  /** Severity is state and wears the status steps; anything else takes slots in order */
  function colorOf(key: string, i: number): string {
    if (spec.split === 'bite.risk_severity') return RISK_COLOR[key] ?? slot(i);
    return slot(i);
  }

  // Severities stack low to high, so the most severe sits on top
  const ORDER: Record<string, number> = { none: 0, low: 1, medium: 2, high: 3 };
  const series = $derived.by(() => {
    const list = [...(result.series ?? [])];
    if (spec.split === 'bite.risk_severity') list.sort((a, b) => (ORDER[a.key] ?? 0) - (ORDER[b.key] ?? 0));
    return list;
  });

  const splitLabel = $derived((k: string) => labelOf(k, spec.split));
</script>

{#if result.kind === 'series'}
  {@const times = (result.times ?? []).map((t) => new Date(t).getTime())}
  <TimeChart {times} intervalMs={intervalMsOf(result.interval ?? '1h')} {height} {onrange}
             kind={viz === 'line' ? 'line' : viz === 'area' ? 'area' : 'bar'}
             series={series.map((s, i) => ({ key: s.key, label: spec.split ? splitLabel(s.key) : spec.metric === 'unique' ? `Distinct ${fields.label(spec.metric_field).toLowerCase()}` : 'Events', color: colorOf(s.key, i), values: s.points }))} />
{:else if viz === 'number'}
  <div class="number">{compact(result.rows?.[0]?.value ?? result.total)}</div>
{:else if viz === 'table'}
  <div class="table-wrap">
    <table class="table">
      <thead>
        <tr>
          <th>{fields.label(spec.rows) || 'All'}</th>
          {#each result.columns ?? [] as c (c)}<th class="num">{splitLabel(c)}</th>{/each}
          <th class="num">{spec.metric === 'unique' ? `Distinct ${fields.label(spec.metric_field).toLowerCase()}` : 'Events'}</th>
        </tr>
      </thead>
      <tbody>
        {#each result.rows ?? [] as r (`${r.field ?? ''}\u0000${r.key}`)}
          {@const href = hrefFor?.(r.key, r.field ?? spec.rows)}
          <tr>
            <td>{#if href}<a {href} class="row-link">{labelOf(r.key, r.field ?? spec.rows)}</a>{:else}{labelOf(r.key, r.field ?? spec.rows)}{/if}</td>
            {#each result.columns ?? [] as c (c)}<td class="num muted">{num(r.cells[c] ?? 0)}</td>{/each}
            <td class="num"><strong>{num(r.value)}</strong></td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{:else if (result.columns ?? []).length}
  <StackedBars rows={(result.rows ?? []).map((r) => ({ ...r, id: `${r.field ?? ''}\u0000${r.key}`, label: labelOf(r.key, r.field ?? spec.rows) }))}
               columns={result.columns ?? []} labelFor={splitLabel}
               hrefFor={hrefFor ? (k) => hrefFor?.(k, spec.rows) : undefined} />
{:else}
  <BarList items={(result.rows ?? []).map((r) => ({ key: r.key, id: `${r.field ?? ''}\u0000${r.key}`, label: labelOf(r.key, r.field ?? spec.rows), value: r.value,
                                                     href: hrefFor?.(r.key, r.field ?? spec.rows) }))} />
{/if}

<style>
  .number { font-size: 2.6rem; font-weight: 700; letter-spacing: -0.03em; line-height: 1; padding: 6px 0 4px; }
  .row-link { color: var(--text); }
</style>
