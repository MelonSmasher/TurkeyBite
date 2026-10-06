<script lang="ts">
  // Events over time: stacked columns, stacked areas, or lines.
  //
  // The crosshair finds the time; the tooltip lists every series there, value
  // first. Dragging across the plot selects a range, which zooms the page's
  // time range. A legend appears for two or more series and isolates one on
  // click; colour follows the series, so hiding one never repaints another.
  import { max } from 'd3-array';
  import { scaleLinear, scaleTime } from 'd3-scale';
  import { area as d3area, curveMonotoneX, line as d3line } from 'd3-shape';
  import { compact, num } from '../format';
  import { axisTime, columnPath, tooltipTime, type Series } from './util';

  let { times, series, kind = 'bar', intervalMs, height = 220, format = num, onrange, legend = true,
        empty = 'Nothing in this range', yLabel = '', marks = [] }: {
    times: number[];
    series: Series[];
    kind?: 'bar' | 'area' | 'line';
    intervalMs: number;
    height?: number;
    format?: (n: number) => string;
    onrange?: (start: number, end: number) => void;
    legend?: boolean;
    empty?: string;
    yLabel?: string;
    /** Labelled moments on the time axis, such as where raw events begin */
    marks?: { t: number; label: string }[];
  } = $props();

  let width = $state(600);
  let hidden = $state<Set<string>>(new Set());
  let hover = $state<number | null>(null);
  let brushStart = $state<number | null>(null);
  let brushEnd = $state<number | null>(null);
  let svg: SVGSVGElement | undefined = $state();

  const M = { top: 10, right: 12, bottom: 26, left: 46 };
  const visible = $derived(series.filter((s) => !hidden.has(s.key)));
  const plotW = $derived(Math.max(10, width - M.left - M.right));
  const plotH = $derived(height - M.top - M.bottom);
  const start = $derived(times.length ? times[0] : 0);
  const end = $derived(times.length ? times[times.length - 1] + intervalMs : 1);
  const x = $derived(scaleTime().domain([start, end]).range([0, plotW]));
  const stacked = $derived(kind !== 'line');

  // Running totals per bucket for stacking, bottom series first
  const stacks = $derived.by(() => {
    const out: { key: string; color: string; lo: number[]; hi: number[]; values: number[] }[] = [];
    const base = times.map(() => 0);
    for (const s of visible) {
      const lo = stacked ? [...base] : times.map(() => 0);
      const hi = s.values.map((v, i) => lo[i] + (v || 0));
      if (stacked) hi.forEach((v, i) => (base[i] = v));
      out.push({ key: s.key, color: s.color, lo, hi, values: s.values });
    }
    return out;
  });
  const top = $derived(max(stacks.flatMap((s) => s.hi)) ?? 0);
  const y = $derived(scaleLinear().domain([0, Math.max(1, top)]).nice(4).range([plotH, 0]));
  // Counts are whole numbers, so a small axis shows 0, 1, 2 rather than 0.2 steps
  const yTicks = $derived(y.ticks(4).filter((t) => Number.isInteger(t)));
  const xTicks = $derived(x.ticks(Math.max(2, Math.min(8, Math.floor(plotW / 110)))));
  const tickFmt = $derived(axisTime(end - start));
  const allZero = $derived(top === 0);

  const bucketPx = $derived(times.length ? plotW / times.length : plotW);
  const barW = $derived(Math.max(1, Math.min(24, bucketPx - 2)));

  const areaGen = $derived(d3area<number>()
    .x((_, i) => x(times[i] + intervalMs / 2))
    .curve(curveMonotoneX));
  const lineGen = $derived(d3line<number>()
    .x((_, i) => x(times[i] + intervalMs / 2))
    .curve(curveMonotoneX));

  function indexAt(clientX: number): number | null {
    if (!svg || !times.length) return null;
    const rect = svg.getBoundingClientRect();
    const px = clientX - rect.left - M.left;
    if (px < 0 || px > plotW) return null;
    const t = x.invert(px).getTime();
    return Math.max(0, Math.min(times.length - 1, Math.floor((t - start) / intervalMs)));
  }

  function onpointermove(event: PointerEvent) {
    hover = indexAt(event.clientX);
    if (brushStart !== null && svg) {
      const rect = svg.getBoundingClientRect();
      brushEnd = Math.max(0, Math.min(plotW, event.clientX - rect.left - M.left));
    }
  }

  function onpointerdown(event: PointerEvent) {
    if (!onrange || !svg || event.button !== 0) return;
    const rect = svg.getBoundingClientRect();
    brushStart = Math.max(0, Math.min(plotW, event.clientX - rect.left - M.left));
    brushEnd = brushStart;
    svg.setPointerCapture(event.pointerId);
  }

  function onpointerup() {
    if (brushStart !== null && brushEnd !== null && onrange && Math.abs(brushEnd - brushStart) > 8) {
      const a = x.invert(Math.min(brushStart, brushEnd)).getTime();
      const b = x.invert(Math.max(brushStart, brushEnd)).getTime();
      onrange(a, b);
    }
    brushStart = null;
    brushEnd = null;
  }

  function toggle(key: string, event: MouseEvent) {
    const next = new Set(hidden);
    if (event.altKey || event.metaKey) {
      // Isolate: show only this one, or everything again
      const only = series.every((s) => s.key === key || next.has(s.key)) && !next.has(key);
      next.clear();
      if (!only) series.forEach((s) => s.key !== key && next.add(s.key));
    } else if (next.has(key)) next.delete(key);
    else if (visible.length > 1) next.add(key);
    hidden = next;
  }

  const tooltipLeft = $derived(hover === null ? 0 : x(times[hover] + intervalMs / 2) + M.left);
  const hoverTotal = $derived(hover === null ? 0 : visible.reduce((a, s) => a + (s.values[hover!] || 0), 0));
  const summary = $derived(`${series.map((s) => s.label).join(', ')} over time; peak ${format(top)}.`);
</script>

<div class="time-chart" bind:clientWidth={width}>
  {#if legend && series.length > 1}
    <ul class="legend">
      {#each series as s (s.key)}
        <li><button type="button" class="legend-item" class:off={hidden.has(s.key)} aria-pressed={!hidden.has(s.key)}
                onclick={(e) => toggle(s.key, e)} title="Click to hide, alt-click to isolate">
          {#if kind === 'line'}<span class="key-line" style:background={s.color}></span>
          {:else}<span class="key-rect" style:background={s.color}></span>{/if}
          {s.label}
        </button></li>
      {/each}
    </ul>
  {/if}
  <div class="plot" style:height="{height}px">
    <svg bind:this={svg} {width} {height} role="img" aria-label={summary}
         onpointermove={onpointermove} onpointerleave={() => (hover = null)}
         onpointerdown={onpointerdown} onpointerup={onpointerup} class:brushable={!!onrange}>
      <g transform="translate({M.left},{M.top})">
        {#each yTicks as t (t)}
          <line class="grid" x1="0" x2={plotW} y1={y(t)} y2={y(t)} />
          <text class="tick" x="-8" y={y(t)} dy="0.32em" text-anchor="end">{compact(t)}</text>
        {/each}
        {#if yLabel}<text class="tick" x={-M.left + 2} y="-2">{yLabel}</text>{/if}
        {#each xTicks as t (t.getTime())}
          <text class="tick" x={x(t)} y={plotH + 17} text-anchor="middle">{tickFmt(t)}</text>
        {/each}

        {#if hover !== null}
          <rect class="hover-band" x={x(times[hover])} y="0" width={Math.max(1, x(times[hover] + intervalMs) - x(times[hover]))} height={plotH} />
        {/if}

        {#if kind === 'bar'}
          {#each stacks as s, si (s.key)}
            {#each s.hi as hi, i (i)}
              {@const v = hi - s.lo[i]}
              {#if v > 0}
                {@const isTop = stacks.slice(si + 1).every((o) => o.hi[i] - o.lo[i] <= 0)}
                {@const y0 = y(s.lo[i])}
                {@const y1 = y(hi)}
                {@const gap = si > 0 && s.lo[i] > 0 ? 2 : 0}
                {@const h = Math.max(isTop ? 1.5 : 0, y0 - y1 - gap)}
                <path d={isTop ? columnPath(x(times[i]) + (bucketPx - barW) / 2, y0 - gap - h, barW, h, Math.min(4, barW / 2))
                         : `M${x(times[i]) + (bucketPx - barW) / 2},${y0 - gap}h${barW}v${-h}h${-barW}Z`}
                      fill={s.color} opacity={hover === null || hover === i ? 1 : 0.55} />
              {/if}
            {/each}
          {/each}
        {:else}
          {#each stacks as s (s.key)}
            {#if kind === 'area'}
              <path d={areaGen.y0((_, i) => y(s.lo[i])).y1((_, i) => y(s.hi[i]))(s.hi) ?? ''}
                    fill={s.color} opacity={stacked && stacks.length > 1 ? 0.22 : 0.1} />
            {/if}
            <path d={lineGen.y((_, i) => y(s.hi[i]))(s.hi) ?? ''} fill="none" stroke={s.color}
                  stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />
          {/each}
          {#if hover !== null}
            <line class="crosshair" x1={x(times[hover] + intervalMs / 2)} x2={x(times[hover] + intervalMs / 2)} y1="0" y2={plotH} />
            {#each stacks as s (s.key)}
              <circle cx={x(times[hover] + intervalMs / 2)} cy={y(s.hi[hover])} r="4" fill={s.color}
                      stroke="var(--chart-surface)" stroke-width="2" />
            {/each}
          {/if}
        {/if}
        <line class="baseline" x1="0" x2={plotW} y1={plotH} y2={plotH} />
        {#each marks as m (m.t)}
          {#if m.t >= start && m.t <= end}
            <line class="mark" x1={x(m.t)} x2={x(m.t)} y1="0" y2={plotH} />
            <text class="mark-label" x={x(m.t) + 6} y="10">{m.label}</text>
          {/if}
        {/each}
        {#if brushStart !== null && brushEnd !== null}
          <rect class="brush" x={Math.min(brushStart, brushEnd)} y="0" width={Math.abs(brushEnd - brushStart)} height={plotH} />
        {/if}
      </g>
    </svg>
    {#if allZero}
      <div class="empty-overlay muted">{empty}</div>
    {/if}
    {#if hover !== null && !allZero && brushStart === null}
      <div class="tooltip" style:left="{tooltipLeft}px" class:flip={tooltipLeft > width * 0.62}>
        <div class="tt-time">{tooltipTime(times[hover], intervalMs)}</div>
        {#each [...visible].reverse() as s (s.key)}
          <div class="tt-row">
            <span class="tt-key" style:background={s.color}></span>
            <span class="tt-value tabular">{format(s.values[hover] || 0)}</span>
            <span class="tt-label">{s.label}</span>
          </div>
        {/each}
        {#if visible.length > 1 && stacked}
          <div class="tt-row total"><span class="tt-key blank"></span><span class="tt-value tabular">{format(hoverTotal)}</span><span class="tt-label">Total</span></div>
        {/if}
      </div>
    {/if}
  </div>
</div>

<style>
  .time-chart { position: relative; width: 100%; user-select: none; }
  .legend { display: flex; flex-wrap: wrap; gap: 4px 14px; margin: 2px 0 8px; padding: 0; list-style: none; }
  .legend-item {
    display: inline-flex; align-items: center; gap: 7px; border: 0; background: none; padding: 2px 0;
    font-size: 0.8rem; color: var(--text-2); cursor: pointer;
  }
  .legend-item.off { color: var(--text-4); }
  .legend-item.off .key-rect, .legend-item.off .key-line { opacity: 0.25; }
  .key-rect { width: 10px; height: 10px; border-radius: 3px; }
  .key-line { width: 14px; height: 2px; border-radius: 2px; }
  .plot { position: relative; }
  svg { display: block; overflow: visible; touch-action: pan-y; }
  svg.brushable { cursor: crosshair; }
  .grid { stroke: var(--grid); stroke-width: 1; shape-rendering: crispEdges; }
  .baseline { stroke: var(--axis); stroke-width: 1; shape-rendering: crispEdges; }
  .tick { fill: var(--chart-muted); font-size: 10.5px; font-variant-numeric: tabular-nums; }
  .crosshair { stroke: var(--text-4); stroke-width: 1; shape-rendering: crispEdges; }
  .mark { stroke: var(--text-3); stroke-width: 1; shape-rendering: crispEdges; }
  .mark-label { fill: var(--text-2); font-size: 10.5px; font-weight: 600; }
  .hover-band { fill: var(--text); opacity: 0.035; }
  .brush { fill: var(--accent); opacity: 0.12; stroke: var(--accent); stroke-width: 1; }
  .empty-overlay { position: absolute; inset: 0 0 26px 46px; display: grid; place-items: center; font-size: 0.88rem; }
  .tooltip {
    position: absolute; top: 4px; transform: translateX(14px); z-index: 5; pointer-events: none;
    min-width: 150px; max-width: 280px; padding: 9px 11px; border-radius: var(--radius);
    background: var(--surface-overlay); backdrop-filter: blur(8px);
    border: 1px solid var(--border-strong); box-shadow: var(--shadow-lg);
  }
  .tooltip.flip { transform: translateX(calc(-100% - 14px)); }
  .tt-time { font-size: 0.74rem; color: var(--text-3); margin-bottom: 6px; white-space: nowrap; }
  .tt-row { display: flex; align-items: center; gap: 8px; font-size: 0.82rem; line-height: 1.65; }
  .tt-key { width: 12px; height: 2px; border-radius: 2px; flex: none; }
  .tt-key.blank { background: transparent; }
  .tt-value { font-weight: 650; color: var(--text); min-width: 42px; }
  .tt-label { color: var(--text-3); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .total { border-top: 1px solid var(--divider); margin-top: 4px; padding-top: 3px; }
</style>
