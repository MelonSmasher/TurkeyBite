<script lang="ts">
  // When things happen: weekday by hour of day, in the viewer's time zone.
  // Magnitude, so one hue light to dark, with a scale legend beside it.
  import { num } from '../format';

  let { points, metric = 'count', label = 'events' }: {
    points: { t: string; count: number; notable?: number }[];
    metric?: 'count' | 'notable';
    label?: string;
  } = $props();

  const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const STEPS = ['var(--seq-1)', 'var(--seq-2)', 'var(--seq-3)', 'var(--seq-4)', 'var(--seq-5)', 'var(--seq-6)', 'var(--seq-7)'];

  const grid = $derived.by(() => {
    const cells = Array.from({ length: 7 }, () => Array.from({ length: 24 }, () => ({ v: 0, n: 0 })));
    for (const p of points) {
      const d = new Date(p.t);
      const day = (d.getDay() + 6) % 7;
      const cell = cells[day][d.getHours()];
      cell.v += metric === 'notable' ? (p.notable ?? 0) : p.count;
      cell.n += 1;
    }
    return cells;
  });
  const peak = $derived(Math.max(1, ...grid.flat().map((c) => c.v)));
  let hover = $state<{ day: number; hour: number; v: number } | null>(null);

  function step(v: number): string {
    if (v <= 0) return 'var(--surface-3)';
    return STEPS[Math.min(STEPS.length - 1, Math.floor((v / peak) * STEPS.length))];
  }
</script>

<div class="heatmap">
  <div class="grid" role="img" aria-label="Activity by weekday and hour">
    <div></div>
    {#each Array.from({ length: 24 }, (_, h) => h) as h (h)}
      <div class="hour">{h % 3 === 0 ? String(h).padStart(2, '0') : ''}</div>
    {/each}
    {#each grid as row, day (day)}
      <div class="day">{DAYS[day]}</div>
      {#each row as cell, hour (hour)}
        <div class="cell" style:background={step(cell.v)} role="presentation"
             onpointerenter={() => (hover = { day, hour, v: cell.v })} onpointerleave={() => (hover = null)}
             class:active={hover?.day === day && hover?.hour === hour}></div>
      {/each}
    {/each}
  </div>
  <div class="foot">
    <div class="readout">
      {#if hover}
        <strong class="tabular">{num(hover.v)}</strong> <span class="muted">{label}, {DAYS[hover.day]} {String(hover.hour).padStart(2, '0')}:00–{String((hover.hour + 1) % 24).padStart(2, '0')}:00</span>
      {:else}
        <span class="muted">Hover a cell for its count</span>
      {/if}
    </div>
    <div class="scale" aria-hidden="true">
      <span class="muted">Less</span>
      {#each STEPS as s (s)}<span class="swatch" style:background={s}></span>{/each}
      <span class="muted">More</span>
    </div>
  </div>
</div>

<style>
  .heatmap { display: flex; flex-direction: column; gap: 10px; }
  .grid { display: grid; grid-template-columns: 30px repeat(24, minmax(0, 1fr)); gap: 2px; }
  .hour { font-size: 0.66rem; color: var(--chart-muted); text-align: left; height: 14px; font-variant-numeric: tabular-nums; }
  .day { font-size: 0.72rem; color: var(--chart-muted); display: flex; align-items: center; }
  .cell { aspect-ratio: 1.35; border-radius: 3px; min-height: 10px; transition: transform var(--fast); }
  .cell.active { outline: 2px solid var(--text); outline-offset: 1px; }
  .foot { display: flex; align-items: center; gap: 12px; font-size: 0.8rem; min-height: 20px; }
  .readout { flex: 1; }
  .scale { display: flex; align-items: center; gap: 3px; font-size: 0.72rem; }
  .swatch { width: 12px; height: 10px; border-radius: 2px; }
  .scale .muted:first-child { margin-right: 4px; }
  .scale .muted:last-child { margin-left: 4px; }
</style>
