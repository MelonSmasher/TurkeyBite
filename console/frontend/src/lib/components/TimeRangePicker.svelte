<script lang="ts">
  // Presets as rows, the selected one checked; a custom range behind the
  // hairline at the foot.
  import { CalendarClock, Check, ChevronDown } from '@lucide/svelte';
  import { PRESETS, timeRange } from '../stores/timerange.svelte';

  let { presets = PRESETS }: { presets?: typeof PRESETS } = $props();
  let open = $state(false);
  let root: HTMLDivElement | undefined = $state();
  let customFrom = $state('');
  let customTo = $state('');

  function local(ms: number): string {
    const d = new Date(ms);
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function openPicker() {
    const { start, end } = timeRange.resolve();
    customFrom = local(start);
    customTo = local(end);
    open = !open;
  }

  function choose(from: string, to: string) {
    timeRange.set(from, to);
    open = false;
  }

  function applyCustom() {
    const a = new Date(customFrom);
    const b = new Date(customTo);
    if (Number.isNaN(a.getTime()) || Number.isNaN(b.getTime()) || b <= a) return;
    choose(a.toISOString(), b.toISOString());
  }
</script>

<svelte:window onclick={(e) => { if (open && root && !root.contains(e.target as Node)) open = false; }}
               onkeydown={(e) => { if (e.key === 'Escape') open = false; }} />

<div class="picker" bind:this={root}>
  <button class="btn trigger" onclick={openPicker} aria-haspopup="listbox" aria-expanded={open}>
    <CalendarClock size={15} />
    <span>{timeRange.label}</span>
    <ChevronDown size={14} class="chev" />
  </button>
  {#if open}
    <div class="pop" role="listbox" aria-label="Time range">
      {#each presets as p (p.id)}
        {@const selected = timeRange.preset?.id === p.id}
        <button class="opt" class:selected role="option" aria-selected={selected} onclick={() => choose(p.from, p.to)}>
          <span class="check">{#if selected}<Check size={16} strokeWidth={3} />{/if}</span>
          <span>{p.label}</span>
          <span class="short mono">{p.short}</span>
        </button>
      {/each}
      <div class="custom">
        <div class="section-title">Custom range</div>
        <label class="field"><span class="field-label">From</span><input class="input input-sm" type="datetime-local" bind:value={customFrom} /></label>
        <label class="field"><span class="field-label">To</span><input class="input input-sm" type="datetime-local" bind:value={customTo} /></label>
        <button class="btn btn-primary btn-sm" onclick={applyCustom}>Apply range</button>
      </div>
    </div>
  {/if}
</div>

<style>
  .picker { position: relative; }
  .trigger { gap: 8px; font-variant-numeric: tabular-nums; }
  .trigger :global(.chev) { color: var(--text-4); }
  .pop {
    position: absolute; right: 0; top: calc(100% + 6px); z-index: 60; width: 270px; padding: 5px;
    background: var(--surface); border: 1px solid var(--border-strong); border-radius: var(--radius-lg);
    box-shadow: var(--shadow-lg); animation: pop 140ms var(--ease);
  }
  .opt {
    display: flex; align-items: center; gap: 8px; width: 100%; padding: 7px 9px; border: 0; background: none;
    border-radius: var(--radius-sm); cursor: pointer; font-size: 0.9rem; color: var(--text-2); text-align: left;
  }
  .opt:hover { background: var(--surface-hover); }
  .opt.selected { color: var(--text); font-weight: 600; }
  .check { width: 16px; display: grid; place-items: center; color: var(--accent-text); }
  .short { margin-left: auto; font-size: 0.75rem; color: var(--text-4); }
  .custom { display: flex; flex-direction: column; gap: 8px; padding: 10px 9px 6px; margin-top: 4px; border-top: 1px solid var(--divider); }
  @keyframes pop { from { opacity: 0; transform: translateY(-4px); } }
</style>
