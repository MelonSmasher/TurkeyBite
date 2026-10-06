<script lang="ts">
  // label · value · delta against the previous period · optional trend
  import { ArrowDownRight, ArrowUpRight, Minus } from '@lucide/svelte';
  import type { Component } from 'svelte';
  import { compact, signedPct } from '../format';
  import Sparkline from './Sparkline.svelte';

  let { label, value, change = null, upIsGood = true, trend = [], icon, href, hint = '', format = compact,
        tone = 'default' }: {
    label: string;
    value: number | null | undefined;
    change?: number | null;
    upIsGood?: boolean;
    trend?: number[];
    icon?: Component<any>;
    href?: string;
    hint?: string;
    format?: (n: number) => string;
    tone?: 'default' | 'critical' | 'accent';
  } = $props();

  const direction = $derived(change === null || change === undefined || Math.abs(change) < 0.005 ? 0 : change > 0 ? 1 : -1);
  const good = $derived(direction === 0 ? null : (direction > 0) === upIsGood);
  const Icon = $derived(icon);
</script>

<svelte:element this={href ? 'a' : 'div'} class="tile card" {href} class:link={!!href} data-tone={tone}>
  <div class="head">
    {#if Icon}<span class="icon"><Icon size={15} /></span>{/if}
    <span class="label">{label}</span>
  </div>
  <div class="body">
    <div class="value">{value === null || value === undefined ? '–' : format(value)}</div>
    {#if trend.length > 1}<Sparkline values={trend} accent={tone === 'critical' ? 'var(--sev-critical)' : 'var(--s1)'} />{/if}
  </div>
  <div class="foot">
    {#if change !== null && change !== undefined}
      <span class="delta" class:good={good === true} class:bad={good === false}>
        {#if direction > 0}<ArrowUpRight size={13} />{:else if direction < 0}<ArrowDownRight size={13} />{:else}<Minus size={13} />{/if}
        {signedPct(change)}
      </span>
      <span class="muted">vs previous period</span>
    {:else if hint}
      <span class="muted">{hint}</span>
    {/if}
  </div>
</svelte:element>

<style>
  .tile { display: flex; flex-direction: column; gap: 8px; padding: 15px 16px 13px; color: var(--text); text-decoration: none;
    position: relative; overflow: hidden; transition: border-color var(--fast), box-shadow var(--fast), transform var(--fast); }
  .tile.link:hover { border-color: var(--border-strong); box-shadow: var(--shadow); text-decoration: none; }
  .tile[data-tone='critical']::before, .tile[data-tone='accent']::before {
    content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 3px;
    background: var(--sev-critical);
  }
  .tile[data-tone='accent']::before { background: var(--accent); }
  .head { display: flex; align-items: center; gap: 8px; }
  .icon { width: 26px; height: 26px; border-radius: 8px; display: grid; place-items: center;
    background: var(--surface-3); color: var(--text-3); }
  .tile[data-tone='critical'] .icon { background: color-mix(in srgb, var(--sev-critical) 12%, transparent); color: var(--sev-critical); }
  .tile[data-tone='accent'] .icon { background: var(--accent-soft); color: var(--accent-text); }
  .label { font-size: 0.84rem; color: var(--text-2); font-weight: 550; }
  .body { display: flex; align-items: flex-end; justify-content: space-between; gap: 10px; }
  .value { font-size: 1.75rem; font-weight: 650; letter-spacing: -0.025em; line-height: 1.05; }
  .foot { display: flex; align-items: center; gap: 6px; font-size: 0.78rem; min-height: 18px; }
  .delta { display: inline-flex; align-items: center; gap: 2px; font-weight: 650; color: var(--text-2); }
  .delta.good { color: var(--delta-good); }
  .delta.bad { color: var(--delta-bad); }
</style>
