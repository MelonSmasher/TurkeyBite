<script lang="ts">
  // A chart's frame: title, actions, and its table-view twin, which carries
  // every value the chart shows for anyone who cannot read the chart.
  import { ChartColumn, Table2 } from '@lucide/svelte';
  import type { Snippet } from 'svelte';
  import { tip } from '../components/tooltip';

  let { title, subtitle = '', refetching = false, table, children, actions, footer, pad = true }: {
    title: string;
    subtitle?: string;
    refetching?: boolean;
    table?: { columns: string[]; rows: (string | number)[][] } | null;
    children: Snippet;
    actions?: Snippet;
    footer?: Snippet;
    pad?: boolean;
  } = $props();
  let showTable = $state(false);
</script>

<section class="card chart-card">
  <div class="card-head">
    <div class="titles">
      <h2 class="card-title">{title}</h2>
      {#if subtitle}<div class="card-sub">{subtitle}</div>{/if}
    </div>
    <div class="spacer"></div>
    {#if actions}{@render actions()}{/if}
    {#if table}
      <button class="btn btn-ghost btn-sm btn-icon" onclick={() => (showTable = !showTable)}
              use:tip={showTable ? 'Show chart' : 'Show as table'} aria-pressed={showTable}>
        {#if showTable}<ChartColumn size={15} />{:else}<Table2 size={15} />{/if}
      </button>
    {/if}
  </div>
  <div class:card-body={pad} class:refetching>
    {#if showTable && table}
      <div class="table-wrap view-table">
        <table class="table">
          <thead><tr>{#each table.columns as c, i (i)}<th class:num={i > 0}>{c}</th>{/each}</tr></thead>
          <tbody>
            {#each table.rows as row, r (r)}
              <tr>{#each row as cell, i (i)}<td class:num={i > 0}>{cell}</td>{/each}</tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      {@render children()}
    {/if}
  </div>
  {#if footer}<div class="card-foot">{@render footer()}</div>{/if}
</section>

<style>
  .chart-card { display: flex; flex-direction: column; }
  .titles { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .view-table { max-height: 320px; border: 1px solid var(--border); border-radius: var(--radius); }
</style>
