<script lang="ts">
  import { Activity, LayoutDashboard, Monitor, Plus, RadioTower, Shield, Users } from '@lucide/svelte';
  import type { Component } from 'svelte';
  import { api } from '../lib/api';
  import Avatar from '../lib/components/Avatar.svelte';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import Modal from '../lib/components/Modal.svelte';
  import PageHeader from '../lib/components/PageHeader.svelte';
  import { ago } from '../lib/format';
  import { Query } from '../lib/query.svelte';
  import { navigate } from '../lib/router.svelte';
  import { session } from '../lib/stores/session.svelte';
  import { errorText, toasts } from '../lib/stores/toasts.svelte';
  import type { Dashboard } from '../lib/types';

  const ICONS: Record<string, Component<any>> = { shield: Shield, activity: Activity, 'radio-tower': RadioTower, monitor: Monitor,
    users: Users, 'layout-dashboard': LayoutDashboard };
  const list = new Query((signal) => api.get<(Dashboard & { updated_at?: string })[]>('/dashboards', { signal }));
  let createOpen = $state(false);
  let name = $state('');
  let description = $state('');

  async function create() {
    try {
      const d = await api.post<Dashboard>('/dashboards', { name, description, widgets: [], time_range: { from: 'now-24h', to: 'now' } });
      createOpen = false;
      navigate(`/dashboards/${d.id}`);
    } catch (e) {
      toasts.error('Could not create the dashboard', errorText(e));
    }
  }

  const groups = $derived([
    { label: 'Built in', items: (list.data ?? []).filter((d) => d.builtin) },
    { label: 'Yours', items: (list.data ?? []).filter((d) => d.mine) },
    { label: 'Shared with everyone', items: (list.data ?? []).filter((d) => !d.builtin && !d.mine && d.shared) },
  ].filter((g) => g.items.length));
</script>

<PageHeader title="Dashboards" subtitle="Views of the network built from saved questions. Each widget is a live query; nothing is stored but the question.">
  {#snippet actions()}
    {#if session.can('dashboards:write')}<button class="btn btn-primary" onclick={() => (createOpen = true)}><Plus size={15} /> New dashboard</button>{/if}
  {/snippet}
</PageHeader>

{#if list.error && !list.data}<EmptyState title="Could not load dashboards" body={errorText(list.error)} />{/if}

{#each groups as group (group.label)}
  <div class="section-title gl">{group.label}</div>
  <div class="cards">
    {#each group.items as d (d.id)}
      {@const Icon = ICONS[d.icon] ?? LayoutDashboard}
      <a class="dash card" href="/dashboards/{d.id}">
        <div class="preview" aria-hidden="true">
          {#each d.widgets.slice(0, 6) as w, wi (w.id)}
            <span class="pv pv-{w.span}" class:short={w.height === 'sm' || w.type === 'stat'}>
              {#if w.type === 'stat' || w.findings?.count_only}<span class="pv-num"></span>
              {:else if ['area', 'stacked', 'line'].includes(w.viz ?? '')}
                <svg viewBox="0 0 100 30" preserveAspectRatio="none" class="pv-line"><path d="M0,{24 - (wi % 3) * 3} C15,{18 + wi} 25,8 40,{14 - wi} S70,{20 + wi} 100,{6 + wi * 2}" fill="none" stroke="var(--s{(wi % 3) + 1})" stroke-width="2" vector-effect="non-scaling-stroke" /></svg>
              {:else if w.type === 'findings'}
                {#each [0, 1, 2] as r (r)}<span class="pv-row" style:top="{8 + r * 9}px"></span>{/each}
              {:else}
                {#each [70, 48, 30] as width, r (r)}<span class="pv-hbar" style:width="{width}%" style:top="{8 + r * 9}px"></span>{/each}
              {/if}
            </span>
          {/each}
        </div>
        <div class="dbody">
          <div class="dtitle"><span class="dicon"><Icon size={15} /></span><strong>{d.name}</strong></div>
          <p class="muted desc">{d.description || 'No description'}</p>
          <div class="dmeta">
            <span class="faint">{d.widgets.length} widget{d.widgets.length === 1 ? '' : 's'}</span>
            {#if d.owner}<span class="owner"><Avatar name={d.owner.display_name} size={18} /> {d.owner.display_name}</span>{/if}
            {#if d.updated_at}<span class="faint">· {ago(d.updated_at)}</span>{/if}
          </div>
        </div>
      </a>
    {/each}
  </div>
{/each}

<Modal bind:open={createOpen} title="New dashboard">
  <div class="stack">
    <label class="field"><span class="field-label">Name</span><input class="input" bind:value={name} placeholder="Exam week" /></label>
    <label class="field"><span class="field-label">Description</span><input class="input" bind:value={description} placeholder="What it is for" /></label>
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (createOpen = false)}>Cancel</button>
    <button class="btn btn-primary" disabled={!name.trim()} onclick={create}>Create</button>
  {/snippet}
</Modal>

<style>
  .gl { margin: 10px 0 10px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 16px; margin-bottom: 22px; }
  .dash { display: flex; flex-direction: column; overflow: hidden; color: var(--text); text-decoration: none; transition: transform var(--fast), box-shadow var(--fast), border-color var(--fast); }
  .dash:hover { transform: translateY(-2px); box-shadow: var(--shadow); border-color: var(--border-strong); text-decoration: none; }
  .preview { display: grid; grid-template-columns: repeat(12, 1fr); gap: 5px; padding: 14px; height: 116px; overflow: hidden;
    background: linear-gradient(160deg, var(--accent-softer), transparent 70%), var(--surface-2); border-bottom: 1px solid var(--divider); }
  .pv { grid-column: span 6; height: 40px; border-radius: 5px; background: var(--surface); border: 1px solid var(--border); position: relative; overflow: hidden; }
  .pv-3 { grid-column: span 3; } .pv-4 { grid-column: span 4; } .pv-8 { grid-column: span 8; } .pv-12 { grid-column: span 12; }
  .pv.short { height: 26px; }
  .pv-hbar { position: absolute; left: 6px; height: 4px; border-radius: 0 2px 2px 0; background: color-mix(in srgb, var(--s1) 70%, transparent); }
  .pv-row { position: absolute; left: 6px; right: 6px; height: 4px; border-radius: 2px; background: var(--surface-3); }
  .pv-row::before { content: ''; position: absolute; left: 0; width: 4px; height: 4px; border-radius: 99px; background: var(--sev-critical); }
  .pv-num { position: absolute; left: 7px; top: 7px; width: 34%; height: 11px; border-radius: 3px; background: color-mix(in srgb, var(--text) 30%, transparent); }
  .pv-line { position: absolute; inset: 6px; width: calc(100% - 12px); height: calc(100% - 12px); }
  .dbody { padding: 14px 16px 16px; display: flex; flex-direction: column; gap: 6px; }
  .dtitle { display: flex; align-items: center; gap: 8px; }
  .dicon { width: 26px; height: 26px; border-radius: 8px; display: grid; place-items: center; background: var(--accent-soft); color: var(--accent-text); }
  .desc { font-size: 0.86rem; }
  .dmeta { display: flex; align-items: center; gap: 8px; font-size: 0.78rem; flex-wrap: wrap; }
  .owner { display: inline-flex; align-items: center; gap: 5px; color: var(--text-3); }
</style>
