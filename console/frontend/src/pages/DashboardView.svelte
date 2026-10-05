<script lang="ts">
  import { ArrowLeft, Check, Copy, LayoutDashboard, Pencil, Plus, Share2, Trash2, X } from '@lucide/svelte';
  import { untrack } from 'svelte';
  import { api } from '../lib/api';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import Modal from '../lib/components/Modal.svelte';
  import TimeRangePicker from '../lib/components/TimeRangePicker.svelte';
  import WidgetView from '../lib/components/WidgetView.svelte';
  import { Query } from '../lib/query.svelte';
  import { navigate, router } from '../lib/router.svelte';
  import { fields } from '../lib/stores/fields.svelte';
  import { session } from '../lib/stores/session.svelte';
  import { timeRange } from '../lib/stores/timerange.svelte';
  import { errorText, toasts } from '../lib/stores/toasts.svelte';
  import type { Dashboard, Widget } from '../lib/types';

  fields.load();
  const id = $derived(router.params.id);
  const board = new Query((signal) => api.get<Dashboard>(`/dashboards/${id}`, { signal }));
  let editing = $state(false);
  let draft = $state<Dashboard | null>(null);
  let addOpen = $state(false);
  let newWidget = $state<Widget>({ id: '', title: '', type: 'pivot', span: 6, height: 'md', viz: 'hbar',
    pivot: { query: '', metric: 'count', rows: 'bite.purpose', rows_size: 10, split: null, split_size: 4, over_time: false } });

  // A dashboard opens on its own range unless the link carries one
  $effect(() => {
    const d = board.data;
    if (d && !router.query.get('from') && d.time_range.from) {
      untrack(() => router.setQuery({ from: d.time_range.from!, to: d.time_range.to ?? 'now' }));
    }
  });

  const d = $derived(editing ? draft : board.data);
  const canEdit = $derived(!!board.data && !board.data.builtin && (board.data.mine || session.can('users:admin')) && session.can('dashboards:write'));

  function startEdit() {
    draft = structuredClone($state.snapshot(board.data!)) as Dashboard;
    editing = true;
  }

  async function saveEdit() {
    if (!draft) return;
    try {
      await api.put(`/dashboards/${draft.id}`, { name: draft.name, description: draft.description, icon: draft.icon,
        widgets: draft.widgets, time_range: { from: timeRange.from, to: timeRange.to }, shared: draft.shared });
      editing = false;
      board.reload();
      toasts.success('Dashboard saved');
    } catch (e) {
      toasts.error('Could not save', errorText(e));
    }
  }

  function move(i: number, dir: -1 | 1) {
    if (!draft) return;
    const j = i + dir;
    if (j < 0 || j >= draft.widgets.length) return;
    const widgets = [...draft.widgets];
    [widgets[i], widgets[j]] = [widgets[j], widgets[i]];
    draft.widgets = widgets;
  }

  function addWidget() {
    if (!draft) return;
    const w = structuredClone($state.snapshot(newWidget)) as Widget;
    w.id = Math.random().toString(36).slice(2, 10);
    if (w.pivot) w.pivot.over_time = ['area', 'stacked', 'line'].includes(w.viz ?? '');
    if (w.type === 'note') delete w.pivot;
    draft.widgets = [...draft.widgets, w];
    addOpen = false;
  }

  async function clone() {
    try {
      const copy = await api.post<Dashboard>(`/dashboards/${id}/clone`);
      navigate(`/dashboards/${copy.id}`);
      toasts.success('Your copy is ready to change');
    } catch (e) {
      toasts.error('Could not clone', errorText(e));
    }
  }

  async function remove() {
    if (!confirm('Delete this dashboard?')) return;
    try {
      await api.del(`/dashboards/${id}`);
      navigate('/dashboards');
    } catch (e) {
      toasts.error('Could not delete', errorText(e));
    }
  }

  const groupable = $derived([{ name: 'entity', label: 'Entity' }, ...fields.list.filter((f) => f.aggregatable && f.type !== 'date' && f.type !== 'boolean')]);
</script>

{#if board.error && !board.data}
  <EmptyState title="Could not load this dashboard" body={errorText(board.error)} />
{:else if d}
  <a class="back" href="/dashboards"><ArrowLeft size={14} /> Dashboards</a>
  <header class="head">
    <div class="icon"><LayoutDashboard size={22} /></div>
    <div class="titles">
      {#if editing && draft}
        <input class="input title-input" bind:value={draft.name} aria-label="Dashboard name" />
        <input class="input" bind:value={draft.description} placeholder="What this dashboard is for" aria-label="Description" />
      {:else}
        <div class="row-wrap">
          <h1>{d.name}</h1>
          {#if d.builtin}<span class="badge">Built-in</span>{:else if d.shared}<span class="badge badge-accent">Shared</span>{/if}
        </div>
        <p class="muted">{d.description}{d.owner ? ` · by ${d.owner.display_name}` : ''}</p>
      {/if}
    </div>
    <div class="actions">
      {#if editing && draft}
        <label class="checkbox"><input type="checkbox" bind:checked={draft.shared} /> <Share2 size={14} /> Shared</label>
        <button class="btn" onclick={() => (addOpen = true)}><Plus size={15} /> Add widget</button>
        <button class="btn" onclick={() => (editing = false)}><X size={15} /> Cancel</button>
        <button class="btn btn-primary" onclick={saveEdit}><Check size={15} /> Save</button>
      {:else}
        <TimeRangePicker />
        {#if session.can('dashboards:write')}<button class="btn" onclick={clone}><Copy size={15} /> Clone</button>{/if}
        {#if canEdit}
          <button class="btn" onclick={startEdit}><Pencil size={15} /> Edit</button>
          <button class="btn btn-icon btn-danger" onclick={remove} aria-label="Delete dashboard"><Trash2 size={15} /></button>
        {/if}
      {/if}
    </div>
  </header>

  {#if !d.widgets.length}
    <EmptyState title="An empty dashboard" body="Add widgets here, or from any question in Analytics with “Add to dashboard”.">
      {#if canEdit && !editing}<button class="btn btn-primary" onclick={() => { startEdit(); addOpen = true; }}><Plus size={15} /> Add a widget</button>{/if}
    </EmptyState>
  {/if}

  <div class="widgets">
    {#if editing && draft}
      {#each draft.widgets as w, i (w.id)}
        <WidgetView bind:widget={draft.widgets[i]} editing onmove={(dir) => move(i, dir)}
                    onremove={() => draft && (draft.widgets = draft.widgets.filter((x) => x.id !== w.id))} />
      {/each}
    {:else}
      {#each d.widgets as w, i (w.id + i)}
        <WidgetView widget={w} />
      {/each}
    {/if}
  </div>
{:else}
  <div class="skeleton" style="height:400px"></div>
{/if}

<Modal bind:open={addOpen} title="Add a widget" width={600}>
  <div class="stack">
    <div class="row3">
      <label class="field"><span class="field-label">Kind</span>
        <select class="select" bind:value={newWidget.type}>
          <option value="pivot">Chart or table</option><option value="stat">Single number</option>
          <option value="findings">Findings list</option><option value="note">Note</option>
        </select></label>
      <label class="field"><span class="field-label">Title</span><input class="input" bind:value={newWidget.title} placeholder="Gaming by hour" /></label>
      <label class="field"><span class="field-label">Width</span>
        <select class="select" bind:value={newWidget.span}>{#each [3, 4, 6, 8, 12] as n (n)}<option value={n}>{n === 12 ? 'Full' : `${n} / 12`}</option>{/each}</select></label>
    </div>
    {#if newWidget.type === 'pivot' || newWidget.type === 'stat'}
      <label class="field"><span class="field-label">Events matching</span><input class="input mono" bind:value={newWidget.pivot!.query} placeholder="purpose:gaming.*" /></label>
      {#if newWidget.type === 'pivot'}
        <div class="row3">
          <label class="field"><span class="field-label">View</span>
            <select class="select" bind:value={newWidget.viz}>
              <option value="hbar">Bars</option><option value="table">Table</option><option value="stacked">Columns over time</option>
              <option value="area">Area over time</option><option value="line">Lines over time</option>
            </select></label>
          <label class="field"><span class="field-label">Group by</span>
            <select class="select" bind:value={newWidget.pivot!.rows}>{#each groupable as f (f.name)}<option value={f.name}>{f.label}</option>{/each}</select></label>
          <label class="field"><span class="field-label">Split by</span>
            <select class="select" bind:value={newWidget.pivot!.split}><option value={null}>Nothing</option>
              {#each groupable.filter((f) => f.name !== 'entity') as f (f.name)}<option value={f.name}>{f.label}</option>{/each}</select></label>
        </div>
      {/if}
    {:else if newWidget.type === 'findings'}
      <p class="muted">Shows the most severe open findings, newest activity first.</p>
    {:else}
      <label class="field"><span class="field-label">Text</span><textarea class="textarea" bind:value={newWidget.note}></textarea></label>
    {/if}
  </div>
  {#snippet footer()}
    <button class="btn" onclick={() => (addOpen = false)}>Cancel</button>
    <button class="btn btn-primary" disabled={!newWidget.title} onclick={addWidget}>Add</button>
  {/snippet}
</Modal>

<style>
  .back { display: inline-flex; align-items: center; gap: 5px; font-size: 0.86rem; color: var(--text-3); margin-bottom: 12px; }
  .head { display: flex; align-items: center; gap: 14px; margin-bottom: 20px; flex-wrap: wrap; }
  .icon { width: 46px; height: 46px; border-radius: 13px; display: grid; place-items: center; color: #fff; background: var(--accent-grad); flex: none; }
  .titles { flex: 1; min-width: 260px; display: flex; flex-direction: column; gap: 4px; }
  .title-input { font-size: 1.2rem; font-weight: 600; height: 40px; }
  .actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .widgets { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 16px; align-items: stretch; }
  .row3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
</style>
