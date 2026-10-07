<script lang="ts">
  // An address that, pressed, asks the system an admin set up (a security
  // console, say) what its inventories know about the device, by signed
  // webhook, and shows the answer here: where it is plugged in, who last used
  // it, and so on, inventory by inventory.
  import { CircleAlert, ExternalLink, MonitorSmartphone, RefreshCw } from '@lucide/svelte';
  import { api } from '../api';
  import { who } from '../privacy';
  import { prefs } from '../stores/prefs.svelte';
  import { session } from '../stores/session.svelte';
  import { errorText } from '../stores/toasts.svelte';
  import Drawer from './Drawer.svelte';
  import { tip } from './tooltip';

  interface Card {
    name: string; configured: boolean; asks: boolean; found: boolean; note: string; problem: string;
    records: { title: string; subtitle: string; facts: [string, string][]; link: string }[];
  }
  interface Answer { address: string; inventories: Card[]; alerts: { count: number; open: number }; link: string }

  let { value, label = null, button = false }: { value: string; label?: string | null; button?: boolean } = $props();
  let open = $state(false);
  let answer = $state<Answer | null>(null);
  let error = $state('');
  let loading = $state(false);
  // In privacy mode the answer names people, so it is asked for first
  let confirmed = $state(false);

  const can = $derived(!!session.me?.device_lookup && session.can('findings:write'));
  const shown = $derived(label ?? who(value, 'bite.client'));
  const asked = $derived(answer?.inventories.filter((c) => c.configured && c.asks) ?? []);
  const unset = $derived(answer?.inventories.filter((c) => !c.configured).map((c) => c.name) ?? []);
  const cannot = $derived(answer?.inventories.filter((c) => c.configured && !c.asks).map((c) => c.name) ?? []);
  const elsewhere = $derived.by(() => {
    try {
      return answer?.link ? new URL(answer.link).host : '';
    } catch {
      return '';
    }
  });

  const where = $derived(elsewhere ? ` in ${elsewhere}` : '');

  async function run() {
    confirmed = true;
    loading = true;
    error = '';
    answer = null;
    try {
      answer = await api.post<Answer>('/devices/lookup', { address: value });
    } catch (e) {
      error = errorText(e);
    } finally {
      loading = false;
    }
  }

  function start() {
    open = true;
    confirmed = false;
    if (!prefs.privacy) run();
  }
</script>

{#if can}
  <button type="button" class={button ? 'btn' : 'lookup mono'} onclick={start} use:tip={'Look this device up'}>
    {shown}<MonitorSmartphone size={button ? 14 : 12} aria-hidden="true" /><span class="sr-only">(look this device up)</span>
  </button>
  <Drawer bind:open title="Device lookup" subtitle={who(value, 'bite.client')} width={620}>
    {#if !confirmed}
      <div class="gate">
        <p>The answer says who uses this device and where it is plugged in, which privacy mode would otherwise hide.</p>
        <button class="btn btn-primary" onclick={run}>Look it up</button>
      </div>
    {:else if loading}
      <p class="muted small">Asking every inventory about {who(value, 'bite.client')}…</p>
      <div class="skeleton" style="height:120px" aria-busy="true" aria-label="Loading"></div>
    {:else if error}
      <div class="alert" role="alert"><CircleAlert size={15} /> {error}</div>
      <button class="btn mt" onclick={run}><RefreshCw size={14} /> Try again</button>
    {:else if answer}
      <div class="cards">
        {#each asked as card (card.name)}
          <section class="card inv">
            <header class="inv-head">
              <strong>{card.name}</strong>
              {#if card.problem}<span class="badge badge-bad">no answer</span>
              {:else if card.found}<span class="badge">{card.records.length} {card.records.length === 1 ? 'record' : 'records'}</span>
              {:else}<span class="muted small">nothing found</span>{/if}
            </header>
            {#if card.problem}<p class="muted small">{card.problem}</p>{/if}
            {#each card.records as record, i (i)}
              <div class="record">
                <div class="rec-title">
                  <span class="mono">{record.title}</span>
                  {#if record.link}<a class="small" href={record.link} target="_blank" rel="noopener noreferrer">Open <ExternalLink size={12} aria-hidden="true" /><span class="sr-only">(in a new tab)</span></a>{/if}
                </div>
                {#if record.subtitle}<div class="muted small">{record.subtitle}</div>{/if}
                {#if record.facts.length}
                  <dl class="facts">
                    {#each record.facts as [k, v], j (j)}<dt class="muted">{k}</dt><dd>{v}</dd>{/each}
                  </dl>
                {/if}
              </div>
            {/each}
            {#if card.note}<p class="muted small">{card.note}</p>{/if}
          </section>
        {:else}
          <p class="muted">No inventory could be asked about an address.</p>
        {/each}
      </div>
      <p class="muted small foot">
        {#if answer.alerts.count}{answer.alerts.count} {answer.alerts.count === 1 ? 'alert' : 'alerts'}{where} name this device, {answer.alerts.open} open.{/if}
        {#if unset.length} Not set up: {unset.join(', ')}.{/if}
        {#if cannot.length} Not searched by address: {cannot.join(', ')}.{/if}
        {#if answer.link} <a href={answer.link} target="_blank" rel="noopener noreferrer">The full lookup{where} <ExternalLink size={12} aria-hidden="true" /><span class="sr-only">(in a new tab)</span></a>{/if}
      </p>
    {/if}
  </Drawer>
{/if}

<style>
  .lookup {
    display: inline-flex; align-items: center; gap: 4px; padding: 0; border: 0; background: none; cursor: pointer;
    font: inherit; color: var(--accent-text);
  }
  .lookup:hover { text-decoration: underline; }
  .btn { gap: 6px; }
  .alert {
    display: flex; align-items: center; gap: 8px; padding: 10px 12px; border-radius: var(--radius);
    background: color-mix(in srgb, var(--sev-critical) 9%, transparent); color: var(--delta-bad);
  }
  .gate { display: flex; flex-direction: column; align-items: flex-start; gap: 12px; }
  .mt { margin-top: 12px; }
  .cards { display: flex; flex-direction: column; gap: 12px; }
  .inv { padding: 14px 16px; display: flex; flex-direction: column; gap: 8px; }
  .inv-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  .record { border-top: 1px solid var(--divider); padding-top: 8px; display: flex; flex-direction: column; gap: 4px; }
  .rec-title { display: flex; align-items: center; justify-content: space-between; gap: 8px; font-weight: 600; }
  .rec-title a { display: inline-flex; align-items: center; gap: 3px; font-weight: 500; }
  .facts { display: grid; grid-template-columns: max-content 1fr; gap: 3px 14px; margin: 4px 0 0; font-size: 0.86rem; }
  .facts dd { margin: 0; overflow-wrap: anywhere; }
  .foot { margin-top: 14px; line-height: 1.6; }
  .foot a { display: inline-flex; align-items: center; gap: 3px; }
</style>
