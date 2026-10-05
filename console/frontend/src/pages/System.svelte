<script lang="ts">
  import { CircleAlert, CircleCheck, Cpu, Database, HardDrive, RefreshCw, Server, Webhook, Workflow } from '@lucide/svelte';
  import { api } from '../lib/api';
  import BarList from '../lib/charts/BarList.svelte';
  import PageHeader from '../lib/components/PageHeader.svelte';
  import { tip } from '../lib/components/tooltip';
  import { ago, bytes, num } from '../lib/format';
  import { Query } from '../lib/query.svelte';

  interface Status {
    version: string; time: string; database: { ok: boolean }; public_url: string;
    opensearch: { ok: boolean; urls: string[]; index_pattern: string; verify_certs: boolean; cluster_name?: string; distribution?: string;
      version?: string; health?: string; nodes?: number; error?: string; docs?: number; bytes?: number;
      indices?: { index: string; health: string; docs: number; bytes: number }[] };
    workers: Record<string, { last: string | null; error: string | null } | boolean>;
    rules: { enabled: number; failing: number }; webhooks: { queued: number; dead: number }; findings: { open: number }; rollups: { days: number };
  }

  const status = new Query((signal) => api.get<Status>('/system/status', { signal }), { refreshMs: 30000 });
  const s = $derived(status.data);
  const workers = $derived(Object.entries(s?.workers ?? {}).filter(([, v]) => typeof v === 'object') as [string, { last: string | null; error: string | null }][]);
  const WORKER_WORDS: Record<string, string> = { scheduler: 'Rule scheduler', dispatcher: 'Webhook dispatcher', rollups: 'Daily rollups' };
</script>

<PageHeader title="System" subtitle="How the console, its database and the cluster it reads are doing.">
  {#snippet actions()}
    <button class="btn" onclick={() => status.reload()}><RefreshCw size={15} /> Refresh</button>
  {/snippet}
</PageHeader>

{#if s}
  <div class="tiles">
    <div class="tile card" class:bad={!s.opensearch.ok}>
      <Server size={20} />
      <div><span class="muted">OpenSearch</span>
        <strong>{s.opensearch.ok ? `${s.opensearch.distribution === 'opensearch' ? 'OpenSearch' : 'Elasticsearch'} ${s.opensearch.version}` : 'Unreachable'}</strong>
        <span class="sub">{s.opensearch.ok ? `${s.opensearch.cluster_name} · ${s.opensearch.nodes} node${s.opensearch.nodes === 1 ? '' : 's'}` : s.opensearch.error}</span></div>
      {#if s.opensearch.health}<span class="health {s.opensearch.health}" use:tip={`Cluster health: ${s.opensearch.health}`}>{s.opensearch.health}</span>{/if}
    </div>
    <div class="tile card"><Database size={20} /><div><span class="muted">Database</span><strong>{s.database.ok ? 'Postgres connected' : 'Unavailable'}</strong><span class="sub">Accounts, rules, findings, webhooks</span></div></div>
    <div class="tile card"><HardDrive size={20} /><div><span class="muted">Events stored</span><strong>{num(s.opensearch.docs ?? 0)}</strong><span class="sub">{bytes(s.opensearch.bytes ?? 0)} in {s.opensearch.indices?.length ?? 0} indices</span></div></div>
    <div class="tile card"><Cpu size={20} /><div><span class="muted">Console</span><strong>Version {s.version}</strong><span class="sub mono">{s.public_url}</span></div></div>
  </div>

  <div class="grid-12">
    <div class="span-5">
      <section class="card">
        <div class="card-head"><h3 class="card-title">Background work</h3></div>
        <div class="card-body">
          {#each workers as [name, w] (name)}
            <div class="worker">
              {#if w.error}<CircleAlert size={16} class="bad-i" />{:else}<CircleCheck size={16} class="good-i" />{/if}
              <div><strong>{WORKER_WORDS[name] ?? name}</strong><span class="muted small">{w.error ?? (w.last ? `Last ran ${ago(w.last)}` : 'Starting')}</span></div>
            </div>
          {/each}
          <div class="facts">
            <div><Workflow size={14} /> {s.rules.enabled} rules enabled{#if s.rules.failing}, <span class="bad-t">{s.rules.failing} failing</span>{/if}</div>
            <div><Webhook size={14} /> {s.webhooks.queued} deliveries queued{#if s.webhooks.dead}, <span class="bad-t">{s.webhooks.dead} dead</span>{/if}</div>
            <div><CircleAlert size={14} /> {s.findings.open} findings open</div>
            <div><HardDrive size={14} /> {s.rollups.days} days of rollups kept</div>
          </div>
        </div>
      </section>
      <section class="card conn">
        <div class="card-head"><h3 class="card-title">Connection</h3></div>
        <div class="card-body kv">
          <span class="muted">URLs</span><span class="mono small">{s.opensearch.urls.join(', ')}</span>
          <span class="muted">Indices</span><span class="mono small">{s.opensearch.index_pattern}</span>
          <span class="muted">Certificates</span><span>{s.opensearch.verify_certs ? 'Verified' : 'Not verified'}</span>
          <span class="muted">Access</span><span class="small">Read only. The console never writes to the cluster.</span>
        </div>
      </section>
    </div>
    <div class="span-7">
      <section class="card">
        <div class="card-head"><h3 class="card-title">Indices</h3><span class="card-sub">Newest first, by documents</span></div>
        <div class="card-body">
          <BarList items={(s.opensearch.indices ?? []).slice(0, 24).map((i) => ({ key: i.index, value: i.docs, sub: bytes(i.bytes) }))} format={num}>
            {#snippet label(item)}<span class="mono small">{item.key}</span>{/snippet}
          </BarList>
        </div>
      </section>
    </div>
  </div>
{:else}
  <div class="skeleton" style="height:400px"></div>
{/if}

<style>
  .tiles { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-bottom: 16px; }
  @media (max-width: 1100px) { .tiles { grid-template-columns: repeat(2, 1fr); } }
  .tile { display: flex; align-items: flex-start; gap: 12px; padding: 16px; position: relative; }
  .tile > :global(svg) { color: var(--accent-text); flex: none; margin-top: 2px; }
  .tile div { display: flex; flex-direction: column; gap: 2px; min-width: 0; font-size: 0.82rem; }
  .tile strong { font-size: 1.02rem; }
  .sub { color: var(--text-3); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .tile.bad { border-color: color-mix(in srgb, var(--sev-critical) 40%, transparent); }
  .health { position: absolute; top: 12px; right: 12px; font-size: 0.72rem; font-weight: 700; padding: 2px 8px; border-radius: 99px; text-transform: capitalize; }
  .health.green { background: color-mix(in srgb, var(--good) 14%, transparent); color: var(--delta-good); }
  .health.yellow { background: rgba(250, 178, 25, 0.16); color: #a15c07; }
  .health.red { background: color-mix(in srgb, var(--sev-critical) 12%, transparent); color: var(--delta-bad); }
  .worker { display: flex; gap: 10px; align-items: flex-start; padding: 8px 0; border-bottom: 1px solid var(--divider); }
  .worker div { display: flex; flex-direction: column; }
  .worker :global(.good-i) { color: var(--good); }
  .worker :global(.bad-i) { color: var(--sev-critical); }
  .small { font-size: 0.8rem; }
  .facts { display: flex; flex-direction: column; gap: 8px; padding-top: 12px; font-size: 0.88rem; color: var(--text-2); }
  .facts div { display: flex; align-items: center; gap: 8px; }
  .bad-t { color: var(--delta-bad); font-weight: 600; }
  .conn { margin-top: 16px; }
  .kv { display: grid; grid-template-columns: 100px 1fr; gap: 8px 12px; font-size: 0.88rem; }
</style>
