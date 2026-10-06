<script lang="ts">
  import { BookOpen, ExternalLink, Search } from '@lucide/svelte';
  import CopyButton from '../lib/components/CopyButton.svelte';
  import PageHeader from '../lib/components/PageHeader.svelte';
  import { Query } from '../lib/query.svelte';
  import { session } from '../lib/stores/session.svelte';

  interface Operation { method: string; path: string; summary: string; description: string; tag: string; params: string[] }

  const spec = new Query(async (signal) => {
    const response = await fetch('/api/openapi.json', { signal });
    return (await response.json()) as { info: { version: string }; paths: Record<string, Record<string, any>> };
  });
  let filter = $state('');

  const ops = $derived.by(() => {
    const out: Operation[] = [];
    for (const [path, methods] of Object.entries(spec.data?.paths ?? {})) {
      for (const [method, op] of Object.entries(methods)) {
        out.push({ method: method.toUpperCase(), path, summary: op.summary ?? '', description: (op.description ?? '').split('\n\n')[0],
                   tag: op.tags?.[0] ?? 'other', params: (op.parameters ?? []).map((p: any) => p.name) });
      }
    }
    return out;
  });
  const groups = $derived.by(() => {
    const f = filter.toLowerCase();
    const map = new Map<string, Operation[]>();
    for (const op of ops) {
      if (f && !`${op.path} ${op.summary} ${op.description} ${op.tag}`.toLowerCase().includes(f)) continue;
      if (!map.has(op.tag)) map.set(op.tag, []);
      map.get(op.tag)!.push(op);
    }
    return [...map.entries()];
  });

  const origin = location.origin;
  const examples = [
    { title: 'Open findings, most severe first', code: `curl -s "${origin}/api/v1/findings?status=open&sort=severity" \\\n  -H "Authorization: Bearer $TBC_KEY"` },
    { title: 'Search events with TBQL', code: `curl -s ${origin}/api/v1/events/search \\\n  -H "Authorization: Bearer $TBC_KEY" -H "Content-Type: application/json" \\\n  -d '{"query": "risk:threat", "from": "now-24h", "size": 100}'` },
    { title: 'Count by anything', code: `curl -s ${origin}/api/v1/analytics/pivot \\\n  -H "Authorization: Bearer $TBC_KEY" -H "Content-Type: application/json" \\\n  -d '{"query": "has:purpose", "rows": "bite.purpose", "from": "now-7d"}'` },
    { title: 'Resolve a finding from a ticketing system', code: `curl -s -X PATCH ${origin}/api/v1/findings/$FINDING_ID \\\n  -H "Authorization: Bearer $TBC_KEY" -H "Content-Type: application/json" \\\n  -d '{"status": "resolved", "note": "Closed in ticket INC-4211"}'` },
  ];
</script>

<PageHeader title="API reference" subtitle="Everything the app does goes through this API, so anything you can do here a script can do too. Authenticate with an API key as a bearer token.">
  {#snippet actions()}
    {#if session.me?.api_docs}<a class="btn" href="/api/docs" target="_blank" rel="noopener"><ExternalLink size={15} /> Interactive docs</a>{/if}
    <a class="btn" href="/api/openapi.json" target="_blank" rel="noopener"><BookOpen size={15} /> OpenAPI</a>
  {/snippet}
</PageHeader>

<div class="examples">
  {#each examples as ex (ex.title)}
    <section class="card ex">
      <div class="ex-head"><strong>{ex.title}</strong><CopyButton text={ex.code} /></div>
      <pre class="code">{ex.code}</pre>
    </section>
  {/each}
</div>

<div class="searchbox"><Search size={14} /><input placeholder="Find an endpoint" bind:value={filter} aria-label="Find an endpoint" /></div>

{#each groups as [tag, list] (tag)}
  <section class="card group">
    <div class="card-head"><h3 class="card-title cap">{tag}</h3><span class="card-sub">{list.length} endpoint{list.length === 1 ? '' : 's'}</span></div>
    <div class="card-body">
      {#each list as op (op.method + op.path)}
        <div class="op">
          <span class="method m-{op.method.toLowerCase()}">{op.method}</span>
          <code class="path mono">{op.path}</code>
          <span class="desc muted">{op.summary}{op.description && op.description !== op.summary ? ` — ${op.description}` : ''}</span>
        </div>
      {/each}
    </div>
  </section>
{/each}

<style>
  .examples { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; margin-bottom: 20px; }
  @media (max-width: 1000px) { .examples { grid-template-columns: 1fr; } }
  .ex { padding: 14px 16px; display: flex; flex-direction: column; gap: 8px; }
  .ex-head { display: flex; align-items: center; justify-content: space-between; font-size: 0.9rem; }
  .ex .code { font-size: 0.78rem; }
  .searchbox { display: flex; align-items: center; gap: 7px; height: 34px; padding: 0 11px; border-radius: var(--radius); border: 1px solid var(--border-strong);
    background: var(--surface); color: var(--text-4); width: 320px; margin-bottom: 14px; }
  .searchbox input { border: 0; outline: none; background: none; flex: 1; color: var(--text); }
  .group { margin-bottom: 14px; }
  .cap { text-transform: capitalize; }
  .op { display: grid; grid-template-columns: 70px minmax(240px, 380px) minmax(0, 1fr); gap: 12px; align-items: center; padding: 8px 0; border-bottom: 1px solid var(--divider); }
  .op:last-child { border-bottom: 0; }
  .method { font-family: var(--font-mono); font-size: 0.72rem; font-weight: 700; padding: 3px 0; border-radius: 6px; text-align: center; }
  .m-get { color: var(--s1); background: color-mix(in srgb, var(--s1) 12%, transparent); }
  .m-post { color: var(--s3); background: color-mix(in srgb, var(--s3) 14%, transparent); }
  .m-put, .m-patch { color: #b77d00; background: color-mix(in srgb, var(--s4) 16%, transparent); }
  .m-delete { color: var(--delta-bad); background: color-mix(in srgb, var(--s8) 12%, transparent); }
  .path { font-size: 0.82rem; overflow-wrap: anywhere; }
  .desc { font-size: 0.84rem; }
</style>
