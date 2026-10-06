<script lang="ts">
  // One event, explained: who, what, and why it carries the categories it does.
  import { Braces, CircleCheck, CircleSlash, CircleHelp, Clock, Globe, History, Info, MonitorSmartphone, Scale } from '@lucide/svelte';
  import { api } from '../api';
  import { dateTime, fullTime, taxon } from '../format';
  import { exploreLink, maskSource } from '../privacy';
  import type { Hit } from '../types';
  import DomainLink from './DomainLink.svelte';
  import Drawer from './Drawer.svelte';
  import EntityLink from './EntityLink.svelte';
  import JsonView from './JsonView.svelte';
  import Segmented from './Segmented.svelte';
  import { quoteValue as quote } from './tbql';

  let { hit = $bindable(null), onfilter }: {
    hit: Hit | null;
    onfilter?: (term: string) => void;
  } = $props();

  let tab = $state<'summary' | 'raw'>('summary');
  let full = $state<Hit | null>(null);
  let open = $state(false);

  $effect(() => {
    open = !!hit;
    full = null;
    tab = 'summary';
    if (hit) {
      const target = hit;
      api.get<Hit>(`/events/doc/${encodeURIComponent(target.index)}/${encodeURIComponent(target.id)}`)
        .then((doc) => { if (hit === target) full = doc; })
        .catch(() => {});
    }
  });

  const b = $derived((hit?.source.bite ?? {}) as Record<string, any>);
  const entity = $derived.by(() => {
    for (const f of ['client_user', 'client_hostname_short', 'client_hosts_short', 'client']) {
      const v = b[f];
      if (v && (!Array.isArray(v) || v.length)) return { field: `bite.${f}`, value: Array.isArray(v) ? v[0] : v };
    }
    return null;
  });
  const claims = $derived.by(() => {
    const out: Record<string, string[]> = {};
    for (const c of (b.claims ?? []) as string[]) {
      const [category, source] = c.split(':');
      (out[category] ??= []).push(source ?? '?');
    }
    return out;
  });
  const contexts = $derived((b.contexts ?? []) as string[]);
  const candidates = $derived((b.contexts_candidate ?? []) as string[]);
  const suppressed = $derived((b.contexts_suppressed ?? []) as string[]);

  function around(): string {
    if (!hit || !entity) return '/explore';
    const t = new Date(hit.source['@timestamp']).getTime();
    const from = new Date(t - 5 * 60e3).toISOString();
    const to = new Date(t + 5 * 60e3).toISOString();
    const short: Record<string, string> = { 'bite.client_user': 'user', 'bite.client_hostname_short': 'host',
                                            'bite.client': 'client' };
    const alias = short[entity.field] ?? entity.field;
    return exploreLink({ q: `${alias}:${quote(String(entity.value))}`, from, to });
  }
</script>

<Drawer bind:open title={(b.requested ?? ['Event'])[0]} width={680} onclose={() => (hit = null)}>
  {#snippet header()}
    <div class="dh">
      <span class="type-badge" class:browser={b.type === 'browser.history'}>
        {#if b.type === 'browser.history'}<MonitorSmartphone size={13} /> Page visit{:else}<Globe size={13} /> DNS lookup{/if}
      </span>
      <h2 class="truncate mono">{(b.requested ?? ['?'])[0]}</h2>
      <div class="muted dh-time"><Clock size={12} /> {fullTime(hit?.source['@timestamp'])}</div>
    </div>
  {/snippet}
  {#snippet actions()}
    <Segmented size="sm" bind:value={tab} options={[{ value: 'summary', label: 'Summary', icon: Info }, { value: 'raw', label: 'JSON', icon: Braces }]} />
  {/snippet}

  {#if hit && tab === 'summary'}
    <div class="sections">
      <section>
        <div class="section-title">Who</div>
        <div class="kv">
          {#if entity}<div class="k">Entity</div><div class="v"><EntityLink field={entity.field} value={entity.value} /></div>{/if}
          {#if b.client}<div class="k">Address</div><div class="v"><EntityLink field="bite.client" value={b.client} /></div>{/if}
          {#if b.client_user}<div class="k">User</div><div class="v"><EntityLink field="bite.client_user" value={b.client_user} /></div>{/if}
          {#if b.client_hostname_short}<div class="k">Machine</div><div class="v"><EntityLink field="bite.client_hostname_short" value={b.client_hostname_short} /></div>{/if}
          {#if b.client_hosts_short?.length}<div class="k">PTR name</div><div class="v"><EntityLink field="bite.client_hosts_short" value={b.client_hosts_short[0]} /></div>{/if}
          {#if b.client_platform}<div class="k">Platform</div><div class="v">{b.client_platform} · {b.client_browser}</div>{/if}
        </div>
        {#if entity}
          <a class="btn btn-sm around" href={around()}><History size={14} /> Their events five minutes either side</a>
        {/if}
      </section>

      <section>
        <div class="section-title">What</div>
        <div class="kv">
          <div class="k">Name</div><div class="v mono">{(b.requested ?? [])[0]}</div>
          {#if b.registrable_domain}<div class="k">Domain</div><div class="v"><DomainLink domain={b.registrable_domain} /></div>{/if}
          {#if b.url}<div class="k">URL</div><div class="v mono small break">{b.url}</div>{/if}
          {#if b.response_code}<div class="k">Response</div><div class="v"><span class="badge" class:badge-bad={b.response_code !== 'NOERROR'}>{b.response_code}</span></div>{/if}
          {#if b.resolved_ips?.length}<div class="k">Answered</div><div class="v mono small">{b.resolved_ips.join(', ')}</div>{/if}
          {#if b.cname_chain?.length}<div class="k">CNAME chain</div><div class="v mono small">{b.cname_chain.join(' → ')}</div>{/if}
          {#if b.incidental}<div class="k">Incidental</div><div class="v"><span class="badge">Made on someone's behalf</span></div>{/if}
        </div>
      </section>

      <section>
        <div class="section-title">Why it is categorised this way</div>
        {#if !contexts.length && !candidates.length && !suppressed.length}
          <p class="muted small">No list claims this name, so it carries no category.</p>
        {:else}
          <div class="facets">
            {#each b.risk ?? [] as r (r)}<span class="facet risk"><span class="dot" style:background="var(--sev-critical)"></span>{taxon(r)}<span class="path">{r}</span></span>{/each}
            {#each b.purpose ?? [] as p (p)}<span class="facet"><span class="dot" style:background="var(--s1)"></span>{taxon(p)}<span class="path">{p}</span></span>{/each}
            {#each b.service ?? [] as sv (sv)}<span class="facet"><span class="dot" style:background="var(--s7)"></span>{taxon(sv)}<span class="path">{sv}</span></span>{/each}
          </div>
          <ul class="evidence">
            {#each contexts as c (c)}
              <li class="believed">
                <CircleCheck size={16} />
                <div><strong>{c}</strong> <span class="muted">is believed:</span>
                  {#if claims[c]?.length}<span class="muted"> {claims[c].length} list{claims[c].length === 1 ? '' : 's'} agree</span>
                    <div class="sources">{#each claims[c] as s (s)}<span class="src">{s}</span>{/each}</div>{/if}
                </div>
                {#if onfilter}<button class="link-btn small" onclick={() => onfilter?.(`category:${c}`)}>Filter</button>{/if}
              </li>
            {/each}
            {#each candidates as c (c)}
              <li class="candidate">
                <CircleHelp size={16} />
                <div><strong>{c}</strong> <span class="muted">is only a candidate: claimed, without the independent support it needs to be believed.</span>
                  {#if claims[c]?.length}<div class="sources">{#each claims[c] as s (s)}<span class="src">{s}</span>{/each}</div>{/if}
                </div>
              </li>
            {/each}
            {#each suppressed as c (c)}
              <li class="suppressed">
                <CircleSlash size={16} />
                <div><strong>{c}</strong> <span class="muted">was cancelled by the ignorelist, which knows better than the lists here.</span></div>
              </li>
            {/each}
          </ul>
          {#if b.resolvers}
            <div class="resolvers">
              <Scale size={14} />
              {#each Object.entries(b.resolvers) as [name, verdict] (name)}
                <span><span class="muted">{name}:</span> <strong>{verdict}</strong></span>
              {/each}
            </div>
          {/if}
        {/if}
      </section>
    </div>
  {:else if hit && tab === 'raw'}
    {#if full}
      <div class="raw"><JsonView value={maskSource(full.source)} open /></div>
    {:else}
      <div class="skeleton" style="height:300px"></div>
    {/if}
    <p class="muted small idx">{hit.index} · {hit.id} · {dateTime(hit.source['@timestamp'], true)}</p>
  {/if}
</Drawer>

<style>
  .dh { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
  .dh h2 { font-size: 1.05rem; }
  .dh-time { display: inline-flex; align-items: center; gap: 5px; font-size: 0.8rem; }
  .type-badge { display: inline-flex; align-items: center; gap: 5px; align-self: flex-start; font-size: 0.74rem; font-weight: 600;
    padding: 2px 8px; border-radius: 99px; background: color-mix(in srgb, var(--s1) 12%, transparent); color: var(--s1); }
  .type-badge.browser { background: color-mix(in srgb, var(--s7) 12%, transparent); color: var(--s7); }
  .sections { display: flex; flex-direction: column; gap: 22px; }
  section { display: flex; flex-direction: column; gap: 10px; }
  .kv { display: grid; grid-template-columns: 120px minmax(0, 1fr); gap: 8px 14px; font-size: 0.9rem; }
  .k { color: var(--text-3); }
  .v { min-width: 0; }
  .small { font-size: 0.82rem; }
  .break { word-break: break-all; }
  .around { align-self: flex-start; }
  .facets { display: flex; flex-wrap: wrap; gap: 6px; }
  .facet { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 99px; border: 1px solid var(--border-strong);
    font-size: 0.84rem; font-weight: 550; background: var(--surface); }
  .facet .path { color: var(--text-4); font-family: var(--font-mono); font-size: 0.74rem; font-weight: 400; }
  .evidence { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 8px; }
  .evidence li { display: flex; gap: 10px; align-items: flex-start; padding: 10px 12px; border-radius: var(--radius); border: 1px solid var(--border);
    background: var(--surface-2); font-size: 0.88rem; }
  .evidence li > div { flex: 1; }
  .believed :global(svg) { color: var(--good); flex: none; margin-top: 1px; }
  .candidate :global(svg) { color: var(--sev-medium); flex: none; margin-top: 1px; }
  .suppressed :global(svg) { color: var(--text-4); flex: none; margin-top: 1px; }
  .sources { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 6px; }
  .src { font-family: var(--font-mono); font-size: 0.74rem; padding: 2px 7px; border-radius: 5px; background: var(--surface-3); color: var(--text-2); }
  .resolvers { display: flex; align-items: center; flex-wrap: wrap; gap: 6px 14px; font-size: 0.84rem; color: var(--text-2); }
  .raw { padding: 12px; border-radius: var(--radius); background: var(--code-bg); border: 1px solid var(--border); }
  .idx { margin-top: 10px; font-family: var(--font-mono); }
</style>
