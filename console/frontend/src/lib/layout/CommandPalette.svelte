<script lang="ts">
  // ⌘K: jump to any page, a person, a domain, a finding, or straight into a
  // search, and flip the switches people reach for most.
  import { ArrowRight, CornerDownLeft, Eye, Globe, Moon, ScanSearch, ShieldAlert, Sun, User, Wand2 } from '@lucide/svelte';
  import type { Component } from 'svelte';
  import { api } from '../api';
  import { trap } from '../components/focus';
  import { NAV } from '../nav';
  import { entitySegment, exploreLink, findingText } from '../privacy';
  import { navigate } from '../router.svelte';
  import { prefs } from '../stores/prefs.svelte';
  import { session } from '../stores/session.svelte';
  import type { Finding } from '../types';

  let { open = $bindable(false) }: { open?: boolean } = $props();
  let text = $state('');
  let active = $state(0);
  let input: HTMLInputElement | undefined = $state();
  let findings = $state<Finding[]>([]);
  let timer: ReturnType<typeof setTimeout> | null = null;

  interface Item {
    id: string;
    label: string;
    hint?: string;
    group: string;
    icon: Component<any>;
    run: () => void;
  }

  const looksLikeDomain = (t: string) => /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(t) && !/^\d+(\.\d+){3}$/.test(t);
  const looksLikeIp = (t: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(t);

  const items = $derived.by(() => {
    const q = text.trim().toLowerCase();
    const out: Item[] = [];
    if (q && session.can('events:read')) {
      out.push({ id: 'search', label: `Search events for “${text.trim()}”`, group: 'Search', icon: ScanSearch,
                 run: () => navigate(exploreLink({ q: text.trim() })) });
      if (looksLikeDomain(q)) {
        out.push({ id: 'domain', label: `Open domain ${q}`, group: 'Search', icon: Globe,
                   run: () => navigate(`/domains/${encodeURIComponent(q)}`) });
      } else if (looksLikeIp(q)) {
        out.push({ id: 'ip', label: `Open client ${q}`, group: 'Search', icon: User,
                   run: () => navigate(`/entities/bite.client/${entitySegment(q)}`) });
      } else if (/^[a-z0-9][a-z0-9._-]+$/.test(q)) {
        out.push({ id: 'user', label: `Open user ${q}`, group: 'Search', icon: User,
                   run: () => navigate(`/entities/bite.client_user/${entitySegment(q)}`) });
        out.push({ id: 'host', label: `Open host ${q}`, group: 'Search', icon: User,
                   run: () => navigate(`/entities/bite.client_hostname_short/${entitySegment(q)}`) });
      }
    }
    for (const f of findings) {
      out.push({ id: `f-${f.id}`, label: findingText(f.title, f), hint: `F-${f.number} · ${f.severity}`, group: 'Findings',
                 icon: ShieldAlert, run: () => navigate(`/findings/${f.id}`) });
    }
    for (const group of NAV) {
      for (const item of group.items) {
        if (item.permission && !session.can(item.permission)) continue;
        const hay = `${item.label} ${item.keywords ?? ''} ${group.label}`.toLowerCase();
        if (!q || hay.includes(q)) {
          out.push({ id: item.href, label: item.label, hint: group.label, group: 'Go to', icon: item.icon,
                     run: () => navigate(item.href) });
        }
      }
    }
    const actions: Item[] = [
      { id: 'theme', label: prefs.resolvedTheme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme',
        group: 'Actions', icon: prefs.resolvedTheme === 'dark' ? Sun : Moon,
        run: () => prefs.set({ theme: prefs.resolvedTheme === 'dark' ? 'light' : 'dark' }) },
      { id: 'privacy', label: prefs.privacy ? 'Turn privacy mode off' : 'Turn privacy mode on (mask identities)',
        group: 'Actions', icon: Eye, run: () => prefs.set({ privacy: !prefs.privacy }) },
    ];
    if (session.can('rules:write')) {
      actions.push({ id: 'new-rule', label: 'Create a rule', group: 'Actions', icon: Wand2, run: () => navigate('/rules/new') });
    }
    out.push(...actions.filter((a) => !q || a.label.toLowerCase().includes(q)));
    return out.slice(0, 40);
  });

  const grouped = $derived.by(() => {
    const map = new Map<string, Item[]>();
    for (const item of items) {
      if (!map.has(item.group)) map.set(item.group, []);
      map.get(item.group)!.push(item);
    }
    return [...map.entries()];
  });

  $effect(() => {
    const q = text.trim();
    if (timer) clearTimeout(timer);
    if (!q || q.length < 2 || !session.can('findings:read')) {
      findings = [];
      return;
    }
    // An answer to an earlier keystroke that arrives late is thrown away
    const controller = new AbortController();
    timer = setTimeout(async () => {
      try {
        const data = await api.get<{ items: Finding[] }>(`/findings?q=${encodeURIComponent(q)}&limit=5&sort=last_seen`,
                                                         { signal: controller.signal });
        if (!controller.signal.aborted) findings = data.items;
      } catch {
        if (!controller.signal.aborted) findings = [];
      }
    }, 180);
    return () => {
      controller.abort();
      if (timer) clearTimeout(timer);
    };
  });

  $effect(() => {
    if (open) {
      text = '';
      active = 0;
    }
  });

  $effect(() => {
    void items.length;
    active = 0;
  });

  function run(item: Item | undefined) {
    if (!item) return;
    open = false;
    item.run();
  }

  function onkeydown(event: KeyboardEvent) {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      open = !open;
      return;
    }
    if (!open) return;
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      active = Math.min(items.length - 1, active + 1);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      active = Math.max(0, active - 1);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      run(items[active]);
    }
  }
</script>

<svelte:window {onkeydown} />

{#if open}
  <div class="backdrop" role="presentation" onclick={() => (open = false)}></div>
  <div class="palette" role="dialog" aria-modal="true" aria-label="Command palette"
       use:trap={{ onescape: () => (open = false), initial: 'input' }}>
    <div class="search">
      <ScanSearch size={18} />
      <input bind:this={input} bind:value={text} placeholder="Type a page, a person, a domain, or anything to search…"
             aria-label="Command" spellcheck="false" autocomplete="off" />
      <span class="kbd">Esc</span>
    </div>
    <div class="results" role="listbox">
      {#each grouped as [group, list] (group)}
        <div class="group-label">{group}</div>
        {#each list as item (item.id)}
          {@const index = items.indexOf(item)}
          <button class="result" class:active={index === active} role="option" aria-selected={index === active}
                  onmouseenter={() => (active = index)} onclick={() => run(item)}>
            <span class="icon"><item.icon size={16} /></span>
            <span class="label truncate">{item.label}</span>
            {#if item.hint}<span class="hint">{item.hint}</span>{/if}
            {#if index === active}<ArrowRight size={14} class="go" />{/if}
          </button>
        {/each}
      {:else}
        <div class="muted none">No matches</div>
      {/each}
    </div>
    <div class="foot">
      <span><span class="kbd">↑</span><span class="kbd">↓</span> move</span>
      <span><span class="kbd"><CornerDownLeft size={11} /></span> open</span>
    </div>
  </div>
{/if}

<style>
  .backdrop { position: fixed; inset: 0; z-index: 90; background: rgba(10, 12, 18, 0.4); backdrop-filter: blur(3px); }
  .palette {
    position: fixed; z-index: 91; top: 12vh; left: 50%; transform: translateX(-50%); width: min(640px, calc(100vw - 32px));
    background: var(--surface); border: 1px solid var(--border-strong); border-radius: 16px; box-shadow: var(--shadow-lg);
    overflow: hidden; animation: pop 160ms var(--ease);
  }
  .search { display: flex; align-items: center; gap: 12px; padding: 14px 16px; border-bottom: 1px solid var(--divider); color: var(--text-3); }
  .search input { flex: 1; border: 0; outline: none; background: none; font-size: 1.02rem; color: var(--text); }
  .results { max-height: 52vh; overflow: auto; padding: 6px; }
  .group-label { padding: 10px 10px 4px; font-size: 0.7rem; font-weight: 650; text-transform: uppercase; letter-spacing: 0.07em; color: var(--text-4); }
  .result {
    display: flex; align-items: center; gap: 11px; width: 100%; padding: 9px 10px; border: 0; background: none;
    border-radius: 9px; cursor: pointer; text-align: left; color: var(--text-2); font-size: 0.93rem;
  }
  .result.active { background: var(--accent-soft); color: var(--text); }
  .icon { width: 28px; height: 28px; border-radius: 8px; display: grid; place-items: center; background: var(--surface-3); color: var(--text-3); flex: none; }
  .result.active .icon { background: var(--accent); color: var(--text-on-accent); }
  .label { flex: 1; }
  .hint { font-size: 0.78rem; color: var(--text-4); white-space: nowrap; }
  .result :global(.go) { color: var(--accent-text); }
  .none { padding: 24px; text-align: center; }
  .foot { display: flex; gap: 16px; padding: 9px 16px; border-top: 1px solid var(--divider); font-size: 0.76rem; color: var(--text-4); background: var(--surface-2); }
  .foot span { display: inline-flex; align-items: center; gap: 4px; }
  @keyframes pop { from { opacity: 0; transform: translate(-50%, -6px) scale(0.985); } }
</style>
