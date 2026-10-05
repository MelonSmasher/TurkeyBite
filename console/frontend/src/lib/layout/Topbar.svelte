<script lang="ts">
  import { Bell, Check, Eye, EyeOff, LogOut, Monitor, Moon, Palette, Search, Settings2, Sun, UserRound } from '@lucide/svelte';
  import { api } from '../api';
  import Avatar from '../components/Avatar.svelte';
  import Menu from '../components/Menu.svelte';
  import SeverityBadge from '../components/SeverityBadge.svelte';
  import { tip } from '../components/tooltip';
  import { ago } from '../format';
  import { findingText } from '../privacy';
  import { Query } from '../query.svelte';
  import { ACCENTS, prefs, type Theme } from '../stores/prefs.svelte';
  import { session } from '../stores/session.svelte';
  import type { Finding } from '../types';

  let { onpalette }: { onpalette: () => void } = $props();

  const freshness = new Query(
    (signal) => api.get<{ latest: string | null; last_5m: number }>('/events/freshness', { signal }),
    { refreshMs: 30000, enabled: () => session.can('events:read') });
  const recent = new Query(
    (signal) => api.get<{ total: number; items: Finding[] }>('/findings?status=new&sort=severity&limit=6', { signal }),
    { refreshMs: 45000, enabled: () => session.can('findings:read') });

  let now = $state(Date.now());
  $effect(() => {
    const t = setInterval(() => (now = Date.now()), 15000);
    return () => clearInterval(t);
  });

  const lagSeconds = $derived(freshness.data?.latest ? (now - new Date(freshness.data.latest).getTime()) / 1000 : null);
  const pipeline = $derived(lagSeconds === null ? 'unknown' : lagSeconds < 300 ? 'live' : lagSeconds < 1800 ? 'delayed' : 'stalled');
  const isMac = navigator.platform.toLowerCase().includes('mac');
  const themes: { id: Theme; label: string; icon: typeof Sun }[] = [
    { id: 'light', label: 'Light', icon: Sun }, { id: 'dark', label: 'Dark', icon: Moon }, { id: 'system', label: 'System', icon: Monitor },
  ];
</script>

<header class="topbar">
  <button class="palette-trigger" onclick={onpalette} aria-label="Search or jump to (command palette)">
    <Search size={15} />
    <span>Search or jump to…</span>
    <span class="keys"><span class="kbd">{isMac ? '⌘' : 'Ctrl'}</span><span class="kbd">K</span></span>
  </button>
  <div class="spacer"></div>

  {#if session.can('events:read')}
    <a class="pipeline {pipeline}" href="/explore" use:tip={freshness.data?.latest
      ? `Newest event ${ago(freshness.data.latest, now)} · ${freshness.data.last_5m.toLocaleString()} in the last 5 minutes`
      : 'No events yet'}>
      <span class="pulse"></span>
      <span>{pipeline === 'live' ? 'Live' : pipeline === 'delayed' ? 'Delayed' : pipeline === 'stalled' ? 'Stalled' : '…'}</span>
      {#if freshness.data && pipeline === 'live'}<span class="rate tabular">{freshness.data.last_5m.toLocaleString()}/5m</span>{/if}
    </a>
  {/if}

  <button class="btn btn-ghost btn-icon" onclick={() => prefs.set({ privacy: !prefs.privacy })}
          use:tip={prefs.privacy ? 'Privacy mode is on: identities are masked' : 'Mask identities (privacy mode)'}
          aria-pressed={prefs.privacy} class:privacy-on={prefs.privacy}>
    {#if prefs.privacy}<EyeOff size={17} />{:else}<Eye size={17} />{/if}
  </button>

  <Menu width={248} label="Appearance">
    {#snippet trigger({ toggle })}
      <button class="btn btn-ghost btn-icon" onclick={toggle} use:tip={'Appearance'} aria-label="Appearance">
        {#if prefs.resolvedTheme === 'dark'}<Moon size={17} />{:else}<Sun size={17} />{/if}
      </button>
    {/snippet}
    {#snippet children()}
      <div class="menu-label">Theme</div>
      {#each themes as t (t.id)}
        <button class="menu-item" onclick={() => prefs.set({ theme: t.id })}>
          <t.icon size={15} /> {t.label}
          {#if prefs.theme === t.id}<Check size={15} style="margin-left:auto" />{/if}
        </button>
      {/each}
      <div class="menu-sep"></div>
      <div class="menu-label">Accent</div>
      <div class="accents">
        {#each ACCENTS as a (a.id)}
          <button class="swatch" class:on={prefs.accent === a.id} style:--sw={a.swatch}
                  onclick={() => prefs.set({ accent: a.id })} use:tip={a.label} aria-label="{a.label} accent">
            {#if prefs.accent === a.id}<Check size={13} strokeWidth={3} />{/if}
          </button>
        {/each}
      </div>
      <div class="menu-sep"></div>
      <button class="menu-item" onclick={() => prefs.set({ density: prefs.density === 'compact' ? 'comfortable' : 'compact' })}>
        <Palette size={15} /> {prefs.density === 'compact' ? 'Comfortable density' : 'Compact density'}
      </button>
    {/snippet}
  </Menu>

  {#if session.can('findings:read')}
    <Menu width={380} label="New findings">
      {#snippet trigger({ toggle })}
        <button class="btn btn-ghost btn-icon bell" onclick={toggle} use:tip={'New findings'} aria-label="New findings">
          <Bell size={17} />
          {#if recent.data?.total}<span class="bell-count">{recent.data.total > 9 ? '9+' : recent.data.total}</span>{/if}
        </button>
      {/snippet}
      {#snippet children({ close })}
        <div class="notif-head">
          <strong>New findings</strong>
          <span class="muted">{recent.data?.total ?? 0} waiting for triage</span>
        </div>
        {#each recent.data?.items ?? [] as f (f.id)}
          <a class="notif" href="/findings/{f.id}" onclick={close}>
            <SeverityBadge severity={f.severity} compact />
            <span class="notif-text">
              <span class="notif-title truncate">{findingText(f.title, f)}</span>
              <span class="muted">{f.rule_name} · {ago(f.last_seen)}</span>
            </span>
          </a>
        {:else}
          <div class="muted notif-empty">Nothing new. Nicely done.</div>
        {/each}
        <div class="menu-sep"></div>
        <a class="menu-item" href="/findings?status=new" onclick={close}>Open the triage queue →</a>
      {/snippet}
    </Menu>
  {/if}

  <Menu width={240} label="Account">
    {#snippet trigger({ toggle })}
      <button class="user" onclick={toggle} aria-label="Account menu">
        <Avatar name={session.user?.display_name ?? '?'} size={30} />
      </button>
    {/snippet}
    {#snippet children({ close })}
      <div class="who">
        <div class="who-name">{session.user?.display_name}</div>
        <div class="muted who-meta">{session.user?.username} · {session.user?.role} · {session.user?.source === 'ldap' ? 'directory' : session.user?.source}</div>
      </div>
      <div class="menu-sep"></div>
      <a class="menu-item" href="/account" onclick={close}><UserRound size={15} /> Your account</a>
      {#if session.can('settings:admin')}<a class="menu-item" href="/admin/system" onclick={close}><Settings2 size={15} /> System</a>{/if}
      <div class="menu-sep"></div>
      <button class="menu-item" onclick={() => session.logout()}><LogOut size={15} /> Sign out</button>
    {/snippet}
  </Menu>
</header>

<style>
  .topbar {
    position: sticky; top: 0; z-index: 25; height: var(--topbar-h);
    display: flex; align-items: center; gap: 6px; padding: 0 20px 0 24px;
    background: color-mix(in srgb, var(--bg) 82%, transparent); backdrop-filter: saturate(1.4) blur(12px);
    border-bottom: 1px solid var(--border);
  }
  .palette-trigger {
    display: flex; align-items: center; gap: 9px; width: min(420px, 40vw); height: 34px; padding: 0 8px 0 11px;
    border-radius: var(--radius); border: 1px solid var(--border-strong); background: var(--surface);
    color: var(--text-4); font-size: 0.9rem; cursor: pointer; box-shadow: var(--shadow-sm);
    transition: border-color var(--fast);
  }
  .palette-trigger:hover { border-color: var(--text-4); }
  .palette-trigger span:nth-child(2) { flex: 1; text-align: left; }
  .keys { display: flex; gap: 3px; }
  .pipeline {
    display: inline-flex; align-items: center; gap: 7px; height: 30px; padding: 0 11px; margin-right: 6px;
    border-radius: 999px; font-size: 0.8rem; font-weight: 600; text-decoration: none;
    background: var(--surface); border: 1px solid var(--border); color: var(--text-2);
  }
  .pipeline:hover { text-decoration: none; border-color: var(--border-strong); }
  .pulse { width: 8px; height: 8px; border-radius: 99px; background: var(--text-4); }
  .live .pulse { background: var(--good); box-shadow: 0 0 0 0 rgba(12, 163, 12, 0.5); animation: ping 2s infinite; }
  .delayed .pulse { background: var(--sev-medium); }
  .stalled .pulse { background: var(--sev-critical); animation: pulse 1.2s infinite; }
  .stalled { color: var(--sev-critical); border-color: color-mix(in srgb, var(--sev-critical) 40%, transparent); }
  .rate { color: var(--text-4); font-weight: 500; }
  @keyframes ping { 0% { box-shadow: 0 0 0 0 rgba(12, 163, 12, 0.45); } 70% { box-shadow: 0 0 0 7px rgba(12, 163, 12, 0); } 100% { box-shadow: 0 0 0 0 rgba(12, 163, 12, 0); } }
  .privacy-on { color: var(--accent-text); background: var(--accent-soft); }
  .accents { display: flex; gap: 6px; padding: 4px 9px 8px; }
  .swatch {
    width: 26px; height: 26px; border-radius: 8px; border: 2px solid transparent; cursor: pointer;
    background: var(--sw); color: #fff; display: grid; place-items: center;
  }
  .swatch.on { box-shadow: 0 0 0 2px var(--surface), 0 0 0 4px var(--sw); }
  .bell { position: relative; }
  .bell-count {
    position: absolute; top: 3px; right: 2px; min-width: 16px; height: 16px; padding: 0 4px; border-radius: 99px;
    background: var(--sev-critical); color: #fff; font-size: 0.66rem; font-weight: 700; display: grid; place-items: center;
    box-shadow: 0 0 0 2px var(--bg);
  }
  .notif-head { display: flex; flex-direction: column; gap: 2px; padding: 8px 10px 8px; font-size: 0.86rem; }
  .notif {
    display: flex; align-items: flex-start; gap: 10px; padding: 8px 10px; border-radius: var(--radius-sm);
    text-decoration: none; color: var(--text);
  }
  .notif:hover { background: var(--surface-hover); text-decoration: none; }
  .notif-text { display: flex; flex-direction: column; gap: 2px; min-width: 0; font-size: 0.86rem; }
  .notif-text .muted { font-size: 0.78rem; }
  .notif-title { font-weight: 550; }
  .notif-empty { padding: 14px 10px; font-size: 0.86rem; }
  .user { border: 0; background: none; padding: 2px; margin-left: 4px; border-radius: 999px; cursor: pointer; }
  .user:hover { box-shadow: 0 0 0 3px var(--accent-soft); }
  .who { padding: 8px 10px; }
  .who-name { font-weight: 600; }
  .who-meta { font-size: 0.8rem; }
</style>
