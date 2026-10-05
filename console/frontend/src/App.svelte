<script lang="ts">
  import { ShieldAlert } from '@lucide/svelte';
  import type { Component } from 'svelte';
  import { api, setUnauthorizedHandler } from './lib/api';
  import EmptyState from './lib/components/EmptyState.svelte';
  import Toasts from './lib/components/Toasts.svelte';
  import CommandPalette from './lib/layout/CommandPalette.svelte';
  import Sidebar from './lib/layout/Sidebar.svelte';
  import Topbar from './lib/layout/Topbar.svelte';
  import { Query } from './lib/query.svelte';
  import { navigate, router } from './lib/router.svelte';
  import { prefs } from './lib/stores/prefs.svelte';
  import { session } from './lib/stores/session.svelte';
  import { routes } from './routes';

  let paletteOpen = $state(false);
  // Page code, by route, as it arrives. The page shown is derived from the
  // route in the same tick the route changes, so the page being left is gone
  // before it could react to the next page's parameters.
  let loaded = $state<Record<string, Component<any>>>({});
  let loadFailed = $state(false);

  router.init(routes);
  setUnauthorizedHandler(() => {
    if (router.route?.public) return;
    const back = encodeURIComponent(location.pathname + location.search);
    location.assign(`/login?next=${back}`);
  });

  const ready = session.load().then((me) => {
    if (!me && !router.route?.public) {
      navigate(`/login?next=${encodeURIComponent(location.pathname + location.search)}`, { replace: true });
    }
  });

  // An admin who must set up a second factor can do nothing else until they
  // have, wherever they try to go
  $effect(() => {
    if (session.me?.mfa_required && router.path !== '/account') navigate('/account?setup=mfa', { replace: true });
  });

  const RELOADED = 'tbc.reloaded';

  $effect(() => {
    const route = router.route;
    if (!route || loaded[route.pattern]) return;
    const pattern = route.pattern;
    loadFailed = false;
    route.component().then((module) => {
      loaded[pattern] = module.default;
      sessionStorage.removeItem(RELOADED);
    }).catch(() => {
      if (router.route?.pattern !== pattern) return;
      // The console was updated since this tab loaded it, and this page's code
      // is gone: load the page afresh, once, rather than leave the last one up
      if (sessionStorage.getItem(RELOADED) !== location.pathname) {
        sessionStorage.setItem(RELOADED, location.pathname);
        location.reload();
      } else {
        loadFailed = true;
      }
    });
  });

  const Page = $derived(router.route ? loaded[router.route.pattern] ?? null : null);
  const pageKey = $derived(router.path);
  const pageParams = $derived(router.params);

  const openFindings = new Query(
    (signal) => api.get<{ open_by_severity: Record<string, number> }>('/findings/stats?days=1', { signal }),
    { refreshMs: 60000, enabled: () => !!session.me && session.can('findings:read') });
  const urgent = $derived((openFindings.data?.open_by_severity.critical ?? 0) + (openFindings.data?.open_by_severity.high ?? 0));

  const allowed = $derived(!router.route?.permission || session.can(router.route.permission));
</script>

{#await ready then}
  {#if router.route?.public}
    {#if Page}<Page params={pageParams} />{/if}
  {:else if session.me}
    <div class="app" class:collapsed={prefs.sidebarCollapsed}>
      <Sidebar openFindings={urgent} />
      <div class="main">
        <Topbar onpalette={() => (paletteOpen = true)} />
        <main class="content">
          {#if !router.route}
            <EmptyState title="Nothing lives here" body="The page you asked for does not exist. Try the command palette (⌘K).">
              <a class="btn" href="/">Go to the overview</a>
            </EmptyState>
          {:else if !allowed}
            <EmptyState icon={ShieldAlert} title="You do not have access to this" body="Your role does not include this page. An administrator can change that." />
          {:else if loadFailed}
            <EmptyState title="This page could not be loaded" body="The console may have been updated. Reload to get the latest version.">
              <button class="btn" onclick={() => location.reload()}>Reload</button>
            </EmptyState>
          {:else if Page}
            {#key pageKey}
              <div class="page fade-enter"><Page params={pageParams} /></div>
            {/key}
          {:else}
            <div class="skeleton" style="height:320px" aria-busy="true" aria-label="Loading"></div>
          {/if}
        </main>
      </div>
    </div>
    <CommandPalette bind:open={paletteOpen} />
  {/if}
{/await}
<Toasts />

<style>
  .app { min-height: 100vh; }
  .main { margin-left: var(--sidebar-w); min-height: 100vh; display: flex; flex-direction: column; transition: margin-left var(--med) var(--ease); }
  .collapsed .main { margin-left: var(--sidebar-w-collapsed); }
  .content {
    flex: 1; padding: 26px 32px 48px; width: 100%; max-width: 1640px; margin: 0 auto;
    background-image: radial-gradient(ellipse 80% 40% at 50% -10%, var(--bg-grad-1), transparent 70%);
  }
  :global(:root[data-density='compact']) .content { padding: 20px 24px 40px; }
  @media (max-width: 900px) {
    .main { margin-left: var(--sidebar-w-collapsed); }
    .content { padding: 18px 16px 40px; }
  }
</style>
