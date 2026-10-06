<script lang="ts">
  import { ExternalLink, ShieldAlert } from '@lucide/svelte';
  import { untrack, type Component } from 'svelte';
  import { api, setMfaRequiredHandler, setUnauthorizedHandler } from './lib/api';
  import { answerArrival, cameFromElsewhere, noteArrival } from './lib/arrival';
  import EmptyState from './lib/components/EmptyState.svelte';
  import Toasts from './lib/components/Toasts.svelte';
  import CommandPalette from './lib/layout/CommandPalette.svelte';
  import Sidebar from './lib/layout/Sidebar.svelte';
  import Topbar from './lib/layout/Topbar.svelte';
  import { Query } from './lib/query.svelte';
  import { navigate, router } from './lib/router.svelte';
  import { hideAddress } from './lib/privacy';
  import { prefs } from './lib/stores/prefs.svelte';
  import { session } from './lib/stores/session.svelte';
  import { routes } from './routes';

  let paletteOpen = $state(false);
  // Page code, by route, as it arrives. The page shown is derived from the
  // route in the same tick the route changes, so the page being left is gone
  // before it could react to the next page's parameters.
  let loaded = $state<Record<string, Component<any>>>({});
  let loadFailed = $state(false);

  noteArrival();
  router.init(routes);

  // A page opened from a link on another site is asked about before it
  // looks anyone up; the overview and your own account are not about anyone
  function arrivalApplies(): boolean {
    const route = router.route;
    return !!route && !route.public && router.path !== '/' && router.path !== '/account'
      && cameFromElsewhere(router.path);
  }
  let askArrival = $state(arrivalApplies());
  $effect(() => {
    void router.path;
    void router.search;
    askArrival = arrivalApplies();
  });
  setUnauthorizedHandler(() => {
    if (router.route?.public) return;
    const back = encodeURIComponent(location.pathname + location.search);
    location.assign(`/login?next=${back}`);
  });

  setMfaRequiredHandler(() => {
    if (!session.me?.mfa_required) session.load();
  });

  const ready = session.load().then((me) => {
    if (!me && !router.route?.public) {
      navigate(`/login?next=${encodeURIComponent(location.pathname + location.search)}`, { replace: true });
    }
  });

  // In privacy mode the address bar never shows a name: rewritten when the
  // mode is turned on, and when a link written without it is followed
  $effect(() => {
    void router.path;
    void router.search;
    if (prefs.privacy && session.me) untrack(() => hideAddress());
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
          {:else if askArrival}
            <EmptyState icon={ExternalLink} title="You followed a link from another site"
                        body={`It opens ${router.route?.title ?? 'a page'}. What you look at here is recorded in the audit log under your name, so open it only if you meant to.`}>
              <div class="row">
                <button class="btn btn-primary" onclick={() => { answerArrival(); askArrival = false; }}>Open it</button>
                <a class="btn" href="/" onclick={answerArrival}>Go to the overview</a>
              </div>
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
