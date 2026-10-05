// A small history-mode router. Plain <a href="/..."> links are intercepted, so
// pages link with ordinary anchors and the browser's own middle-click and
// copy-link behaviour keep working.

import type { Component } from 'svelte';

export interface RouteDef {
  pattern: string;
  component: () => Promise<{ default: Component<any> }>;
  title: string;
  permission?: string;
  public?: boolean;
  section?: string;
}

interface Compiled extends RouteDef {
  regex: RegExp;
  keys: string[];
}

function compile(route: RouteDef): Compiled {
  const keys: string[] = [];
  const source = route.pattern
    .replace(/\/$/, '')
    .split('/')
    .map((part) => {
      if (part.startsWith(':')) {
        keys.push(part.slice(1));
        return '([^/]+)';
      }
      if (part === '*') {
        keys.push('rest');
        return '(.*)';
      }
      return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('/');
  return { ...route, keys, regex: new RegExp(`^${source || ''}/?$`) };
}

class Router {
  path = $state(location.pathname);
  search = $state(location.search);
  params = $state<Record<string, string>>({});
  route = $state<Compiled | null>(null);
  #routes: Compiled[] = [];

  get query(): URLSearchParams {
    return new URLSearchParams(this.search);
  }

  init(routes: RouteDef[]) {
    this.#routes = routes.map(compile);
    this.#resolve();
    window.addEventListener('popstate', () => {
      this.path = location.pathname;
      this.search = location.search;
      this.#resolve();
    });
    document.addEventListener('click', (event) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey ||
          event.shiftKey || event.altKey) return;
      const anchor = (event.target as HTMLElement | null)?.closest?.('a');
      if (!anchor || anchor.target || anchor.hasAttribute('download')) return;
      const href = anchor.getAttribute('href');
      if (!href || !href.startsWith('/') || href.startsWith('/api/') || href.startsWith('//')) return;
      event.preventDefault();
      this.navigate(href);
    });
  }

  #resolve() {
    for (const route of this.#routes) {
      const match = route.regex.exec(this.path);
      if (match) {
        const params: Record<string, string> = {};
        try {
          route.keys.forEach((key, i) => (params[key] = decodeURIComponent(match[i + 1] ?? '')));
        } catch {
          // A malformed %-escape: no page, rather than a blank one
          break;
        }
        this.params = params;
        this.route = route;
        document.title = `${route.title} · TurkeyBite Console`;
        return;
      }
    }
    this.params = {};
    this.route = null;
    document.title = 'Not found · TurkeyBite Console';
  }

  navigate(href: string, opts: { replace?: boolean } = {}) {
    const url = new URL(href, location.origin);
    const samePath = url.pathname === this.path;
    if (opts.replace) history.replaceState({}, '', url);
    else history.pushState({}, '', url);
    this.path = url.pathname;
    this.search = url.search;
    this.#resolve();
    if (!samePath) window.scrollTo({ top: 0 });
  }

  /** Updates query parameters in place, without a new history entry. */
  setQuery(updates: Record<string, string | null | undefined>, opts: { push?: boolean } = {}) {
    const params = new URLSearchParams(location.search);
    for (const [key, value] of Object.entries(updates)) {
      if (value === null || value === undefined || value === '') params.delete(key);
      else params.set(key, value);
    }
    const text = params.toString();
    const url = `${location.pathname}${text ? `?${text}` : ''}`;
    if (url === `${location.pathname}${location.search}`) return;
    if (opts.push) history.pushState({}, '', url);
    else history.replaceState({}, '', url);
    this.search = location.search;
  }
}

export const router = new Router();

export function navigate(href: string, opts?: { replace?: boolean }) {
  router.navigate(href, opts);
}
