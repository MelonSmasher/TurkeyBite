// Display preferences: theme, accent, density, privacy mode.
//
// They belong to the account, and follow a person from browser to browser.
// How the page looks (theme, accent, density, sidebar) is also kept in this
// browser, so it applies before the first paint; privacy mode is not, so on a
// shared computer one person's choice never decides what the next one sees.
// A change saves only what changed, at once for privacy mode, so a slow save
// or another tab cannot put an older value back; other tabs of the same
// person hear about it straight away.

import { api } from '../api';
import { toasts } from './toasts.svelte';

export type Theme = 'light' | 'dark' | 'system';
export type Accent = 'iris' | 'ocean' | 'forest' | 'ember' | 'rose' | 'slate';
export type Density = 'comfortable' | 'compact';

export const ACCENTS: { id: Accent; label: string; swatch: string }[] = [
  { id: 'iris', label: 'Iris', swatch: '#5b4fe9' },
  { id: 'ocean', label: 'Ocean', swatch: '#0b84a5' },
  { id: 'forest', label: 'Forest', swatch: '#1f8a4c' },
  { id: 'ember', label: 'Ember', swatch: '#d9480f' },
  { id: 'rose', label: 'Rose', swatch: '#d6336c' },
  { id: 'slate', label: 'Slate', swatch: '#3f4b5f' },
];

const KEY = 'tbc.prefs';

interface Look {
  theme?: Theme;
  accent?: Accent;
  density?: Density;
  sidebar_collapsed?: boolean;
}

type Changes = Partial<{ theme: Theme; accent: Accent; density: Density; privacy: boolean; sidebarCollapsed: boolean }>;

function load(): Look {
  try {
    return JSON.parse(localStorage.getItem(KEY) || '{}');
  } catch {
    return {};
  }
}

function wire(changes: Changes): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (changes.theme !== undefined) out.theme = changes.theme;
  if (changes.accent !== undefined) out.accent = changes.accent;
  if (changes.density !== undefined) out.density = changes.density;
  if (changes.privacy !== undefined) out.privacy_mode = changes.privacy;
  if (changes.sidebarCollapsed !== undefined) out.sidebar_collapsed = changes.sidebarCollapsed;
  return out;
}

class Prefs {
  theme = $state<Theme>('system');
  accent = $state<Accent>('iris');
  density = $state<Density>('comfortable');
  privacy = $state(false);
  sidebarCollapsed = $state(false);
  resolvedTheme = $state<'light' | 'dark'>('light');
  #media = matchMedia('(prefers-color-scheme: dark)');
  #saveTimer: ReturnType<typeof setTimeout> | null = null;
  #unsaved: Record<string, unknown> = {};
  #user: string | null = null;
  #channel = typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel('tbc-prefs');

  constructor() {
    const stored = load();
    this.theme = stored.theme ?? 'system';
    this.accent = stored.accent ?? 'iris';
    this.density = stored.density ?? 'comfortable';
    this.sidebarCollapsed = stored.sidebar_collapsed ?? false;
    this.#media.addEventListener('change', () => this.apply());
    this.#channel?.addEventListener('message', (event) => {
      const { user, changes } = event.data ?? {};
      if (user && user === this.#user) this.#change(changes as Changes);
    });
    this.apply();
  }

  /** The account's preferences, as the server has them; the organisation's
   *  privacy default where the person has not chosen. */
  adopt(server: Record<string, unknown>, privacyDefault: boolean, user: string) {
    this.#user = user;
    if (server.theme) this.theme = server.theme as Theme;
    if (server.accent) this.accent = server.accent as Accent;
    if (server.density) this.density = server.density as Density;
    if (typeof server.sidebar_collapsed === 'boolean') this.sidebarCollapsed = server.sidebar_collapsed;
    this.privacy = typeof server.privacy_mode === 'boolean' ? server.privacy_mode : privacyDefault;
    this.apply();
  }

  /** Forgets whose preferences these are, at sign-out. */
  forget() {
    this.#user = null;
    this.privacy = false;
    this.apply();
  }

  apply() {
    const dark = this.theme === 'dark' || (this.theme === 'system' && this.#media.matches);
    this.resolvedTheme = dark ? 'dark' : 'light';
    const root = document.documentElement;
    root.dataset.theme = this.resolvedTheme;
    root.dataset.accent = this.accent;
    root.dataset.density = this.density;
    root.classList.toggle('privacy', this.privacy);
    localStorage.setItem(KEY, JSON.stringify({
      theme: this.theme, accent: this.accent, density: this.density, sidebar_collapsed: this.sidebarCollapsed,
    } satisfies Look));
  }

  #change(changes: Changes) {
    if (changes.theme) this.theme = changes.theme;
    if (changes.accent) this.accent = changes.accent;
    if (changes.density) this.density = changes.density;
    if (changes.privacy !== undefined) this.privacy = changes.privacy;
    if (changes.sidebarCollapsed !== undefined) this.sidebarCollapsed = changes.sidebarCollapsed;
    this.apply();
  }

  set(changes: Changes, persist = true) {
    this.#change(changes);
    if (!persist || !this.#user) return;
    this.#channel?.postMessage({ user: this.#user, changes });
    Object.assign(this.#unsaved, wire(changes));
    if (this.#saveTimer) clearTimeout(this.#saveTimer);
    // Privacy mode saves at once: a reload a moment later must not show names
    if (changes.privacy !== undefined) this.#save();
    else this.#saveTimer = setTimeout(() => this.#save(), 400);
  }

  #save() {
    const body = this.#unsaved;
    this.#unsaved = {};
    this.#saveTimer = null;
    if (!Object.keys(body).length || !this.#user) return;
    // Saved only onto the account this tab belongs to
    api.put('/account/preferences', { ...body, user_id: this.#user }).catch((e) => {
      if ((e as { status?: number }).status === 409) {
        location.reload();
        return;
      }
      toasts.error('Your preference was not saved',
        'privacy_mode' in body ? 'Privacy mode applies here, but another browser or a reload may not have it.'
          : 'It applies here until you reload.');
    });
  }
}

export const prefs = new Prefs();
