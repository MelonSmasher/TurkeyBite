// Display preferences: theme, accent, density, privacy mode. Kept in local
// storage so they apply before the first paint, and saved to the account so
// they follow a person to another browser.

import { api } from '../api';

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

interface Stored {
  theme?: Theme;
  accent?: Accent;
  density?: Density;
  privacy_mode?: boolean;
  sidebar_collapsed?: boolean;
  timezone?: string;
  // When these were last changed here, so the newer of this browser's and
  // the account's preferences wins, whichever arrives last
  updated_at?: number;
}

function load(): Stored {
  try {
    return JSON.parse(localStorage.getItem(KEY) || '{}');
  } catch {
    return {};
  }
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
  #updatedAt = 0;

  constructor() {
    const stored = load();
    this.theme = stored.theme ?? 'system';
    this.accent = stored.accent ?? 'iris';
    this.density = stored.density ?? 'comfortable';
    this.privacy = stored.privacy_mode ?? false;
    this.sidebarCollapsed = stored.sidebar_collapsed ?? false;
    this.#updatedAt = stored.updated_at ?? 0;
    this.#media.addEventListener('change', () => this.apply());
    this.apply();
  }

  /** The account's preferences, unless this browser changed its own since;
   *  then this browser's are saved to the account instead. */
  adopt(server: Record<string, unknown>, privacyDefault: boolean) {
    const serverAt = typeof server.updated_at === 'number' ? server.updated_at : 0;
    if (this.#updatedAt > serverAt) {
      this.#save();
      return;
    }
    if (server.theme) this.theme = server.theme as Theme;
    if (server.accent) this.accent = server.accent as Accent;
    if (server.density) this.density = server.density as Density;
    if (typeof server.sidebar_collapsed === 'boolean') this.sidebarCollapsed = server.sidebar_collapsed;
    this.privacy = typeof server.privacy_mode === 'boolean' ? server.privacy_mode : privacyDefault || this.privacy;
    this.#updatedAt = serverAt;
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
      theme: this.theme, accent: this.accent, density: this.density, privacy_mode: this.privacy,
      sidebar_collapsed: this.sidebarCollapsed, updated_at: this.#updatedAt,
    } satisfies Stored));
  }

  #save() {
    if (this.#saveTimer) clearTimeout(this.#saveTimer);
    this.#saveTimer = setTimeout(() => {
      api.put('/account/preferences', {
        theme: this.theme, accent: this.accent, density: this.density,
        privacy_mode: this.privacy, sidebar_collapsed: this.sidebarCollapsed, updated_at: this.#updatedAt,
      }).catch(() => { /* a preference that did not save is not worth an error */ });
    }, 500);
  }

  set(changes: Partial<{ theme: Theme; accent: Accent; density: Density; privacy: boolean; sidebarCollapsed: boolean }>,
      persist = true) {
    if (changes.theme) this.theme = changes.theme;
    if (changes.accent) this.accent = changes.accent;
    if (changes.density) this.density = changes.density;
    if (changes.privacy !== undefined) this.privacy = changes.privacy;
    if (changes.sidebarCollapsed !== undefined) this.sidebarCollapsed = changes.sidebarCollapsed;
    if (persist) this.#updatedAt = Date.now();
    this.apply();
    if (persist) this.#save();
  }
}

export const prefs = new Prefs();
