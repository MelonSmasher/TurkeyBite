// Who is signed in, and what they may do.
//
// Every tab of the console in this browser shares one session cookie, so a
// sign-out or a sign-in as someone else in one tab changes who the others
// act as. They are told at once, and a tab coming back into view checks too:
// one left showing another person's view reloads rather than carry on as
// them, with their preferences, under the new person's cookie.

import { api } from '../api';
import type { Me } from '../types';
import { clearPersonal, ownPersonal } from './personal';
import { prefs } from './prefs.svelte';
import { timeRange } from './timerange.svelte';

// How often a tab coming back into view asks who is signed in, at most
const RECHECK_MS = 30_000;

class Session {
  me = $state<Me | null>(null);
  loading = $state(true);
  #channel = typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel('tbc-session');
  #checked = 0;

  constructor() {
    this.#channel?.addEventListener('message', (event) => {
      const { kind, user } = event.data ?? {};
      if (kind === 'signed-out' && this.me) this.#elsewhere();
      if (kind === 'signed-in' && this.me && user !== this.me.user.id) this.#elsewhere();
    });
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible' && this.me) this.#recheck();
    });
  }

  get user() {
    return this.me?.user ?? null;
  }

  can(permission: string): boolean {
    return !!this.me?.permissions.includes(permission);
  }

  async load(): Promise<Me | null> {
    this.loading = true;
    try {
      this.me = await api.get<Me>('/auth/me');
      ownPersonal(this.me.user.id);
      prefs.adopt(this.me.preferences, this.me.privacy_mode_default, this.me.user.id);
      timeRange.useDefault(this.me.default_range);
      this.#checked = Date.now();
    } catch (e) {
      this.me = null;
      // Signed out, or the session ran out: what was kept for whoever it was goes
      if ((e as { status?: number }).status === 401) clearPersonal();
    } finally {
      this.loading = false;
    }
    return this.me;
  }

  /** Tells the other tabs who is signed in now, after signing in. */
  announce(user: string) {
    this.#channel?.postMessage({ kind: 'signed-in', user });
  }

  async logout() {
    try {
      await api.post('/auth/logout');
    } finally {
      this.#channel?.postMessage({ kind: 'signed-out' });
      this.me = null;
      prefs.forget();
      clearPersonal();
      location.assign('/login');
    }
  }

  /** Someone else is signed in here now, or no one: this tab starts again. */
  #elsewhere() {
    this.me = null;
    prefs.forget();
    location.reload();
  }

  async #recheck() {
    if (Date.now() - this.#checked < RECHECK_MS) return;
    this.#checked = Date.now();
    try {
      const now = await api.get<Me>('/auth/me');
      if (now.user.id !== this.me?.user.id) this.#elsewhere();
    } catch {
      // Signed out: the next request finds out and sends this tab to sign in
    }
  }
}

export const session = new Session();
