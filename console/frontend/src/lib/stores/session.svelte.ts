// Who is signed in, and what they may do.

import { api } from '../api';
import type { Me } from '../types';
import { prefs } from './prefs.svelte';

class Session {
  me = $state<Me | null>(null);
  loading = $state(true);

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
      prefs.adopt(this.me.preferences, this.me.privacy_mode_default);
    } catch {
      this.me = null;
    } finally {
      this.loading = false;
    }
    return this.me;
  }

  async logout() {
    try {
      await api.post('/auth/logout');
    } finally {
      this.me = null;
      location.assign('/login');
    }
  }
}

export const session = new Session();
