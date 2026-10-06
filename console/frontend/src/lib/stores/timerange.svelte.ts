// The time range every page shares. It lives in the URL (?from=&to=), so a
// link to a view brings its range with it, and falls back to the last range
// used, so moving between pages keeps the frame, and before any to the range
// the organisation opens pages on.

import { router } from '../router.svelte';
import { resolveTime } from '../time';

export interface RangePreset {
  id: string;
  label: string;
  short: string;
  from: string;
  to: string;
}

export const PRESETS: RangePreset[] = [
  { id: '15m', label: 'Last 15 minutes', short: '15m', from: 'now-15m', to: 'now' },
  { id: '1h', label: 'Last hour', short: '1h', from: 'now-1h', to: 'now' },
  { id: '4h', label: 'Last 4 hours', short: '4h', from: 'now-4h', to: 'now' },
  { id: '24h', label: 'Last 24 hours', short: '24h', from: 'now-24h', to: 'now' },
  { id: 'today', label: 'Today so far', short: 'Today', from: 'now/d', to: 'now' },
  { id: '7d', label: 'Last 7 days', short: '7d', from: 'now-7d', to: 'now' },
  { id: '14d', label: 'Last 14 days', short: '14d', from: 'now-14d', to: 'now' },
  { id: '30d', label: 'Last 30 days', short: '30d', from: 'now-30d', to: 'now' },
];

const KEY = 'tbc.range';

class TimeRangeStore {
  #chosen = this.#load();
  #fallback = $state<{ from: string; to: string }>(this.#chosen ?? { from: 'now-24h', to: 'now' });

  #load(): { from: string; to: string } | null {
    try {
      const stored = JSON.parse(sessionStorage.getItem(KEY) || 'null');
      if (stored?.from && stored?.to) return stored;
    } catch {
      /* ignore */
    }
    return null;
  }

  /** The organisation's default, for a tab where no range was chosen yet. */
  useDefault(from: string) {
    if (!this.#chosen && PRESETS.some((p) => p.from === from)) this.#fallback = { from, to: 'now' };
  }

  get from(): string {
    return router.query.get('from') || this.#fallback.from;
  }

  get to(): string {
    return router.query.get('to') || this.#fallback.to;
  }

  get preset(): RangePreset | undefined {
    return PRESETS.find((p) => p.from === this.from && p.to === this.to);
  }

  get label(): string {
    const preset = this.preset;
    if (preset) return preset.label;
    const fmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    const a = new Date(this.from);
    const b = this.to === 'now' ? null : new Date(this.to);
    if (Number.isNaN(a.getTime())) return `${this.from} → ${this.to}`;
    return `${fmt.format(a)} → ${b && !Number.isNaN(b.getTime()) ? fmt.format(b) : 'now'}`;
  }

  /** The window in milliseconds, resolved now: for charts and bucket maths. */
  resolve(): { start: number; end: number } {
    return { start: resolveTime(this.from), end: resolveTime(this.to) };
  }

  set(from: string, to: string) {
    this.#chosen = { from, to };
    this.#fallback = { from, to };
    sessionStorage.setItem(KEY, JSON.stringify({ from, to }));
    router.setQuery({ from, to }, { push: true });
  }

  /** Puts the shared range into the URL on a page that shows it. */
  sync() {
    if (!router.query.get('from')) router.setQuery({ from: this.from, to: this.to });
  }
}

export { resolveTime };
export const timeRange = new TimeRangeStore();
