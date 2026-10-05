// Shared chart helpers: colours by role, axis formatting.

import { timeFormat } from 'd3-time-format';

export interface Series {
  key: string;
  label: string;
  color: string;
  values: number[];
}

/** The categorical slots, in their validated order. Assigned in sequence, never cycled. */
export const SLOTS = ['var(--s1)', 'var(--s2)', 'var(--s3)', 'var(--s4)', 'var(--s5)', 'var(--s6)', 'var(--s7)', 'var(--s8)'];
export const OTHER = 'var(--deemph)';

/** Colour for the i-th series; past eight, everything folds into "Other". */
export function slot(i: number): string {
  return i < SLOTS.length ? SLOTS[i] : OTHER;
}

/** Severity is state, so it wears the fixed status steps, never a series slot. */
export const SEVERITY_COLOR: Record<string, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  info: 'var(--sev-info)',
  none: 'var(--deemph)',
};

/** TurkeyBite's risk severities are three, mapped onto the top three status steps. */
export const RISK_COLOR: Record<string, string> = {
  high: 'var(--sev-critical)',
  medium: 'var(--sev-high)',
  low: 'var(--sev-medium)',
  none: 'var(--deemph)',
};

const fmtMinute = timeFormat('%H:%M');
const fmtDay = timeFormat('%b %-d');
const fmtDayHour = timeFormat('%b %-d %H:%M');

/** An axis tick formatter that suits the span on screen. */
export function axisTime(spanMs: number): (d: Date) => string {
  if (spanMs <= 2 * 86400e3) {
    return (d: Date) => (d.getHours() === 0 && d.getMinutes() === 0 ? fmtDay(d) : fmtMinute(d));
  }
  return (d: Date) => fmtDay(d);
}

export function tooltipTime(start: number, intervalMs: number): string {
  const a = new Date(start);
  if (intervalMs >= 86400e3) return fmtDay(a);
  const b = new Date(start + intervalMs);
  const sameDay = a.toDateString() === b.toDateString();
  return `${fmtDayHour(a)} – ${sameDay ? fmtMinute(b) : fmtDayHour(b)}`;
}

/** A rect path with only its data end rounded: the top for a column. */
export function columnPath(x: number, y: number, w: number, h: number, r = 4): string {
  if (h <= 0 || w <= 0) return '';
  const rr = Math.min(r, w / 2, h);
  return `M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`;
}

/** A bar growing right from x, rounded at its right end only. */
export function barPath(x: number, y: number, w: number, h: number, r = 4): string {
  if (h <= 0 || w <= 0) return '';
  const rr = Math.min(r, h / 2, w);
  return `M${x},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h - rr}Q${x + w},${y + h} ${x + w - rr},${y + h}H${x}Z`;
}

export function intervalMsOf(name: string): number {
  const m = /^(\d+)([smhd])$/.exec(name);
  if (!m) return 3600e3;
  return Number(m[1]) * { s: 1e3, m: 6e4, h: 36e5, d: 864e5 }[m[2] as 's' | 'm' | 'h' | 'd'];
}
