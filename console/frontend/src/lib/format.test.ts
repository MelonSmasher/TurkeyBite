import { describe, expect, it } from 'vitest';
import { alias } from './alias';
import { compact, duration, signedPct, spanWords, taxon } from './format';
import { resolveTime } from './time';

describe('format', () => {
  it('compacts big numbers only', () => {
    expect(compact(9999)).toBe((9999).toLocaleString());
    expect(compact(12500)).toMatch(/12\.5\s?K/i);
  });

  it('signs percentages', () => {
    expect(signedPct(0.25)).toBe('+25%');
    expect(signedPct(-0.051)).toBe('-5.1%');
    expect(signedPct(null)).toBe('–');
  });

  it('names taxonomy paths in words', () => {
    expect(taxon('policy.anonymiser')).toBe('VPNs and proxies');
    expect(taxon('threat.something-new')).toBe('Something new');
  });

  it('describes durations', () => {
    expect(duration(90)).toBe('2 min');
    expect(duration(3 * 3600 + 15 * 60)).toBe('3h 15m');
    expect(spanWords(900)).toBe('15 minutes');
    expect(spanWords(86400)).toBe('1 day');
  });
});

describe('resolveTime', () => {
  const now = Date.UTC(2026, 9, 5, 12, 30);
  it('resolves relative times', () => {
    expect(resolveTime('now', now)).toBe(now);
    expect(resolveTime('now-24h', now)).toBe(now - 864e5);
    expect(resolveTime('now-15m', now)).toBe(now - 15 * 6e4);
  });

  it('passes absolute times through', () => {
    expect(resolveTime('2026-10-01T00:00:00Z', now)).toBe(Date.UTC(2026, 9, 1));
  });
});

describe('alias', () => {
  it('is stable and hides the value', () => {
    expect(alias('noah.kim')).toBe(alias('noah.kim'));
    expect(alias('noah.kim')).not.toContain('noah');
    expect(alias('noah.kim')).not.toBe(alias('ava.chen'));
  });
});
