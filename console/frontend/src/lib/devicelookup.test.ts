import { describe, expect, it } from 'vitest';
import { lookupHost, lookupHref } from './devicelookup';

describe('device lookup links', () => {
  it('puts the address where {value} is, escaped', () => {
    expect(lookupHref('https://sac.example.edu/respond/device/?q={value}', '10.20.30.40'))
      .toBe('https://sac.example.edu/respond/device/?q=10.20.30.40');
    expect(lookupHref('https://sac.example.edu/respond/device/?q={value}', 'fe80::1%en0'))
      .toBe('https://sac.example.edu/respond/device/?q=fe80%3A%3A1%25en0');
    expect(lookupHost('https://sac.example.edu/respond/device/?q={value}')).toBe('sac.example.edu');
  });

  it('is no link without a lookup set, or a value', () => {
    expect(lookupHref('', '10.0.0.5')).toBeNull();
    expect(lookupHref(null, '10.0.0.5')).toBeNull();
    expect(lookupHref('https://sac.example.edu/', '10.0.0.5')).toBeNull();
    expect(lookupHref('https://sac.example.edu/?q={value}', '')).toBeNull();
  });
});
