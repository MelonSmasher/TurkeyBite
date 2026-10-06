import { describe, expect, it } from 'vitest';
import { alias } from './alias';
import { maskDocument, maskNames, maskQueryValues, maskStrings } from './mask';

describe('privacy masking', () => {
  it('replaces a name where it stands on its own', () => {
    expect(maskNames('Threat domain contacted by noah.kim', ['noah.kim'])).toBe(`Threat domain contacted by ${alias('noah.kim')}`);
    expect(maskNames('ava uses Java, not lava', ['ava'])).toBe(`${alias('ava')} uses Java, not lava`);
    expect(maskNames('10.0.0.55 is not 10.0.0.5', ['10.0.0.5'])).toBe(`10.0.0.55 is not ${alias('10.0.0.5')}`);
  });

  it('masks the values of identity fields in a query, and nothing else', () => {
    expect(maskQueryValues('(risk:threat) AND user:noah.kim')).toBe(`(risk:threat) AND user:${alias('noah.kim')}`);
    expect(maskQueryValues('host:"lab 12" OR domain:noah.kim')).toBe(`host:"${alias('lab 12')}" OR domain:noah.kim`);
    expect(maskQueryValues('bite.client:10.0.0.5')).toBe(`bite.client:${alias('10.0.0.5')}`);
  });

  it('aliases identities in a document and withholds the rest', () => {
    const doc = { '@timestamp': 't', bite: { client_user: 'ava', client_ips: ['10.0.0.5'], requested: ['x.example'] },
                  packet: { src: '10.0.0.5' } };
    const masked = maskDocument(doc);
    expect(masked.bite.client_user).toBe(alias('ava'));
    expect(masked.bite.client_ips).toEqual([alias('10.0.0.5')]);
    expect(masked.bite.requested).toEqual(['x.example']);
    expect(masked.packet).toBe('[hidden in privacy mode]');
    expect(doc.bite.client_user).toBe('ava');
  });

  it('masks a name in every string of a payload', () => {
    const payload = { finding: { title: 'Seen: ava', entity: 'ava', count: 3 }, tags: ['ava'] };
    expect(maskStrings(payload, ['ava'])).toEqual({ finding: { title: `Seen: ${alias('ava')}`, entity: alias('ava'), count: 3 },
                                                    tags: [alias('ava')] });
  });
});

describe('privacy masking, round two', () => {
  it('masks grouped values and field names in any case', async () => {
    const { maskQueryValues } = await import('./mask');
    expect(maskQueryValues('User:noah.kim')).toBe(`User:${alias('noah.kim')}`);
    expect(maskQueryValues('user:(noah.kim OR "ava chen") AND risk:threat'))
      .toBe(`user:(${alias('noah.kim')} OR "${alias('ava chen')}") AND risk:threat`);
  });

  it('masks a name stored cut short wherever its whole appears', async () => {
    const { maskPrefixes } = await import('./mask');
    expect(maskPrefixes('Seen by averyveryverylongname.example today', ['averyvery']))
      .toBe(`Seen by ${alias('averyveryverylongname.example')} today`);
  });

  it('copies a document that is a proxy', () => {
    const doc = new Proxy({ bite: { client_user: 'ava' } }, {});
    expect(maskDocument(doc).bite.client_user).toBe(alias('ava'));
  });
});

describe('addresses and queries', () => {
  it('hides text in an address and gets it back', async () => {
    const { hide, reveal } = await import('./urlsafe');
    for (const text of ['noah.kim', 'user:"ava chen" AND risk:threat', 'zoë', '']) {
      expect(reveal(hide(text))).toBe(text);
      expect(hide(text)).not.toContain('noah');
    }
    expect(reveal('plain')).toBe('plain');
  });

  it('quotes a value as the server would', async () => {
    const { quoteValue } = await import('./components/tbql');
    expect(quoteValue('lab-12')).toBe('lab-12');
    expect(quoteValue('*')).toBe('"*"');
    expect(quoteValue('ava chen')).toBe('"ava chen"');
    expect(quoteValue('OR')).toBe('"OR"');
  });
});

describe('privacy masking, round three', () => {
  it('masks free text, which TBQL matches against names, but not other fields or operators', () => {
    expect(maskQueryValues('noah.kim AND risk:threat')).toBe(`${alias('noah.kim')} AND risk:threat`);
    expect(maskQueryValues('"ava chen" OR NOT lab-12')).toBe(`"${alias('ava chen')}" OR NOT ${alias('lab-12')}`);
    expect(maskQueryValues('domain:(noah.kim OR x.example) AND *')).toBe('domain:(noah.kim OR x.example) AND *');
    expect(maskQueryValues('(noah.kim OR user:(ava))')).toBe(`(${alias('noah.kim')} OR user:(${alias('ava')}))`);
    expect(maskQueryValues('user:* AND @timestamp:>now-1h')).toBe('user:* AND @timestamp:>now-1h');
  });
});

describe('the query bar in privacy mode', () => {
  it('is edited as aliases, and searches for the real names', async () => {
    const { maskForEditing, unmaskForSearch } = await import('./mask');
    const known = new Map<string, string>();
    const shown = maskForEditing('user:noah.kim AND host:"lab 12"', known);
    expect(shown).toBe(`user:${alias('noah.kim')} AND host:"${alias('lab 12')}"`);
    expect(shown).not.toContain('noah');
    // Typed around: the aliases still stand for the names
    expect(unmaskForSearch(`${shown} AND risk:threat`, known)).toBe('user:noah.kim AND host:"lab 12" AND risk:threat');
    // An alias put in from a suggestion, for a name that needs quoting
    known.set(alias('ava chen'), 'ava chen');
    expect(unmaskForSearch(`user:${alias('ava chen')}`, known)).toBe('user:"ava chen"');
    // Typed in full, a name stays as typed
    expect(unmaskForSearch('user:liam', known)).toBe('user:liam');
  });
});
