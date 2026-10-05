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
