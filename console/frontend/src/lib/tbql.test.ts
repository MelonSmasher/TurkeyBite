import { describe, expect, it } from 'vitest';
import { context, tokenize } from './components/tbql';

describe('tokenize', () => {
  it('colours fields, operators, values and quotes', () => {
    const kinds = tokenize('risk:threat AND NOT user:"ava chen"').filter((t) => t.kind !== 'space').map((t) => t.kind);
    expect(kinds).toEqual(['field', 'value', 'op', 'op', 'field', 'quoted']);
  });

  it('keeps every character, so the overlay lines up with the input', () => {
    const text = '  (domain:*.tiktok.com OR -incidental:true) client:10.0.0.0/8';
    expect(tokenize(text).map((t) => t.text).join('')).toBe(text);
  });

  it('reads a leading minus as negation but a hyphen inside a word as the word', () => {
    expect(tokenize('-host:lab-12').map((t) => t.kind)).toEqual(['neg', 'field', 'value']);
  });

  it('understands comparisons', () => {
    expect(tokenize('@timestamp:>=now-1h').map((t) => t.kind)).toEqual(['field', 'compare', 'value']);
  });
});

describe('context', () => {
  it('knows a field name is being typed', () => {
    expect(context('risk:threat AND ca', 18)).toMatchObject({ kind: 'field', prefix: 'ca', start: 16 });
  });

  it('knows a value of a field is being typed', () => {
    expect(context('category:soc', 12)).toMatchObject({ kind: 'value', field: 'category', prefix: 'soc' });
  });

  it('knows a value inside a group', () => {
    expect(context('category:(porn OR gam', 21)).toMatchObject({ kind: 'value', field: 'category', prefix: 'gam' });
  });
});
