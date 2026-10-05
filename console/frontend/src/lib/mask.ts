// How privacy mode masks names in text, queries and documents. Pure, so it
// can be tested; privacy.ts applies it when privacy mode is on.

import { alias } from './alias';
import { tokenize } from './components/tbql';

export const IDENTITY_FIELDS = new Set(['bite.client', 'bite.client_ips', 'bite.client_user', 'bite.client_hostname',
  'bite.client_hostname_short', 'bite.client_hosts', 'bite.client_hosts_short', 'bite.ptr', 'entity']);

// What a query may call them, as well as their full names
export const IDENTITY_NAMES = new Set([...IDENTITY_FIELDS, 'client', 'ip', 'src', 'user', 'username', 'hostname',
  'host', 'ptrs', 'ptr']);

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** `text` with each of `values` replaced by its alias where it stands on its
 *  own, so "ava" leaves "Java" alone. */
export function maskNames(text: string, values: (string | null | undefined)[]): string {
  let out = text;
  for (const value of values) {
    if (!value || value.length < 2) continue;
    out = out.replace(new RegExp(`(?<![\\w.-])${escapeRegExp(value)}(?![\\w-])`, 'g'), alias(value));
  }
  return out;
}

/** A TBQL query with the values of identity fields replaced by aliases. */
export function maskQueryValues(query: string): string {
  let field: string | null = null;
  return tokenize(query).map((t) => {
    if (t.kind === 'field') {
      field = t.text.slice(0, -1);
      return t.text;
    }
    if ((t.kind === 'value' || t.kind === 'quoted') && field && IDENTITY_NAMES.has(field)) {
      return t.kind === 'quoted' ? `"${alias(t.text.replace(/^"|"$/g, ''))}"` : alias(t.text);
    }
    if (t.kind !== 'space' && t.kind !== 'compare' && t.kind !== 'paren') field = null;
    return t.text;
  }).join('');
}

/** An event document with its identities aliased and everything outside
 *  `bite`, such as the raw packet, withheld rather than half masked. */
export function maskDocument<T>(source: T): T {
  if (!source || typeof source !== 'object') return source;
  const copy = structuredClone(source) as Record<string, any>;
  const bite = copy.bite as Record<string, unknown> | undefined;
  if (bite && typeof bite === 'object') {
    for (const name of Object.keys(bite)) {
      if (!IDENTITY_FIELDS.has(`bite.${name}`)) continue;
      const value = bite[name];
      bite[name] = Array.isArray(value) ? value.map((v) => alias(String(v))) : value == null ? value : alias(String(value));
    }
  }
  for (const key of Object.keys(copy)) {
    if (key !== 'bite' && key !== '@timestamp') copy[key] = '[hidden in privacy mode]';
  }
  return copy as T;
}

/** Every string in a JSON value with `values` masked. */
export function maskStrings<T>(value: T, values: (string | null | undefined)[]): T {
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') return maskNames(v, values);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
    return v;
  };
  return walk(value) as T;
}
