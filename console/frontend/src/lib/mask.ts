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
 *  own, so "ava" leaves "Java" alone. Longest first, so one name inside
 *  another is not half replaced. */
export function maskNames(text: string, values: (string | null | undefined)[]): string {
  let out = text;
  const names = [...new Set(values.filter((v): v is string => !!v && v.length >= 2))].sort((a, b) => b.length - a.length);
  for (const value of names) {
    out = out.replace(new RegExp(`(?<![\\w.-])${escapeRegExp(value)}(?![\\w-])`, 'g'), alias(value));
  }
  return out;
}

/** `text` with whatever starts with each of `prefixes` aliased, up to the next
 *  space: for a name that was stored cut short, whose whole the text has. */
export function maskPrefixes(text: string, prefixes: string[]): string {
  let out = text;
  for (const prefix of prefixes) {
    if (prefix.length < 2) continue;
    out = out.replace(new RegExp(`(?<![\\w.-])${escapeRegExp(prefix)}\\S*`, 'g'), (m) => alias(m));
  }
  return out;
}

function aliasToken(kind: string, text: string): string {
  return kind === 'quoted' ? `"${alias(text.replace(/^"|"$/g, ''))}"` : alias(text);
}

/** Which tokens of a query are values of identity fields: user:x, and each
 *  value in user:(x OR y). Field names in any case, as TBQL takes them. */
export function identityValueTokens(query: string): Set<number> {
  const out = new Set<number>();
  let field: string | null = null;
  let depth = 0;
  for (const t of tokenize(query)) {
    if (depth > 0) {
      if (t.kind === 'paren') depth += t.text === '(' ? 1 : -1;
      else if (t.kind === 'value' || t.kind === 'quoted' || t.kind === 'text') out.add(t.start);
      continue;
    }
    if (t.kind === 'field') {
      field = t.text.slice(0, -1).toLowerCase();
    } else if (t.kind === 'paren' && t.text === '(' && field && IDENTITY_NAMES.has(field)) {
      depth = 1;
      field = null;
    } else if ((t.kind === 'value' || t.kind === 'quoted') && field && IDENTITY_NAMES.has(field)) {
      out.add(t.start);
    } else if (t.kind !== 'space' && t.kind !== 'compare') {
      field = null;
    }
  }
  return out;
}

/** A TBQL query with the values of identity fields replaced by aliases. */
export function maskQueryValues(query: string): string {
  const masked = identityValueTokens(query);
  return tokenize(query).map((t) => (masked.has(t.start) ? aliasToken(t.kind, t.text) : t.text)).join('');
}

/** The token as privacy mode shows it, for the query bar's colouring. */
export function maskToken(t: { kind: string; text: string }): string {
  return aliasToken(t.kind, t.text);
}

/** An event document with its identities aliased and everything outside
 *  `bite`, such as the raw packet, withheld rather than half masked. */
export function maskDocument<T>(source: T): T {
  if (!source || typeof source !== 'object') return source;
  // A JSON round trip rather than structuredClone, which a Svelte state
  // proxy cannot pass through
  const copy = JSON.parse(JSON.stringify(source)) as Record<string, any>;
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
