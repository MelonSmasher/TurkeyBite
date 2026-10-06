// How privacy mode masks names in text, queries and documents. Pure, so it
// can be tested; privacy.ts applies it when privacy mode is on.

import { alias } from './alias';
import { quoteValue, tokenize } from './components/tbql';

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

/** Which tokens of a query could name someone: values of identity fields,
 *  user:x and each value in user:(x OR y), field names in any case as TBQL
 *  takes them; and free text, which TBQL matches against user and host names
 *  among others. A value of any other field, domain:x, is left as it is. */
export function identityValueTokens(query: string): Set<number> {
  const out = new Set<number>();
  let field: string | null = null;
  // Each open group: of an identity field's values, another field's, or free text
  const groups: ('identity' | 'other' | 'free')[] = [];
  for (const t of tokenize(query)) {
    const inside = groups.at(-1) ?? 'free';
    if (t.kind === 'paren') {
      if (t.text === '(') {
        groups.push(field ? (IDENTITY_NAMES.has(field) ? 'identity' : 'other') : inside);
      } else {
        groups.pop();
      }
      field = null;
    } else if (t.kind === 'field') {
      field = t.text.slice(0, -1).toLowerCase();
    } else if (t.kind === 'value' || t.kind === 'quoted' || t.kind === 'text') {
      const fielded = field !== null && t.kind !== 'text';
      const named = fielded ? IDENTITY_NAMES.has(field!) : inside !== 'other';
      // A bare * is "any", not a name
      if (named && t.text !== '*') out.add(t.start);
      field = null;
    } else if (t.kind !== 'space' && t.kind !== 'compare') {
      field = null;
    }
  }
  return out;
}

/** The names a query holds: what privacy mode aliases in it. */
export function namesInQuery(query: string): string[] {
  const marked = identityValueTokens(query);
  return tokenize(query).filter((t) => marked.has(t.start)).map((t) => (t.kind === 'quoted' ? unquote(t.text) : t.text));
}

/** A TBQL query with the values of identity fields replaced by aliases. */
export function maskQueryValues(query: string): string {
  const masked = identityValueTokens(query);
  return tokenize(query).map((t) => (masked.has(t.start) ? aliasToken(t.kind, t.text) : t.text)).join('');
}

function unquote(text: string): string {
  return text.replace(/^"/, '').replace(/"$/, '').replace(/\\(["\\])/g, '$1');
}

/** A query as the query bar shows it in privacy mode, every name in it
 *  aliased, with each alias's real value noted in `known`, so that what is
 *  typed around them can be turned back into the real query. */
export function maskForEditing(query: string, known: Map<string, string>): string {
  const masked = identityValueTokens(query);
  return tokenize(query).map((t) => {
    if (!masked.has(t.start)) return t.text;
    const real = t.kind === 'quoted' ? unquote(t.text) : t.text;
    const shown = alias(real);
    known.set(shown, real);
    return t.kind === 'quoted' ? `"${shown}"` : shown;
  }).join('');
}

/** The real query behind what the query bar shows: each alias it knows put
 *  back as the value it stands for, quoted as that needs. */
export function unmaskForSearch(shown: string, known: Map<string, string>): string {
  if (!known.size) return shown;
  return tokenize(shown).map((t) => {
    if (t.kind !== 'value' && t.kind !== 'text' && t.kind !== 'quoted') return t.text;
    const real = known.get(t.kind === 'quoted' ? unquote(t.text) : t.text);
    if (real === undefined) return t.text;
    return t.kind === 'quoted' ? `"${real.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"` : quoteValue(real);
  }).join('');
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
