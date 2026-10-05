// Privacy mode: people and machines are shown as stable aliases, for a
// screen being shared or a demo. The alias is derived from the value, so one
// person is the same alias everywhere and across reloads; it is not a secret
// and does not pretend to be, just a way not to put names on a projector.
//
// Names turn up in more than identity columns: in finding titles and
// summaries ("…contacted by noah.kim"), in queries (user:noah.kim), and in
// raw event documents. Each has a helper here, so every place that shows one
// masks it the same way.

import { alias } from './alias';
import { IDENTITY_FIELDS, IDENTITY_NAMES, maskDocument, maskNames, maskQueryValues, maskStrings } from './mask';
import { prefs } from './stores/prefs.svelte';

export { alias };

export function isIdentity(field: string | null | undefined): boolean {
  return !!field && IDENTITY_FIELDS.has(field);
}

/** Whether a query's field name, full or short, names a person or machine. */
export function isIdentityName(name: string | null | undefined): boolean {
  return !!name && IDENTITY_NAMES.has(name);
}

/** The value to show for an identity, masked when privacy mode is on. */
export function who(value: unknown, field?: string | null): string {
  if (value === null || value === undefined) return '–';
  const text = String(value);
  if (!prefs.privacy) return text;
  if (field && !isIdentity(field)) return text;
  return alias(text);
}

/** Free text with the named identities in it masked, in privacy mode. */
export function maskText(text: string | null | undefined, ...values: (string | null | undefined)[]): string {
  if (!text) return text ?? '';
  return prefs.privacy ? maskNames(text, values) : text;
}

/** A finding's title, summary or query, without the name of who it is about. */
export function findingText(text: string | null | undefined, finding: { entity?: string | null }): string {
  return maskText(text, finding.entity);
}

/** A TBQL query with the values of identity fields masked, in privacy mode:
 *  user:noah.kim reads user:gentle-plover-95. */
export function maskQuery(query: string | null | undefined): string {
  if (!query) return query ?? '';
  return prefs.privacy ? maskQueryValues(query) : query;
}

/** An event's document with every identity in it masked, for showing raw. */
export function maskSource<T>(source: T): T {
  return prefs.privacy ? maskDocument(source) : source;
}

/** A copy of any JSON value with `names` masked in every string in it, for
 *  showing a webhook's payload. */
export function maskDeep<T>(value: T, ...names: (string | null | undefined)[]): T {
  return prefs.privacy && names.some(Boolean) ? maskStrings(value, names) : value;
}
