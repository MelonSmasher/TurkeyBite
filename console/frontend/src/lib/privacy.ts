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
import { qs } from './api';
import { IDENTITY_FIELDS, IDENTITY_NAMES, maskDocument, maskNames, maskPrefixes, maskQueryValues, maskStrings } from './mask';
import { prefs } from './stores/prefs.svelte';
import { hide } from './urlsafe';

export { alias };

export function isIdentity(field: string | null | undefined): boolean {
  return !!field && IDENTITY_FIELDS.has(field);
}

/** A link to Explore with a query, the query hidden from the address bar in
 *  privacy mode. */
export function exploreLink(params: { q?: string | null; from?: string | null; to?: string | null }): string {
  const { q, ...rest } = params;
  return `/explore${qs(prefs.privacy && q ? { qe: hide(q), ...rest } : { q, ...rest })}`;
}

/** A path segment for a person or machine, hidden in privacy mode. */
export function entitySegment(value: string): string {
  return encodeURIComponent(prefs.privacy ? hide(value) : value);
}

/** Whether a query's field name, full or short, in any case, names a person or machine. */
export function isIdentityName(name: string | null | undefined): boolean {
  return !!name && IDENTITY_NAMES.has(name.toLowerCase());
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

interface Named {
  entity?: string | null;
  entity_field?: string | null;
  evidence?: { detail?: { field?: string; new_value?: unknown } | null } | Record<string, any>;
}

/** The people and machines a finding names: who it is about, when that is a
 *  person or machine and not, say, a domain, and the new value a first-seen
 *  rule found, when that is one. A name stored cut short is matched by what
 *  is left of it. */
export function findingNames(finding: Named): string[] {
  const names: string[] = [];
  if (finding.entity && isIdentity(finding.entity_field) && !finding.entity.endsWith('…')) names.push(finding.entity);
  const detail = (finding.evidence as Record<string, any> | undefined)?.detail;
  if (detail && isIdentity(detail.field) && detail.new_value != null) names.push(String(detail.new_value));
  return names;
}

/** A finding's title, summary or query, without the names in it. */
export function findingText(text: string | null | undefined, finding: Named): string {
  const out = maskText(text, ...findingNames(finding));
  const cut = finding.entity && isIdentity(finding.entity_field) && finding.entity.endsWith('…');
  return prefs.privacy && cut ? maskPrefixes(out, [finding.entity!.slice(0, -1)]) : out;
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
