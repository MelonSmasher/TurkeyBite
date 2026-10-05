// How a pivot names its keys, wherever it is drawn: the chart, its legend and
// its table view all go through here, so privacy mode masks them all alike.

import { taxon } from '../format';
import { who } from '../privacy';
import { fields } from '../stores/fields.svelte';

export function pivotLabel(key: string, field: string | null | undefined): string {
  const def = fields.byName(field ?? '');
  if (field === 'entity' || def?.identity) return who(key, def?.name ?? 'entity');
  if (def?.hierarchical) return taxon(key);
  if (key === 'browser.history') return 'Page visits';
  if (key === 'dns' && field === 'bite.type') return 'DNS lookups';
  if (field === 'bite.risk_severity') return `${key.charAt(0).toUpperCase()}${key.slice(1)} risk`;
  return key;
}
