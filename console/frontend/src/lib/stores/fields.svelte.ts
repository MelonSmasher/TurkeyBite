// The field catalogue, fetched once and shared by the query bar, the field
// sidebar, the pivot builder and the rule editor.

import { api } from '../api';
import type { FieldDef } from '../types';

class Fields {
  list = $state<FieldDef[]>([]);
  entityFields = $state<string[]>([]);
  #loading: Promise<void> | null = null;

  load(): Promise<void> {
    if (!this.#loading) {
      this.#loading = api.get<{ fields: FieldDef[]; entity: { fields: string[] } }>('/fields')
        .then((data) => {
          this.list = data.fields;
          this.entityFields = data.entity.fields;
        })
        .catch(() => {
          this.#loading = null;
        });
    }
    return this.#loading;
  }

  byName(name: string | null | undefined): FieldDef | undefined {
    if (!name) return undefined;
    const lower = name.toLowerCase();
    return this.list.find((f) => f.name.toLowerCase() === lower || f.aliases.includes(lower));
  }

  label(name: string | null | undefined): string {
    if (name === 'entity') return 'Entity';
    return this.byName(name)?.label ?? name ?? '';
  }

  /** The short name a query would use: bite.client_user -> user */
  alias(name: string): string {
    const f = this.byName(name);
    return f?.aliases[0] ?? name;
  }
}

export const fields = new Fields();
