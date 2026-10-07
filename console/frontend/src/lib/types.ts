// Shapes the API returns, as the app uses them.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type FindingStatus = 'new' | 'acknowledged' | 'in_progress' | 'resolved' | 'false_positive';

export interface UserRef {
  id: string;
  username: string;
  display_name: string;
  role: 'viewer' | 'analyst' | 'admin';
  source: 'local' | 'ldap' | 'service';
}

export interface User extends UserRef {
  email?: string | null;
  disabled?: boolean;
  mfa_enabled?: boolean;
  locked?: boolean;
  locked_until?: string | null;
  last_login_at?: string | null;
  created_at?: string | null;
  ldap_dn?: string | null;
  failed_logins?: number;
  api_keys?: number;
  sessions?: number;
}

export interface Me {
  user: User;
  via: string;
  permissions: string[];
  preferences: Record<string, unknown>;
  org_name: string;
  privacy_mode_default: boolean;
  default_range: string;
  device_lookup_url: string;
  mfa_required: boolean;
  version: string;
  api_docs: boolean;
}

export interface Bucket {
  key: string;
  count: number;
}

export interface Finding {
  id: string;
  number: number;
  rule_id: string | null;
  rule_name: string;
  rule_type: string;
  category: string;
  severity: Severity;
  status: FindingStatus;
  title: string;
  summary: string;
  entity_field: string | null;
  entity: string | null;
  first_seen: string;
  last_seen: string;
  event_count: number;
  occurrences: number;
  evidence: {
    query?: string;
    from?: string;
    to?: string;
    count?: number;
    value?: number;
    top_domains?: Bucket[];
    top_categories?: Bucket[];
    detail?: Record<string, unknown>;
    first_window?: string;
  };
  tags: string[];
  assignee: UserRef | null;
  resolved_at: string | null;
  snoozed_until: string | null;
  created_at: string;
  updated_at: string;
}

export interface Rule {
  id: string;
  builtin_key: string | null;
  builtin: boolean;
  builtin_version: number | null;
  modified: boolean;
  update_available: boolean;
  name: string;
  description: string;
  category: string;
  type: string;
  query: string;
  params: Record<string, number | string>;
  group_by: string[];
  severity: Severity;
  enabled: boolean;
  interval_seconds: number;
  window_seconds: number;
  dedup_seconds: number;
  schedule: { days: number[]; start: string; end: string; timezone: string } | null;
  exceptions: { id?: string; query: string; note?: string; created_by?: string; created_at?: string;
    expires_at?: string | null; finding?: string }[];
  webhook_ids: string[];
  tags: string[];
  title_template: string;
  last_run_at: string | null;
  next_run_at: string | null;
  last_status: string | null;
  last_error: string | null;
  last_duration_ms: number | null;
  last_hits: number | null;
  consecutive_failures: number;
  open_findings?: number;
  total_findings?: number;
  findings_14d?: number[];
  default?: Record<string, unknown>;
}

export interface FieldDef {
  name: string;
  label: string;
  type: string;
  group: string;
  description: string;
  aliases: string[];
  aggregatable: boolean;
  hierarchical: boolean;
  identity: boolean;
  columns_default: boolean;
}

export interface Hit {
  id: string;
  index: string;
  source: Record<string, any>;
}

export interface Webhook {
  id: string;
  name: string;
  url: string;
  format: string;
  events: string[];
  all_findings: boolean;
  min_severity: Severity;
  redact_entities: boolean;
  enabled: boolean;
  has_headers: boolean;
  header_names?: string[];
  last_status: string | null;
  last_delivery_at: string | null;
  failure_streak: number;
  last_24h?: Record<string, number>;
  secret?: string;
}

export interface Delivery {
  id: string;
  webhook_id: string;
  event: string;
  finding_id: string | null;
  status: 'pending' | 'succeeded' | 'failed' | 'dead';
  attempts: number;
  entity?: string | null;
  names?: string[];
  next_attempt_at: string | null;
  last_status_code: number | null;
  last_error: string | null;
  duration_ms: number | null;
  created_at: string;
  delivered_at: string | null;
  title?: string | null;
  payload?: unknown;
  response_snippet?: string | null;
  rendered?: unknown;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  display: string;
  scopes: string[];
  state: 'active' | 'revoked' | 'expired';
  owner: UserRef;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  last_used_ip: string | null;
  revoked_at: string | null;
  key?: string;
}

export interface Widget {
  id: string;
  title: string;
  type: 'pivot' | 'findings' | 'stat' | 'note';
  span: 3 | 4 | 6 | 8 | 12;
  height?: 'sm' | 'md' | 'lg';
  viz?: string;
  pivot?: PivotSpec;
  findings?: { status?: string; severity?: string[]; limit?: number; count_only?: boolean };
  note?: string;
}

export interface PivotSpec {
  query?: string;
  metric?: 'count' | 'unique';
  metric_field?: string | null;
  rows?: string | null;
  rows_size?: number;
  split?: string | null;
  split_size?: number;
  over_time?: boolean;
  interval?: string;
}

export interface Dashboard {
  id: string;
  name: string;
  description: string;
  icon: string;
  widgets: Widget[];
  time_range: { from?: string; to?: string };
  shared: boolean;
  builtin: boolean;
  owner: UserRef | null;
  mine: boolean;
}

export interface PivotResult {
  kind: 'series' | 'table';
  interval?: string;
  times?: string[];
  series?: { key: string; points: number[]; total: number }[];
  rows?: { key: string; field?: string | null; value: number; cells: Record<string, number> }[];
  columns?: string[];
  total: number;
}
