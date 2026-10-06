// The navigation, shared by the sidebar and the command palette.

import {
  BookOpen, ChartLine, ChartNoAxesCombined, Gauge, KeyRound, LayoutDashboard, ScanSearch, ScrollText,
  Server, ShieldAlert, ShieldCheck, UserCog, Users, Webhook, Workflow,
} from '@lucide/svelte';
import type { Component } from 'svelte';

export interface NavItem {
  href: string;
  label: string;
  icon: Component<any>;
  permission?: string;
  keywords?: string;
  badge?: 'findings';
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV: NavGroup[] = [
  {
    label: 'Monitor',
    items: [
      { href: '/', label: 'Overview', icon: Gauge, permission: 'events:read', keywords: 'home dashboard summary' },
      { href: '/findings', label: 'Findings', icon: ShieldAlert, permission: 'findings:read', badge: 'findings',
        keywords: 'alerts incidents triage' },
      { href: '/dashboards', label: 'Dashboards', icon: LayoutDashboard, permission: 'dashboards:read' },
      { href: '/trends', label: 'Trends', icon: ChartLine, permission: 'events:read', keywords: 'long term history rollups' },
    ],
  },
  {
    label: 'Investigate',
    items: [
      { href: '/explore', label: 'Explore', icon: ScanSearch, permission: 'events:read', keywords: 'search discover events logs' },
      { href: '/analytics', label: 'Analytics', icon: ChartNoAxesCombined, permission: 'events:read', keywords: 'pivot aggregate visualize' },
      { href: '/entities', label: 'Entities', icon: Users, permission: 'events:read', keywords: 'people users hosts clients devices' },
    ],
  },
  {
    label: 'Detect',
    items: [
      { href: '/rules', label: 'Rules', icon: Workflow, permission: 'rules:read', keywords: 'detections analysis engine' },
    ],
  },
  {
    label: 'Integrate',
    items: [
      { href: '/integrations/webhooks', label: 'Webhooks', icon: Webhook, permission: 'webhooks:read', keywords: 'alerts slack teams' },
      { href: '/integrations/api-keys', label: 'API keys', icon: KeyRound, permission: 'apikeys:self', keywords: 'tokens integration' },
      { href: '/integrations/api', label: 'API reference', icon: BookOpen, permission: 'events:read', keywords: 'docs openapi' },
    ],
  },
  {
    label: 'Admin',
    items: [
      { href: '/admin/users', label: 'Users', icon: UserCog, permission: 'users:admin', keywords: 'accounts service' },
      { href: '/admin/auth', label: 'Authentication', icon: ShieldCheck, permission: 'settings:admin', keywords: 'ldap directory mfa' },
      { href: '/admin/audit', label: 'Audit log', icon: ScrollText, permission: 'audit:read', keywords: 'history accountability' },
      { href: '/admin/system', label: 'System', icon: Server, permission: 'settings:admin', keywords: 'status opensearch health' },
    ],
  },
];
