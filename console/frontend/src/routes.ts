// Every page, loaded on demand so the first paint ships only what it needs.

import type { RouteDef } from './lib/router.svelte';

export const routes: RouteDef[] = [
  { pattern: '/login', title: 'Sign in', public: true, component: () => import('./pages/Login.svelte') },
  { pattern: '/', title: 'Overview', permission: 'events:read', component: () => import('./pages/Overview.svelte') },
  { pattern: '/explore', title: 'Explore', permission: 'events:read', component: () => import('./pages/Explore.svelte') },
  { pattern: '/analytics', title: 'Analytics', permission: 'events:read', component: () => import('./pages/Analytics.svelte') },
  { pattern: '/entities', title: 'Entities', permission: 'events:read', component: () => import('./pages/Entities.svelte') },
  { pattern: '/entities/:field/:value', title: 'Entity', permission: 'events:read', component: () => import('./pages/EntityProfile.svelte') },
  { pattern: '/domains/:domain', title: 'Domain', permission: 'events:read', component: () => import('./pages/DomainProfile.svelte') },
  { pattern: '/findings', title: 'Findings', permission: 'findings:read', component: () => import('./pages/Findings.svelte') },
  { pattern: '/findings/:id', title: 'Finding', permission: 'findings:read', component: () => import('./pages/FindingDetail.svelte') },
  { pattern: '/rules', title: 'Rules', permission: 'rules:read', component: () => import('./pages/Rules.svelte') },
  { pattern: '/rules/new', title: 'New rule', permission: 'rules:write', component: () => import('./pages/RuleEditor.svelte') },
  { pattern: '/rules/:id', title: 'Rule', permission: 'rules:read', component: () => import('./pages/RuleEditor.svelte') },
  { pattern: '/dashboards', title: 'Dashboards', permission: 'dashboards:read', component: () => import('./pages/Dashboards.svelte') },
  { pattern: '/dashboards/:id', title: 'Dashboard', permission: 'dashboards:read', component: () => import('./pages/DashboardView.svelte') },
  { pattern: '/trends', title: 'Trends', permission: 'events:read', component: () => import('./pages/Trends.svelte') },
  { pattern: '/integrations/webhooks', title: 'Webhooks', permission: 'webhooks:read', component: () => import('./pages/Webhooks.svelte') },
  { pattern: '/integrations/api-keys', title: 'API keys', permission: 'apikeys:self', component: () => import('./pages/ApiKeys.svelte') },
  { pattern: '/integrations/api', title: 'API reference', permission: 'events:read', component: () => import('./pages/ApiReference.svelte') },
  { pattern: '/admin/users', title: 'Users', permission: 'users:admin', component: () => import('./pages/Users.svelte') },
  { pattern: '/admin/auth', title: 'Authentication', permission: 'settings:admin', component: () => import('./pages/Authentication.svelte') },
  { pattern: '/admin/audit', title: 'Audit log', permission: 'audit:read', component: () => import('./pages/Audit.svelte') },
  { pattern: '/admin/system', title: 'System', permission: 'settings:admin', component: () => import('./pages/System.svelte') },
  { pattern: '/account', title: 'Your account', component: () => import('./pages/Account.svelte') },
];
