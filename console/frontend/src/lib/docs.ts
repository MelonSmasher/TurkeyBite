// The documentation site, served beside the app at /docs/ when the console
// has a docs container (TBCONSOLE_DOCS_URL). It is its own site, so its links
// open in a tab of their own, the same one each time.

import { BookOpen, GraduationCap, LayoutPanelTop, Tags } from '@lucide/svelte';
import type { Component } from 'svelte';

export const DOCS_WINDOW = 'tb-docs';

export interface HelpLink {
  href: string;
  label: string;
  icon: Component<any>;
}

export const HELP_LINKS: HelpLink[] = [
  { href: '/docs/tutorial/', label: 'Interactive tutorial', icon: GraduationCap },
  { href: '/docs/', label: 'Documentation', icon: BookOpen },
  { href: '/docs/console/', label: 'Using the console', icon: LayoutPanelTop },
  { href: '/docs/categories/', label: 'How sites are categorised', icon: Tags },
];

/** Opens a page of the documentation in its tab. */
export function openDocs(href: string): void {
  window.open(href, DOCS_WINDOW);
}
