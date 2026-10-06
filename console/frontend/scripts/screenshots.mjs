// Renders screenshots of the running console with a real browser: the built
// app's own JavaScript and CSS, against the API and whatever data it holds.
//
//   BASE=http://127.0.0.1:8710 OUT=../docs/screenshots node scripts/screenshots.mjs
//
// Sign-in comes from USERNAME and PASSWORD, by default the demo's admin.

import { chromium } from "@playwright/test";
import { mkdirSync } from "node:fs";

const base = process.env.BASE ?? "http://127.0.0.1:8710";
const out = process.env.OUT ?? "../docs/screenshots";
const username = process.env.USERNAME_TB ?? "admin";
const password = process.env.PASSWORD_TB ?? "TurkeyBite-demo-2026!";
const only = process.env.ONLY ? process.env.ONLY.split(",") : null;
const scale = Number(process.env.SCALE ?? 1);
// eslint-disable-next-line security/detect-non-literal-fs-filename -- OUT is the developer's own choice
mkdirSync(out, { recursive: true });

const week = "from=now-7d&to=now";

// name, path, theme, options: { full, accent, privacy, act(page), height }
const shots = [
  ["login-light", "/login", "light", { anonymous: true }],
  ["login-dark", "/login", "dark", { anonymous: true, accent: "ocean" }],
  ["overview-light", "/", "light", { full: true }],
  ["overview-dark", "/", "dark", { full: true }],
  ["explore-light", `/explore?q=${encodeURIComponent("risk:threat OR risk:policy.anonymiser")}&${week}`, "light", {}],
  ["explore-event-dark", `/explore?q=${encodeURIComponent("risk:threat")}&${week}`, "dark", {
    act: async (page) => { await page.click("table.events tbody tr:nth-child(2)"); await page.waitForTimeout(900); } }],
  ["analytics-light", "/analytics", "light", {}],
  ["analytics-over-time-dark", `/analytics?${week}`, "dark", {
    act: async (page) => { await page.click("button.chip:has-text(\"Risk over time\")"); await page.waitForTimeout(1200); } }],
  ["entities-light", "/entities", "light", {}],
  ["entity-profile-dark", `/entities/bite.client_user/noah.kim?${week}`, "dark", { full: true }],
  ["entity-profile-privacy-light", `/entities/bite.client_user/noah.kim?${week}`, "light", { privacy: true }],
  ["domain-light", `/domains/minexmr-pool.net?${week}`, "light", { full: true }],
  ["findings-light", "/findings", "light", {}],
  ["findings-dark", "/findings", "dark", {}],
  ["finding-detail-light", null, "light", { full: true, findingFor: "noah.kim" }],
  ["rules-light", "/rules", "light", {}],
  ["rules-dark", "/rules", "dark", { full: true }],
  ["rule-editor-backtest-light", null, "light", { full: true, rule: "anonymiser",
    act: async (page) => {
      await page.click("button:has-text(\"3 days\")");
      await page.click("button:has-text(\"Run backtest\")");
      await page.waitForSelector(".bt-sum", { timeout: 30000 });
      await page.waitForTimeout(600);
    } }],
  ["dashboards-light", "/dashboards", "light", {}],
  ["dashboard-security-dark", null, "dark", { full: true, dashboard: "Security posture" }],
  ["dashboard-network-light", null, "light", { full: true, dashboard: "Network usage" }],
  ["trends-light", "/trends", "light", { full: true }],
  ["webhooks-light", "/integrations/webhooks", "light", {}],
  ["api-keys-light", "/integrations/api-keys", "light", {}],
  ["api-reference-dark", "/integrations/api", "dark", {}],
  ["users-light", "/admin/users", "light", {}],
  ["authentication-light", "/admin/auth", "light", { full: true }],
  ["audit-light", "/admin/audit", "light", {}],
  ["system-dark", "/admin/system", "dark", {}],
  ["account-light", "/account", "light", {}],
  ["command-palette-dark", "/", "dark", {
    act: async (page) => { await page.keyboard.press("Meta+k"); await page.keyboard.type("noah"); await page.waitForTimeout(700); } }],
  ["overview-ember-dark", "/", "dark", { accent: "ember" }],
];

const browser = await chromium.launch();

async function context(theme, opts) {
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: scale,
                                         colorScheme: theme === "dark" ? "dark" : "light", reducedMotion: "reduce" });
  await ctx.addInitScript(({ theme: t, accent, privacy }) => {
    localStorage.setItem("tbc.prefs", JSON.stringify({ theme: t, accent: accent ?? "iris", "privacy_mode": !!privacy }));
  }, { theme, accent: opts.accent, privacy: opts.privacy });
  return ctx;
}

async function signIn(page) {
  await page.goto(`${base}/login`);
  await page.fill("input[autocomplete=username]", username);
  await page.fill("input[type=password]", password);
  await page.click("button.submit");
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
}

async function api(page, path) {
  return page.evaluate(async (p) => (await fetch(`/api/v1${p}`)).json(), path);
}

// One signed-in context per theme and option set
const sessions = new Map();
function sessionKey(theme, opts) {
  return [theme, opts.accent ?? "", opts.privacy ? 1 : 0, opts.anonymous ? 1 : 0].join("|");
}

async function pageFor(theme, opts) {
  const key = sessionKey(theme, opts);
  if (!sessions.has(key)) {
    const ctx = await context(theme, opts);
    const page = await ctx.newPage();
    page.on("pageerror", (e) => console.error("pageerror:", String(e)));
    if (!opts.anonymous) await signIn(page);
    sessions.set(key, page);
  }
  return sessions.get(key);
}

// The account keeps its preferences on the server and every context signs in
// as the same person, so each shot sets its own just before it is taken
async function setPreferences(page, theme, opts) {
  const result = await page.evaluate(async (prefs) => {
    const csrf = decodeURIComponent(document.cookie.match(/(?:^|; )tbc_csrf=([^;]+)/)?.[1] ?? "");
    const response = await fetch("/api/v1/account/preferences", {
      method: "PUT", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(prefs) });
    return response.status;
  }, { theme, accent: opts.accent ?? "iris", "privacy_mode": !!opts.privacy, density: "comfortable",
       "sidebar_collapsed": false });
  if (result !== 200) throw new Error(`could not set preferences: HTTP ${result}`);
}

for (const [name, path, theme, opts] of shots) {
  if (only && !only.includes(name)) continue;
  const page = await pageFor(theme, opts);
  let target = path;
  if (opts.findingFor) {
    const list = await api(page, `/findings?entity=${opts.findingFor}&sort=severity&limit=1`);
    target = `/findings/${list.items[0].id}`;
  }
  if (opts.rule) {
    const rules = await api(page, "/rules");
    target = `/rules/${rules.find((r) => r.builtin_key === opts.rule).id}`;
  }
  if (opts.dashboard) {
    const boards = await api(page, "/dashboards");
    target = `/dashboards/${boards.find((d) => d.name === opts.dashboard).id}`;
  }
  await page.setViewportSize({ width: 1600, height: 1000 });
  if (!opts.anonymous) await setPreferences(page, theme, opts);
  await page.goto(`${base}${target}`);
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(1200);
  if (opts.act) await opts.act(page);
  if (opts.full) {
    // Grow the window to the page rather than stitching a full-page capture,
    // so the sidebar, which is the height of the window, runs the full length
    const height = await page.evaluate(() => Math.min(3200, document.documentElement.scrollHeight));
    await page.setViewportSize({ width: 1600, height });
    await page.waitForTimeout(500);
  }
  await page.screenshot({ path: `${out}/${name}.png` });
  console.log("captured", name);
}

await browser.close();
