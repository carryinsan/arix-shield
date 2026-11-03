#!/usr/bin/env node
/**
 * Optional Playwright smoke farm. It is deliberately read-only and restricted
 * to local/.test targets. It never follows a request to an unrelated origin.
 */
import { readFile } from 'node:fs/promises';

export function assertLabTarget(input) {
  let url;
  try { url = new URL(input); } catch { throw new Error('ARIX_BROWSER_BASE_URL must be an absolute URL'); }
  const localNames = new Set(['localhost', '127.0.0.1', '[::1]']);
  const allowed = localNames.has(url.hostname) || url.hostname.endsWith('.test');
  if (!allowed || !['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Browser farm target must be localhost, loopback, or a reserved .test hostname; public targets are refused.');
  }
  if (url.username || url.password) throw new Error('Credentials must not be embedded in the browser farm URL.');
  return url;
}

async function main() {
  const base = process.env.ARIX_BROWSER_BASE_URL;
  if (!base) throw new Error('Set ARIX_BROWSER_BASE_URL to a local or reserved .test staging target.');
  const baseUrl = assertLabTarget(base);
  const concurrency = Math.max(1, Math.min(40, Number(process.env.ARIX_BROWSER_WORKERS || 8)));
  const routeInput = process.env.ARIX_BROWSER_ROUTES || '/';
  const routes = routeInput.split(',').map((s) => s.trim()).filter(Boolean).slice(0, 20);
  for (const route of routes) {
    if (!route.startsWith('/') || route.startsWith('//')) throw new Error(`Only same-origin absolute paths are allowed: ${route}`);
    const resolved = new URL(route, baseUrl);
    if (resolved.origin !== baseUrl.origin) throw new Error(`Cross-origin route refused: ${route}`);
  }
  let storageState;
  if (process.env.ARIX_PLAYWRIGHT_STORAGE_STATE) storageState = JSON.parse(await readFile(process.env.ARIX_PLAYWRIGHT_STORAGE_STATE, 'utf8'));
  let chromium;
  try { ({ chromium } = await import('playwright')); }
  catch { throw new Error('Playwright is optional and was not found. Install it in the target test checkout to run this browser farm.'); }

  const browser = await chromium.launch({ headless: true });
  const results = [];
  const queue = Array.from({ length: concurrency }, async (_, worker) => {
    const context = await browser.newContext(storageState ? { storageState } : {});
    // Block cross-origin subresources and navigations. No mutations are issued.
    await context.route('**/*', async (route) => {
      const target = new URL(route.request().url());
      if (target.origin !== baseUrl.origin) return route.abort('blockedbyclient');
      return route.continue();
    });
    const page = await context.newPage();
    for (let repeat = 0; repeat < 2; repeat++) {
      for (const path of routes) {
        const url = new URL(path, baseUrl).href;
        try {
          const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15_000 });
          results.push({ worker, url, status: response?.status() ?? null, ok: Boolean(response && response.status() < 500) });
        } catch (error) { results.push({ worker, url, status: null, ok: false, error: String(error.message).slice(0, 180) }); }
      }
    }
    await context.close();
  });
  await Promise.all(queue);
  await browser.close();
  const report = { target: baseUrl.origin, concurrency, routeCount: routes.length, requests: results.length, passed: results.filter((r) => r.ok).length, failed: results.filter((r) => !r.ok).length, authenticatedStorageStateProvided: Boolean(storageState), results };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (report.failed) process.exitCode = 1;
}

if (import.meta.url === `file://${process.argv[1]}`) main().catch((error) => { console.error(error.message); process.exitCode = 2; });
