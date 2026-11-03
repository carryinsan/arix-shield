#!/usr/bin/env node
/** Local deterministic endurance run; no sockets or external systems. */
import { mkdir, writeFile } from 'node:fs/promises';
import { inspectRequest } from '../api/_lib/waf-engine.js';
import { performance } from 'node:perf_hooks';

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i < 0 ? fallback : Number(process.argv[i + 1]);
}
const durationMs = Math.max(1_000, Math.min(86_400_000, arg('--duration-ms', 60_000)));
const concurrency = Math.max(1, Math.min(64, arg('--concurrency', 8)));
const outDir = process.env.ARIX_LAB_OUT_DIR || 'results';
const endAt = performance.now() + durationMs;
const start = performance.now();
let total = 0;
let allowed = 0;
let rejected = 0;
let errors = 0;
let peakHeap = process.memoryUsage().heapUsed;
let peakRss = process.memoryUsage().rss;
const perSecond = [];
let tickStart = performance.now();
let tickCount = 0;

const benign = [
  { method: 'GET', url: '/health?lang=hi', headers: { accept: 'application/json' } },
  { method: 'POST', url: '/comment', headers: { 'content-type': 'text/plain' }, body: "O'Connor: SELECT is a SQL tutorial keyword, not a query." },
  { method: 'POST', url: '/profile', headers: { 'content-type': 'application/json' }, body: { displayName: 'Ari', locale: 'gu-IN', note: 'ગુજરાતી અને हिन्दी' } }
];
const adversarial = [
  { method: 'GET', url: '/search?q=%27%20OR%201%3D1%20--' },
  { method: 'POST', url: '/x', headers: { 'content-type': 'text/plain' }, body: '<script>alert(1)</script>' },
  { method: 'POST', url: '/x', headers: { 'content-type': 'application/json' }, body: { '$ne': null } },
  { method: 'POST', url: '/xml', headers: { 'content-type': 'application/xml' }, body: '<!DOCTYPE x [<!ENTITY y SYSTEM "file:///etc/passwd">]><x>&y;</x>' }
];

async function worker(id) {
  let local = 0;
  while (performance.now() < endAt) {
    const isAttack = ((local + id) % 5) === 0;
    const request = isAttack ? adversarial[(local + id) % adversarial.length] : benign[(local + id) % benign.length];
    try {
      const result = inspectRequest({ production: true, ...request });
      total++;
      tickCount++;
      if (result.allowed) allowed++; else rejected++;
      // Invariant: generated bad inputs are denied; generated benign inputs are not.
      if (isAttack === result.allowed) errors++;
    } catch { errors++; total++; tickCount++; }
    local++;
    if ((local & 255) === 0) {
      const usage = process.memoryUsage();
      peakHeap = Math.max(peakHeap, usage.heapUsed);
      peakRss = Math.max(peakRss, usage.rss);
      await new Promise((resolve) => setImmediate(resolve));
    }
    const now = performance.now();
    if (now - tickStart >= 1_000) {
      perSecond.push({ atSeconds: Number(((now - start) / 1000).toFixed(1)), requests: tickCount });
      tickStart = now; tickCount = 0;
    }
  }
}
await Promise.all(Array.from({ length: concurrency }, (_, i) => worker(i)));
const elapsedSeconds = (performance.now() - start) / 1000;
const report = {
  generatedAt: new Date().toISOString(), node: process.version, durationRequestedMs: durationMs,
  elapsedSeconds, concurrency, totalRequests: total, allowed, rejected, invariantErrors: errors,
  requestsPerSecond: total / elapsedSeconds,
  peakHeapMiB: peakHeap / 1024 / 1024, peakRssMiB: peakRss / 1024 / 1024,
  perSecond, scope: 'Local in-process loop; no real network, browser farm, external Redis, or database involved.'
};
await mkdir(outDir, { recursive: true });
await writeFile(`${outDir}/endurance-results.json`, `${JSON.stringify(report, null, 2)}\n`);
await writeFile(`${outDir}/endurance-report.md`, `# ArixShield local endurance results\n\n- Generated: ${report.generatedAt}\n- Requested duration: ${durationMs} ms\n- Actual duration: ${elapsedSeconds.toFixed(2)} s\n- Concurrent workers: ${concurrency}\n- Requests processed: ${total.toLocaleString()}\n- Invariant errors: **${errors}**\n- Throughput: ${report.requestsPerSecond.toFixed(0)} req/s\n- Peak heap: ${report.peakHeapMiB.toFixed(1)} MiB\n- Peak RSS: ${report.peakRssMiB.toFixed(1)} MiB\n\n${report.scope}\n`);
console.log(JSON.stringify(report, null, 2));
if (errors) process.exitCode = 1;
