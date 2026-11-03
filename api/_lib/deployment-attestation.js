import { readFile } from 'node:fs/promises';
import { verifyDatabaseRlsActive } from './db-guard.js';

function parseStatus(status) {
  const fields = Object.create(null);
  for (const line of status.split('\n')) {
    const match = /^([A-Za-z_]+):\s*(.*?)\s*$/.exec(line);
    if (match) fields[match[1]] = match[2];
  }
  return fields;
}

/**
 * Verify controls applied by the container/host operator. This function does not
 * activate seccomp, nftables, read-only mounts or PostgreSQL policy by itself.
 * Set ARIX_REQUIRE_HARDENED_RUNTIME=true to make a production caller fail closed.
 */
export async function verifyDeploymentHardening({ pgClient = null, tables = [], schema = 'public', required = process.env.ARIX_REQUIRE_HARDENED_RUNTIME === 'true' } = {}) {
  const production = process.env.NODE_ENV === 'production' || process.env.VERCEL_ENV === 'production';
  const issues = [];
  const observations = { platform: process.platform, uid: typeof process.getuid === 'function' ? process.getuid() : null, noNewPrivs: null, effectiveCapabilities: null, databaseRls: null };
  if ((production || required) && observations.uid === 0) issues.push('RUNTIME_IS_ROOT');
  if (process.platform === 'linux') {
    try {
      const status = parseStatus(await readFile('/proc/self/status', 'utf8'));
      observations.noNewPrivs = status.NoNewPrivs === '1';
      observations.effectiveCapabilities = status.CapEff || null;
      if (required && observations.noNewPrivs !== true) issues.push('LINUX_NO_NEW_PRIVS_NOT_ENABLED');
      if (required && (!observations.effectiveCapabilities || !/^0+$/.test(observations.effectiveCapabilities))) issues.push('LINUX_EFFECTIVE_CAPABILITIES_NOT_ZERO');
    } catch {
      if (required) issues.push('LINUX_PROC_STATUS_UNAVAILABLE');
    }
  } else if (required) issues.push('HARDENED_LINUX_RUNTIME_REQUIRED');

  if (tables.length) {
    if (!pgClient) issues.push('POSTGRES_RLS_EXECUTOR_UNAVAILABLE');
    else {
      try { observations.databaseRls = await verifyDatabaseRlsActive(pgClient, tables, { schema, throwOnFailure: false }); }
      catch (error) { observations.databaseRls = { ok: false, issues: [String(error?.message || error).slice(0, 180)] }; }
      if (!observations.databaseRls.ok) issues.push('POSTGRES_RLS_ATTESTATION_FAILED');
    }
  } else if (process.env.ARIX_REQUIRE_POSTGRES_RLS === 'true') {
    issues.push('POSTGRES_RLS_TABLE_LIST_OR_EXECUTOR_MISSING');
  }
  const report = Object.freeze({ ok: issues.length === 0, required: Boolean(required), production, observations, issues, checkedAt: new Date().toISOString() });
  if (required && !report.ok) throw Object.assign(new Error(`Deployment hardening attestation failed: ${issues.join(', ')}`), { code: 'ARIX_DEPLOYMENT_HARDENING_FAILED', report });
  return report;
}

export function parseRlsTableEnvironment(value = process.env.ARIX_POSTGRES_RLS_TABLES) {
  if (typeof value !== 'string' || !value.trim()) return [];
  const names = value.split(',').map((item) => item.trim()).filter(Boolean);
  if (names.length > 500 || names.some((name) => !/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(name))) throw new TypeError('ARIX_POSTGRES_RLS_TABLES must be a comma-separated list of unqualified PostgreSQL table names.');
  return [...new Set(names)];
}
