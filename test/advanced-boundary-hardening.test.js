import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { runWithArixContext } from '../sdk/context.js';
import { protectPgPool } from '../sdk/database-guard.js';
import { installProcessEgressFirewall, processEgressFirewallStatus } from '../sdk/process-egress-firewall.js';
import { inspectLinuxHardeningStatus } from '../api/_lib/integrity.js';
import { createEdgeGatewayServer } from '../edge/gateway.mjs';
import { generateKeyPairSync } from 'node:crypto';

function fakePool() {
  const events = [];
  const client = {
    async query(text, values) { events.push({ text, values }); return { rows: [{ ok: true }] }; },
    release(error) { events.push({ release: true, error: Boolean(error) }); }
  };
  return { events, pool: { async connect() { events.push({ connect: true }); return client; }, async end() { events.push({ end: true }); } } };
}

test('PostgreSQL facade binds tenant/user context inside every transaction and keeps raw Pool methods private', async () => {
  const { pool, events } = fakePool();
  const protectedPool = protectPgPool(pool);
  assert.equal(typeof protectedPool.query, 'undefined');
  await assert.rejects(protectedPool.withTenantTransaction(async () => {}), { code: 'ARIX_UNSCOPED_DB_ACCESS' });
  await assert.rejects(
    runWithArixContext({ tenantId: 'tenant-a', userId: 'anonymous' }, () => protectedPool.withTenantTransaction(async () => {})),
    { code: 'ARIX_UNSCOPED_DB_ACCESS' }
  );
  const result = await runWithArixContext({ tenantId: 'tenant-a', userId: 'user-a' }, () => protectedPool.withTenantTransaction(async (db) => db.query('SELECT * FROM records WHERE record_id = $1', ['r1'])));
  assert.deepEqual(result.rows, [{ ok: true }]);
  assert.match(events[1].text, /^BEGIN ISOLATION LEVEL READ COMMITTED/);
  assert.match(events[2].text, /set_config\('arix\.tenant_id', \$1, true\)/);
  assert.deepEqual(events[2].values.slice(0, 2), ['tenant-a', 'user-a']);
  assert.equal(events.at(-2).text, 'COMMIT');
  assert.equal(events.at(-1).release, true);
  await runWithArixContext({ tenantId: 'tenant-a', userId: 'user-a' }, () => protectedPool.withTenantTransaction((db) => db.query('UPDATE records SET label = $1 WHERE id = $2', ['x', 'r1'])));
  assert.match(events.at(-3).text, /^UPDATE records SET/);
});

test('PostgreSQL scoped adapter blocks tenant-GUC mutation, control commands, and stacked statements', async () => {
  const { pool, events } = fakePool();
  const protectedPool = protectPgPool(pool);
  await runWithArixContext({ tenantId: 'tenant-a', userId: 'user-a' }, async () => {
    await assert.rejects(protectedPool.withTenantTransaction((db) => db.query("SELECT set_config('arix.tenant_id', 'tenant-b', true)")), { code: 'ARIX_SQL_CONTROL_BLOCKED' });
    await assert.rejects(protectedPool.withTenantTransaction((db) => db.query('SET LOCAL arix.tenant_id = tenant-b')), { code: 'ARIX_SQL_CONTROL_BLOCKED' });
    await assert.rejects(protectedPool.withTenantTransaction((db) => db.query('SELECT 1; DELETE FROM records')), { code: 'ARIX_SQL_REJECTED' });
  });
  assert.equal(events.filter((event) => event.text === 'ROLLBACK').length, 3);
  assert.equal(events.filter((event) => event.text === 'COMMIT').length, 0);
});

test('process egress guard replaces only the configured fetch target with the safe transport', async () => {
  const calls = [];
  const target = { fetch: async () => new Response('native') };
  const status = installProcessEgressFirewall({
    enabled: true,
    target,
    lockGlobalFetch: false,
    safeFetch: async (url, options) => {
      calls.push({ url, options });
      return new Response('ok', { status: 200 });
    }
  });
  assert.equal(status.installed, true);
  assert.deepEqual(processEgressFirewallStatus(target).intercepts, ['globalThis.fetch']);
  const response = await target.fetch('https://public.example/path', { method: 'POST', headers: { 'x-test': '1' }, body: 'bounded' });
  assert.equal(await response.text(), 'ok');
  assert.equal(calls[0].url, 'https://public.example/path');
  assert.equal(calls[0].options.body, 'bounded');
  assert.equal(calls[0].options.allowedPorts[0], 443);
  assert.equal(target.fetch.name, 'fetch');
});

test('Linux attestation distinguishes a hardened non-root process from missing controls', () => {
  const valid = inspectLinuxHardeningStatus({ platform: 'linux', uid: 65532, statusText: 'NoNewPrivs:\t1\nCapEff:\t0000000000000000\n' });
  assert.equal(valid.ok, true);
  const invalid = inspectLinuxHardeningStatus({ platform: 'linux', uid: 0, statusText: 'NoNewPrivs:\t0\nCapEff:\t0000000000000001\n' });
  assert.equal(invalid.ok, false);
  assert.deepEqual(invalid.issues, ['LINUX_RUNTIME_IS_ROOT', 'LINUX_NO_NEW_PRIVS_NOT_SET', 'LINUX_EFFECTIVE_CAPABILITIES_NOT_EMPTY']);
});

test('gateway exposes configured process-local connection ceilings and no false global-DDoS claim', () => {
  const { privateKey } = generateKeyPairSync('ed25519');
  const server = createEdgeGatewayServer({
    upstreamUrl: 'http://127.0.0.1:3000', privateKey,
    allowInsecureUpstream: true, maxConnections: 64, maxConcurrentRequests: 16
  });
  assert.equal(server.maxConnections, 64);
  assert.equal(server.maxRequestsPerSocket, 100);
  server.close();
});

test('RLS migration generator is transactionally locked and refuses superuser/BYPASSRLS execution', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arix-rls-'));
  const input = join(directory, 'schema.sql');
  const output = join(directory, 'policies.sql');
  try {
    await import('node:fs/promises').then(({ writeFile }) => writeFile(input, 'CREATE TABLE public.records (id uuid PRIMARY KEY, tenant_id text NOT NULL);\n'));
    const result = spawnSync(process.execPath, ['scripts/generate-rls-policies.mjs', input, output], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    const sql = await readFile(output, 'utf8');
    assert.match(sql, /^BEGIN;/m);
    assert.match(sql, /pg_advisory_xact_lock/);
    assert.match(sql, /rolsuper OR rolbypassrls/);
    assert.match(sql, /ENABLE ROW LEVEL SECURITY/);
    assert.match(sql, /FORCE ROW LEVEL SECURITY/);
    assert.match(sql, /current_setting\('arix\.tenant_id', true\)/);
    assert.match(sql, /^COMMIT;/m);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
