import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import http from 'node:http';
import net from 'node:net';
import { generateKeyPairSync } from 'node:crypto';
import { createEdgeClearanceTicket, verifyEdgeClearanceTicket } from '../api/_lib/edge-clearance.js';
import { withTenantTransaction, verifyDatabaseRlsActive } from '../api/_lib/db-guard.js';
import { getArixContext, hasScopedDataReceipt, runWithArixContext } from '../sdk/context.js';
import { installScopedResponseReceiptGate } from '../sdk/node.js';
import { generateEgressFirewallRules } from '../scripts/generate-egress-firewall.mjs';
import { installSafeGlobalAgents } from '../sdk/egress-agent.js';
import { createEdgeGatewayServer } from '../edge/gateway.mjs';
import { createReplicatedStateServer } from '../state/replicated-state-server.mjs';

const SECRET = 'arixshield-test-master-secret-with-at-least-32-bytes';


test('Node response receipt gate atomically blocks unscoped JSON and permits scoped JSON', async () => {
  const server = http.createServer((req, res) => {
    runWithArixContext({ tenantId: 'tenant-a', userId: 'user-a' }, async () => {
      installScopedResponseReceiptGate(res);
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json; charset=utf-8');
      if (req.url === '/scoped') {
        const db = { async query() { return { rows: [] }; } };
        await withTenantTransaction(db, { tenantId: 'tenant-a', userId: 'user-a' }, async (tx) => tx.query('SELECT 1'), { driver: 'pg' });
      }
      res.write('{"result":');
      res.end('"ok"}');
    }).catch((error) => { if (!res.headersSent) { res.statusCode = 500; res.end(JSON.stringify({ error: error.message })); } else res.destroy(error); });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const denied = await fetch(`${base}/unscoped`);
    assert.equal(denied.status, 500);
    assert.deepEqual(await denied.json(), { error: 'Unscoped Data Access Blocked' });
    const allowed = await fetch(`${base}/scoped`);
    assert.equal(allowed.status, 200);
    assert.deepEqual(await allowed.json(), { result: 'ok' });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('edge clearance tickets bind origin, path and method and reject tampering', () => {
  const now = 1_800_000_000_000;
  const ticket = createEdgeClearanceTicket({ audience: 'https://app.example', pathPrefix: '/api/private', methods: ['GET'], ttlMs: 10_000, now, secret: SECRET });
  assert.equal(verifyEdgeClearanceTicket(ticket, { audience: 'https://app.example', path: '/api/private/users', method: 'GET', now: now + 100, secret: SECRET }), true);
  assert.equal(verifyEdgeClearanceTicket(ticket, { audience: 'https://evil.example', path: '/api/private/users', method: 'GET', now: now + 100, secret: SECRET }), false);
  assert.equal(verifyEdgeClearanceTicket(ticket, { audience: 'https://app.example', path: '/api/private/users', method: 'POST', now: now + 100, secret: SECRET }), false);
  assert.equal(verifyEdgeClearanceTicket(`${ticket.slice(0, -1)}A`, { audience: 'https://app.example', path: '/api/private/users', method: 'GET', now: now + 100, secret: SECRET }), false);
  assert.equal(verifyEdgeClearanceTicket(ticket, { audience: 'https://app.example', path: '/api/private/users', method: 'GET', now: now + 20_000, secret: SECRET }), false);
});

test('PostgreSQL tenant transaction sets transaction-local scope and records request receipt only after commit', async () => {
  const calls = [];
  const client = {
    async query(sql, params) { calls.push({ sql, params }); return { rows: [] }; }
  };
  const observed = await runWithArixContext({ tenantId: 'tenant-a', userId: 'user-a' }, async () => {
    assert.equal(hasScopedDataReceipt(), false);
    const result = await withTenantTransaction(client, { tenantId: 'tenant-a', userId: 'user-a' }, async (tx) => {
      assert.equal(getArixContext().tenantId, 'tenant-a');
      assert.equal(hasScopedDataReceipt(), false);
      await tx.query('SELECT 1');
      return { rowCount: 1 };
    }, { driver: 'pg' });
    return { result, receipt: hasScopedDataReceipt() };
  });
  assert.deepEqual(observed, { result: { rowCount: 1 }, receipt: true });
  assert.equal(calls[0].sql, 'BEGIN');
  assert.match(calls[1].sql, /set_config\('arix\.tenant_id', \$1, true\)/);
  assert.deepEqual(calls[1].params, ['tenant-a', 'user-a']);
  assert.equal(calls.at(-1).sql, 'COMMIT');
});

test('PostgreSQL tenant transaction rolls back and does not issue a receipt on failure', async () => {
  const calls = [];
  const client = { async query(sql) { calls.push(sql); return { rows: [] }; } };
  await runWithArixContext({ tenantId: 'tenant-a', userId: 'user-a' }, async () => {
    await assert.rejects(withTenantTransaction(client, { tenantId: 'tenant-a', userId: 'user-a' }, async () => { throw new Error('query failed'); }, { driver: 'pg' }), /query failed/);
    assert.equal(hasScopedDataReceipt(), false);
  });
  assert.equal(calls.at(-1), 'ROLLBACK');
});

test('RLS verifier requires FORCE RLS and a non-bypass runtime role', async () => {
  const safeClient = { async query() { return { rows: [
    { role_name: 'arix_app', rolsuper: false, rolbypassrls: false, table_name: 'students', table_exists: true, row_security: true, force_row_security: true },
    { role_name: 'arix_app', rolsuper: false, rolbypassrls: false, table_name: 'fees', table_exists: true, row_security: true, force_row_security: true }
  ] }; } };
  assert.equal((await verifyDatabaseRlsActive(safeClient, ['students', 'fees'])).ok, true);
  const unsafeClient = { async query() { return { rows: [{ role_name: 'postgres', rolsuper: true, rolbypassrls: true, table_name: 'students', table_exists: true, row_security: true, force_row_security: false }] }; } };
  const report = await verifyDatabaseRlsActive(unsafeClient, ['students'], { throwOnFailure: false });
  assert.equal(report.ok, false);
  assert.ok(report.issues.includes('DATABASE_ROLE_IS_SUPERUSER'));
  assert.ok(report.issues.includes('DATABASE_ROLE_BYPASSES_RLS'));
  assert.ok(report.issues.includes('RLS_FORCE_DISABLED:students'));
});

test('MySQL tenant session variables are cleared before a pooled connection is released', async () => {
  const calls = [];
  let released = false;
  const connection = {
    async beginTransaction() { calls.push('BEGIN'); },
    async query(sql, values) { calls.push({ sql, values }); return [[], []]; },
    async commit() { calls.push('COMMIT'); },
    async rollback() { calls.push('ROLLBACK'); },
    release() { released = true; }
  };
  const pool = { async getConnection() { return connection; } };
  const result = await runWithArixContext({ tenantId: 'tenant-a', userId: 'user-a' }, () => withTenantTransaction(pool, { tenantId: 'tenant-a', userId: 'user-a' }, async (tx) => {
    await tx.query('SELECT 1');
    return 'ok';
  }, { driver: 'mysql2' }));
  assert.equal(result, 'ok');
  assert.equal(calls[1].sql, 'SET @arix_tenant_id = ?, @arix_user_id = ?');
  assert.equal(calls.at(-1).sql, 'SET @arix_tenant_id = NULL, @arix_user_id = NULL');
  assert.equal(released, true);
});

test('public request-context API does not expose scoped-receipt issuance', async () => {
  const contextApi = await import('../sdk/context.js');
  assert.equal(Object.hasOwn(contextApi, 'recordScopedDataReceipt'), false);
});

test('SQLite tenant transaction refuses to pretend native RLS exists', async () => {
  await runWithArixContext({ tenantId: 'tenant-a', userId: 'user-a' }, async () => {
    await assert.rejects(withTenantTransaction({ exec() {} }, { tenantId: 'tenant-a', userId: 'user-a' }, async () => true, { driver: 'sqlite' }), { code: 'ARIX_SQLITE_SCOPE_ADAPTER_REQUIRED' });
  });
});

test('UID egress rules validate allow CIDRs and block private/reserved destinations', () => {
  const rules = generateEgressFirewallRules({ uid: '65532', allow: ['10.20.0.0/16', '2001:db8::/32'] });
  assert.match(rules, /meta skuid 65532 ip daddr \{ 10\.20\.0\.0\/16 \} accept/);
  assert.match(rules, /meta skuid 65532 ip6 daddr \{ 2001:db8::\/32 \} accept/);
  assert.match(rules, /169\.254\.0\.0\/16.*drop/);
  assert.throws(() => generateEgressFirewallRules({ allow: ['10.0.0.1/99'] }), /Invalid allow CIDR/);
});

test('global http/https agents are opt-in, block unapproved HTTP and restore cleanly', () => {
  const originalHttp = http.globalAgent;
  const guard = installSafeGlobalAgents({ allowedHosts: [], allowPublicHttps: false });
  try {
    assert.notEqual(http.globalAgent, originalHttp);
    assert.throws(() => guard.httpAgent.createConnection({ host: '127.0.0.1', port: 80 }), { code: 'EHOSTUNREACH' });
  } finally {
    guard.restore();
  }
  assert.equal(http.globalAgent, originalHttp);
});

test('gateway requires exact SNI configuration for a production TLS listener and CA for mTLS', () => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  const { privateKey } = generateKeyPairSync('ed25519');
  try {
    assert.throws(() => createEdgeGatewayServer({ upstreamUrl: 'https://origin.example', privateKey, listenerTls: { cert: 'placeholder', key: 'placeholder' } }), /EDGE_ALLOWED_SNI_HOSTS/);
    assert.throws(() => createEdgeGatewayServer({ upstreamUrl: 'https://origin.example', privateKey, listenerTls: { cert: 'placeholder', key: 'placeholder' }, allowedSniHosts: ['edge.example'], requireClientCertificate: true }), /trusted client CA/);
  } finally {
    if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous;
  }
});

test('gateway contracts header and keep-alive timeouts under socket pressure, then restores them', async () => {
  const upstream = http.createServer((_req, res) => res.end('ok'));
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  const { privateKey } = generateKeyPairSync('ed25519');
  const gateway = createEdgeGatewayServer({ upstreamUrl: `http://127.0.0.1:${upstream.address().port}`, privateKey, allowInsecureUpstream: true, maxConcurrentRequests: 4, shedThreshold: 0.5 });
  gateway.listen(0, '127.0.0.1');
  await once(gateway, 'listening');
  const sockets = [];
  try {
    for (let index = 0; index < 2; index++) {
      const socket = net.connect(gateway.address().port, '127.0.0.1');
      sockets.push(socket);
      await once(socket, 'connect');
    }
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.equal(gateway.headersTimeout, 2000);
    assert.equal(gateway.keepAliveTimeout, 1000);
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.equal(gateway.headersTimeout, 10_000);
    assert.equal(gateway.keepAliveTimeout, 5000);
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => gateway.close(resolve));
    await new Promise((resolve) => upstream.close(resolve));
  }
});

test('replicated state server persists commands to WAL and recovers after restart', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arix-state-'));
  let server;
  try {
    const options = { dataDir: directory, restToken: 'existing-upstash-token-for-test', masterSecret: SECRET };
    server = createReplicatedStateServer(options);
    await server.ready;
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const endpoint = `http://127.0.0.1:${server.address().port}`;
    const headers = { authorization: 'Bearer existing-upstash-token-for-test', 'content-type': 'application/json' };
    let response = await fetch(endpoint, { method: 'POST', headers, body: JSON.stringify(['SET', 'durable:key', 'value-1', 'EX', '120']) });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).result, 'OK');
    response = await fetch(endpoint, { method: 'POST', headers, body: JSON.stringify(['EVAL', 'return 1', '0']) });
    assert.equal(response.status, 400);
    await new Promise((resolve) => server.close(resolve));
    server = createReplicatedStateServer(options);
    await server.ready;
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    response = await fetch(`http://127.0.0.1:${server.address().port}`, { method: 'POST', headers, body: JSON.stringify(['GET', 'durable:key']) });
    assert.equal((await response.json()).result, 'value-1');
    assert.equal(server.stateSnapshot().seq, 1);
    assert.equal(server.stateSnapshot().unfinalized, 0);
  } finally {
    if (server?.listening) await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});

test('three-node state topology requires quorum and applies committed writes on replicas', async () => {
  const directories = await Promise.all([0, 1, 2].map(() => mkdtemp(join(tmpdir(), 'arix-state-peer-'))));
  const servers = [];
  try {
    const token = 'existing-upstash-token-for-peer-tests';
    const shared = { restToken: token, masterSecret: SECRET };
    const replicaA = createReplicatedStateServer({ ...shared, dataDir: directories[1], role: 'replica' });
    const replicaB = createReplicatedStateServer({ ...shared, dataDir: directories[2], role: 'replica' });
    servers.push(replicaA, replicaB);
    await Promise.all([replicaA.ready, replicaB.ready]);
    for (const server of servers) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); }
    const peers = servers.map((server) => `http://127.0.0.1:${server.address().port}`);
    const primary = createReplicatedStateServer({ ...shared, dataDir: directories[0], role: 'primary', peers });
    servers.push(primary);
    await primary.ready;
    primary.listen(0, '127.0.0.1');
    await once(primary, 'listening');
    const endpoint = `http://127.0.0.1:${primary.address().port}`;
    const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
    const write = await fetch(endpoint, { method: 'POST', headers, body: JSON.stringify(['SET', 'quorum:key', 'committed']) });
    assert.equal(write.status, 200);
    for (const replica of [replicaA, replicaB]) {
      assert.equal(replica.stateSnapshot().seq, 1);
      assert.equal(replica.stateSnapshot().unfinalized, 0);
      const denied = await fetch(`http://127.0.0.1:${replica.address().port}`, { method: 'POST', headers, body: JSON.stringify(['SET', 'should-not-write', 'no']) });
      assert.equal(denied.status, 503);
    }
  } finally {
    for (const server of servers) if (server.listening) await new Promise((resolve) => server.close(resolve));
    await Promise.all(directories.map((directory) => rm(directory, { recursive: true, force: true })));
  }
});
