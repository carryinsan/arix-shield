import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { inspectRequest } from '../api/_lib/waf-engine.js';
import { assertTenantScopedQuery } from '../api/_lib/postgres-rls.js';
import { withTenantTransaction } from '../api/_lib/db-guard.js';
import { runWithArixContext } from '../sdk/context.js';
import { processCriticalThreatEvent } from '../api/_lib/redis.js';
import { base64urlEncode, dpopThumbprint, sealResourceId, verifyRequestDpopProof } from '../api/_lib/crypto-trap.js';
import { findOwnershipMismatch, rewriteCapabilityRequest } from '../api/_lib/crypto-trap.js';
import { createSession, getSession, rotateSession } from '../api/_lib/session.js';
import { getJson, setJson } from '../api/_lib/redis.js';
import { makeResponseShim } from '../api/_lib/vercel-handler.js';

const SECRET = 'arix-latest-regression-secret-with-at-least-48-bytes';

function inspectText(body, contentType = 'text/plain') {
  return inspectRequest({ method: 'POST', url: '/api/regression', headers: { 'content-type': contentType }, body });
}

test('WAF preserves SQL line-comment boundaries before grammar tokenization', () => {
  const result = inspectText('1--\nUNION SELECT password FROM users');
  assert.equal(result.allowed, false);
  assert.ok(result.findings.some((finding) => ['SQLI_UNION', 'SQLI_GRAMMAR'].includes(finding.id)));
});

test('SQL grammar prefilter includes boolean and comparison operators', () => {
  for (const payload of ['1 OR 1 <> 2', '1 OR 2 > 1', '1 AND 2 < 3', '1 OR 1 != 2']) {
    const result = inspectText(payload);
    assert.equal(result.allowed, false, payload);
    assert.ok(result.findings.some((finding) => finding.id === 'SQLI_BOOLEAN'), `${payload}: ${JSON.stringify(result.findings)}`);
  }
});

test('WAF checks raw Java serialization signatures before control-byte normalization', () => {
  const escaped = inspectText(String.raw`\xac\xed\x00\x05`);
  assert.equal(escaped.allowed, false);
  assert.ok(escaped.findings.some((finding) => finding.id === 'UNSAFE_DESERIALIZATION'));
  const bytes = inspectText('\u00ac\u00ed\x00\x05');
  assert.equal(bytes.allowed, false);
  assert.ok(bytes.findings.some((finding) => finding.id === 'UNSAFE_DESERIALIZATION'));
});

test('PostgreSQL scoped-query guard blocks Unicode escaped identifiers and dynamic SQL helpers', () => {
  const attacks = [
    String.raw`SELECT U&"set\005fconfig"('arix.tenant_id', 'victim', true)`,
    `SELECT query_to_xml('SELECT set_config(''arix.tenant_id'', ''victim'', true)', true, false, '')`,
    `SELECT dblink_exec('conn', 'SET arix.tenant_id = victim')`,
    `SELECT cursor_to_xml('SELECT set_config(''arix.tenant_id'', ''victim'', true)', true, false, '')`
  ];
  for (const sql of attacks) assert.throws(() => assertTenantScopedQuery([sql]), { code: 'ARIX_RLS_CONTEXT_MUTATION_BLOCKED' }, sql);
  assert.doesNotThrow(() => assertTenantScopedQuery([`SELECT 'U&"set_config" query_to_xml(''data'')'`]));
});

test('Prisma PostgreSQL callback receives guarded raw methods and a role-verified transaction', async () => {
  const calls = [];
  const modelResult = [{ id: 1 }];
  const tx = {
    record: { async findMany() { return modelResult; } },
    async $queryRawUnsafe(sql, ...values) {
      calls.push({ sql, values });
      if (sql.startsWith('SELECT rolsuper')) return [{ rolsuper: false, rolbypassrls: false }];
      return [];
    },
    async $executeRawUnsafe(sql, ...values) { calls.push({ sql, values }); return 1; },
    async $queryRaw(strings, ...values) { calls.push({ sql: Array.from(strings).join('?'), values }); return []; }
  };
  const prisma = { async $transaction(callback) { return callback(tx); } };
  await runWithArixContext({ tenantId: 'tenant-prisma', userId: 'user-prisma' }, async () => {
    const result = await withTenantTransaction(prisma, { tenantId: 'tenant-prisma', userId: 'user-prisma' }, async (scoped) => {
      assert.equal(scoped.$transaction, undefined, 'nested transaction control is not exposed');
      assert.deepEqual(await scoped.record.findMany(), modelResult);
      await scoped.$queryRawUnsafe('SELECT 1');
      assert.throws(() => scoped.$queryRawUnsafe("SELECT set_config('arix.tenant_id', 'other', true)"), { code: 'ARIX_RLS_CONTEXT_MUTATION_BLOCKED' });
      assert.throws(() => scoped.$executeRawUnsafe('SET LOCAL arix.tenant_id = other'), { code: 'ARIX_RLS_CONTEXT_MUTATION_BLOCKED' });
      return 'ok';
    }, { driver: 'prisma', provider: 'postgresql' });
    assert.equal(result, 'ok');
  });
  assert.ok(calls.some(({ sql }) => sql.startsWith('SELECT rolsuper')));
  assert.ok(calls.some(({ sql }) => sql.includes("set_config('arix.tenant_id', $1, true)")));
  assert.ok(calls.some(({ sql }) => sql === 'SELECT 1'));
});

test('Prisma PostgreSQL refuses a superuser or BYPASSRLS runtime role', async () => {
  const tx = {
    async $queryRawUnsafe(sql) {
      if (sql.startsWith('SELECT rolsuper')) return [{ rolsuper: true, rolbypassrls: false }];
      return [];
    },
    async $executeRawUnsafe() { return 1; }
  };
  const prisma = { async $transaction(callback) { return callback(tx); } };
  await runWithArixContext({ tenantId: 'tenant-prisma-root', userId: 'user-prisma-root' }, async () => {
    await assert.rejects(withTenantTransaction(prisma, { tenantId: 'tenant-prisma-root', userId: 'user-prisma-root' }, async () => 'must-not-run', { driver: 'prisma', provider: 'postgresql' }), { code: 'ARIX_RLS_PRIVILEGED_ROLE' });
  });
});

test('MySQL transaction callback cannot rewrite tenant variables or execute stored programs', async () => {
  const calls = [];
  const connection = {
    async beginTransaction() { calls.push('BEGIN'); },
    async query(sql, values) { calls.push({ sql, values }); return [[], []]; },
    async execute(sql, values) { calls.push({ sql, values }); return [[], []]; },
    async commit() { calls.push('COMMIT'); },
    async rollback() { calls.push('ROLLBACK'); },
    release() { calls.push('RELEASE'); }
  };
  const pool = { async getConnection() { return connection; } };
  await runWithArixContext({ tenantId: 'tenant-mysql', userId: 'user-mysql' }, async () => {
    await assert.rejects(withTenantTransaction(pool, { tenantId: 'tenant-mysql', userId: 'user-mysql' }, async (tx) => {
      await tx.query('SELECT 1');
      await assert.rejects(tx.query('SET @arix_tenant_id = \'victim\''), { code: 'ARIX_SQL_CONTROL_BLOCKED' });
      await assert.rejects(tx.execute('CALL change_tenant_context()'), { code: 'ARIX_SQL_CONTROL_BLOCKED' });
    }, { driver: 'mysql2' }), { code: 'ARIX_SQL_CONTROL_BLOCKED' });
  });
  assert.ok(calls.some((call) => call?.sql === 'SET @arix_tenant_id = ?, @arix_user_id = ?'));
  assert.ok(calls.some((call) => call?.sql === 'SET @arix_tenant_id = NULL, @arix_user_id = NULL'));
  assert.equal(calls.some((call) => call?.sql?.startsWith('CALL')), false);
});

test('critical containment and alert enqueue continue after audit-chain append failure', async () => {
  let savedProject = null;
  let queued = null;
  const initial = { id: 'critical-audit-test', policy: { mode: 'DRY_RUN', autoContainmentEnabled: true, alertWebhookUrl: 'https://alerts.example.test/hook' } };
  const result = await processCriticalThreatEvent('critical-audit-test', { type: 'CANARY_KEY_USED', blocked: true }, {
    appendAudit: async () => { throw new Error('simulated CAS contention'); },
    readProject: async (key) => { assert.equal(key, 'arix:project:critical-audit-test'); return initial; },
    saveProject: async (key, value) => { assert.equal(key, 'arix:project:critical-audit-test'); savedProject = value; },
    dispatchAlert: async (_url, incident) => { assert.equal(incident.audit, null); assert.equal(incident.auditUnavailable, true); throw new Error('simulated webhook outage'); },
    queueAlert: async (id, incident) => { assert.equal(id, 'critical-audit-test'); queued = incident; }
  });
  assert.equal(savedProject.policy.mode, 'ENFORCE');
  assert.equal(result.containmentApplied, true);
  assert.equal(result.alertQueued, true);
  assert.equal(queued.auditUnavailable, true);
  assert.equal(queued.containment, true);
});

test('request-bound DPoP replay entry remains present throughout the full +/-45 second iat window', async () => {
  process.env.ARIX_MASTER_SECRET = SECRET;
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const thumbprint = await dpopThumbprint(publicJwk);
  const originalNow = Date.now;
  const nowMs = originalNow();
  const url = 'https://app.example.test/api/replay-window';
  const bodyBytes = new TextEncoder().encode('');
  const digest = new Uint8Array(await webcrypto.subtle.digest('SHA-256', bodyBytes));
  const header = base64urlEncode(new TextEncoder().encode(JSON.stringify({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk })));
  const payload = base64urlEncode(new TextEncoder().encode(JSON.stringify({ htm: 'GET', htu: url, iat: Math.floor(nowMs / 1000) + 30, jti: `request-proof-window-${nowMs}`, ath: base64urlEncode(digest), nonce: 'clearance-nonce-request-window' })));
  const input = `${header}.${payload}`;
  const signature = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode(input));
  const proof = `${input}.${base64urlEncode(new Uint8Array(signature))}`;
  try {
    Date.now = () => nowMs;
    const first = await verifyRequestDpopProof({ proof, method: 'GET', url, bodyBytes, expectedThumbprint: thumbprint, clearanceNonce: 'clearance-nonce-request-window', projectId: `replay-window-${nowMs}` });
    assert.equal(first.valid, true, first.reason);
    Date.now = () => nowMs + 16_000;
    const replay = await verifyRequestDpopProof({ proof, method: 'GET', url, bodyBytes, expectedThumbprint: thumbprint, clearanceNonce: 'clearance-nonce-request-window', projectId: `replay-window-${nowMs}` });
    assert.equal(replay.valid, false);
    assert.equal(replay.reason, 'DPOP_REPLAY');
  } finally { Date.now = originalNow; }
});

test('duplicate JSON scanner complexity exhaustion is an explicit blocking protocol finding', () => {
  const padding = Array(12_100).fill('0').join(',');
  const raw = `{"pad":[${padding}],"role":"user","role":"admin"}`;
  const result = inspectRequest({ method: 'POST', url: '/api/complex-json', headers: { 'content-type': 'application/json' }, body: JSON.parse(raw), rawBody: raw, contentLength: Buffer.byteLength(raw) });
  assert.equal(result.allowed, false);
  assert.ok(result.findings.some((finding) => finding.id === 'JSON_COMPLEXITY_LIMIT'));
});

test('capability query array allowlist validates and rewrites every resource ID', () => {
  process.env.ARIX_MASTER_SECRET = SECRET;
  const identity = { tenantId: 'tenant-array', userId: 'user-array' };
  const first = sealResourceId('order-100', identity, 'read');
  const second = sealResourceId('order-200', identity, 'read');
  const allowed = rewriteCapabilityRequest(`/api/orders?id=${encodeURIComponent(first)}&id=${encodeURIComponent(second)}`, null, identity, { method: 'GET', arrayQueryFields: ['id'] });
  assert.equal(allowed.invalid, false);
  assert.equal(allowed.verifiedResourceIds, 2);
  assert.equal(new URL(allowed.url, 'https://arix.test').searchParams.getAll('id').join(','), 'order-100,order-200');
  const disallowed = rewriteCapabilityRequest(`/api/orders?id=${encodeURIComponent(first)}&id=${encodeURIComponent(second)}`, null, identity, { method: 'GET' });
  assert.equal(disallowed.invalid, true);
});

test('ownership mismatch traversal checks root arrays, nested envelopes and records beyond the old 100-item cutoff', () => {
  assert.ok(findOwnershipMismatch([{ item: { owner_id: 'other-user' } }], 'expected-user'));
  assert.ok(findOwnershipMismatch({ data: { nested: { userId: 'other-user' } } }, 'expected-user'));
  const records = Array.from({ length: 125 }, () => ({ ownerId: 'expected-user' }));
  records[124].ownerId = 'other-user';
  assert.ok(findOwnershipMismatch({ results: records }, 'expected-user'));
  assert.equal(findOwnershipMismatch({ items: [{ ownerId: 'expected-user' }] }, 'expected-user'), null);
});

test('short project/user-prefixed path identifiers are treated as resource IDs', () => {
  const result = rewriteCapabilityRequest('/api/users/usr_12345', null, 'user-short-id', { method: 'GET', requireSealed: true });
  assert.equal(result.invalid, true);
});

test('session rotation grace rejects stale cookies without revoking the replacement or other devices', async () => {
  const previous = { nodeEnv: process.env.NODE_ENV, vercel: process.env.VERCEL };
  const originalNow = Date.now;
  delete process.env.VERCEL;
  process.env.NODE_ENV = 'test';
  const ownerId = `rotation-owner-${originalNow()}`;
  const projectId = `rotation-project-${originalNow()}`;
  const nowMs = originalNow();
  try {
    Date.now = () => nowMs;
    const first = await createSession(ownerId, projectId, { headers: {}, socket: { remoteAddress: '127.0.0.1' } });
    const otherDevice = await createSession(ownerId, projectId, { headers: {}, socket: { remoteAddress: '127.0.0.2' } });
    const rotated = await rotateSession(ownerId, projectId, first.tokenHash, { headers: {}, socket: { remoteAddress: '127.0.0.1' } });
    assert.ok(rotated);
    Date.now = () => nowMs + 1_000;
    assert.equal(await getSession({ headers: { cookie: `arix_session=${first.token}` } }), null, 'old token is never accepted during grace');
    assert.equal((await getSession({ headers: { cookie: `arix_session=${rotated.token}` } }))?.ownerId, ownerId, 'replacement remains valid');
    assert.equal((await getSession({ headers: { cookie: `arix_session=${otherDevice.token}` } }))?.ownerId, ownerId, 'other device family remains valid');
    Date.now = () => nowMs + 16_000;
    assert.equal(await getSession({ headers: { cookie: `arix_session=${first.token}` } }), null, 'old-token replay after grace revokes its family');
    assert.equal(await getSession({ headers: { cookie: `arix_session=${rotated.token}` } }), null, 'same-family replacement is revoked after replay');
    assert.equal((await getSession({ headers: { cookie: `arix_session=${otherDevice.token}` } }))?.ownerId, ownerId, 'separate device remains active');
  } finally {
    Date.now = originalNow;
    if (previous.nodeEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = previous.nodeEnv;
    if (previous.vercel === undefined) delete process.env.VERCEL; else process.env.VERCEL = previous.vercel;
  }
});

test('session-rotation race does not revoke the winning family when SET NX loses', async () => {
  // A direct marker is enough to exercise the loser path without a timing race.
  process.env.NODE_ENV = 'test';
  const ownerId = `rotation-race-owner-${Date.now()}`;
  const projectId = `rotation-race-project-${Date.now()}`;
  const first = await createSession(ownerId, projectId);
  await setJson(`arix:session-spent:${first.tokenHash}`, { familyId: first.familyId, ownerId, spentAt: Date.now() }, 86400);
  const winner = await createSession(ownerId, projectId, null, { familyId: first.familyId });
  const loser = await rotateSession(ownerId, projectId, first.tokenHash);
  assert.equal(loser, null);
  assert.equal((await getJson(`arix:session:${winner.tokenHash}`))?.ownerId, ownerId);
});

test('Vercel response shim preserves Set-Cookie array entries separately', () => {
  const shim = makeResponseShim();
  shim.response.setHeader('Set-Cookie', [
    'arix_session=one; Path=/; HttpOnly; SameSite=Strict',
    '__Host-arix_session=two; Path=/; Secure; HttpOnly; SameSite=Strict'
  ]);
  shim.response.end('ok');
  const response = shim.toWebResponse();
  assert.deepEqual(response.headers.getSetCookie(), [
    'arix_session=one; Path=/; HttpOnly; SameSite=Strict',
    '__Host-arix_session=two; Path=/; Secure; HttpOnly; SameSite=Strict'
  ]);
});
