import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { inspectRequest } from '../api/_lib/waf-engine.js';
import { sealResourceId, rewriteCapabilityRequest, derivePassword, sha256Hex, verifySignedToken } from '../api/_lib/crypto-trap.js';
import { normalizeRoute, extractResourceId } from '../api/_lib/abuse.js';
import { assertTenantScopedQuery } from '../api/_lib/postgres-rls.js';
import { withTenantTransaction } from '../api/_lib/db-guard.js';
import { runWithArixContext } from '../sdk/context.js';
import { setAdd, setMembers, setJson, setString, enqueueIncidentAlert, claimIncidentAlert, recoverIncidentAlertClaims, ackIncidentAlert, listRange } from '../api/_lib/redis.js';
import { verifyStepUpCredentials } from '../api/_lib/step-up.js';
import { drainIncidentAlertOutbox } from '../api/_lib/alerts.js';
import { issuePowChallenge, validatePow, inspectDecryptedClearancePayload, isSuspiciousAutomation } from '../api/shield.js';
import { accountLoginRequiresPow } from '../api/auth.js';

const secret = 'arix-audit-regression-secret-at-least-48-bytes';
const ids = (result) => new Set(result.findings.map((finding) => finding.id));
const validBrowserSignals = { renderSeed: 'seedValue_123', webdriver: false, headless: false, automationFlag: false, screenMismatch: false, eventTimingAnomaly: false, interactionCountBucket: '0', touchAvailable: false, hardwareConcurrencyBucket: '4-7', hardwareConcurrency: 4, platform: 'Win32', canvasAvailable: true, webglAvailable: true, webglRenderer: 'WebGL Renderer', canvasPixelHash: '', keyboardSamples: 0, keyboardDwellVariance: 0, focusTransitions: 0, prototypeTampered: false, pointerSamples: 0, straightLineRatio: 0, pointerSpeedVariance: 0, kinematicAnomaly: false };

 test('decrypted browser clearance plaintext is subjected to the same WAF inspection as ordinary input', () => {
  const result = inspectDecryptedClearancePayload({
    projectId: 'project-audit', path: '/files/../../etc/passwd', latencyMs: 12,
    iat: Date.now(), clearanceVersion: 1,
    signals: { ...validBrowserSignals, webglRenderer: '<script>alert(1)</script>' }
  }, 'project-audit', 'POST');
  assert.equal(result.valid, true);
  assert.ok(result.inspection.findings.length > 0);
  assert.ok(ids(result.inspection).has('PATH_TRAVERSAL'));
  assert.equal(inspectDecryptedClearancePayload({ projectId: 'other', path: '/', latencyMs: 1, iat: Date.now(), clearanceVersion: 1, signals: {} }, 'project-audit').valid, false);
  assert.equal(inspectDecryptedClearancePayload({ projectId: 'project-audit', path: '/', latencyMs: 1, iat: Date.now(), clearanceVersion: 1, signals: { ...validBrowserSignals, token: 'hidden WAF payload' } }, 'project-audit').valid, false);
  // The SDK emits exact string counts 0..4 before it reaches the 5-19 bucket.
  assert.equal(inspectDecryptedClearancePayload({ projectId: 'project-audit', path: '/', latencyMs: 1, iat: Date.now(), clearanceVersion: 1, signals: { ...validBrowserSignals, interactionCountBucket: '3' } }, 'project-audit').valid, true);
});

test('browser PoW is bound to the DPoP thumbprint and atomically single-use', async () => {
  process.env.ARIX_MASTER_SECRET = secret;
  const projectId = `pow-audit-${Date.now()}`;
  const thumbprint = 'dpop-thumbprint-for-audit';
  const signals = { renderSeed: 'seed-a', keyboardSamples: 3 };
  const token = await issuePowChallenge(projectId, signals, thumbprint);
  const claims = await verifySignedToken(token, 'browser-pow');
  assert.equal(claims.thumbprint, thumbprint);
  assert.equal(await validatePow(projectId, token, '0', signals, 'different-thumbprint'), false);
  let solution = '';
  for (let candidate = 0; candidate < 200000; candidate++) {
    const digest = createHash('sha256').update(`${claims.nonce}:${claims.binding}:${candidate}`).digest();
    if (digest[0] === 0 && digest[1] === 0) { solution = String(candidate); break; }
  }
  assert.notEqual(solution, '');
  assert.equal(await validatePow(projectId, token, solution, signals, thumbprint), true);
  assert.equal(await validatePow(projectId, token, solution, signals, thumbprint), false);
});

test('account login abuse requires a one-use PoW but cannot time-lock a correct password behind an account 429', () => {
  const now = Date.now();
  assert.equal(accountLoginRequiresPow('1', now + 30000, now), true);
  assert.equal(accountLoginRequiresPow(null, now - 1, now), false);
});

test('account failure counters cannot demand impossible MFA for password-only accounts', async () => {
  process.env.ARIX_MASTER_SECRET = secret;
  const ownerId = `owner-stepup-${Date.now()}`;
  const email = `stepup-${Date.now()}@example.test`;
  const password = 'ArixAudit-Strong-Password-2026!';
  const passwordRecord = await derivePassword(password);
  await setJson(`arix:user:${ownerId}`, { id: ownerId, email, password: passwordRecord, totpEnabled: false, passkeys: [] });
  const emailHash = await sha256Hex(email.toLowerCase());
  await setString(`arix:auth:acct-failure-count:${emailHash}`, '5', 900);
  const result = await verifyStepUpCredentials({ ownerId, projectId: 'project-audit', password });
  assert.equal(result.ok, true);
  assert.equal(result.factor, 'password');
});

test('passkey-only sensitive actions reject password-only re-authentication', async () => {
  process.env.ARIX_MASTER_SECRET = secret;
  const ownerId = `owner-passkey-stepup-${Date.now()}`;
  const password = 'ArixAudit-Strong-Password-2026!';
  const passwordRecord = await derivePassword(password);
  await setJson(`arix:user:${ownerId}`, { id: ownerId, email: 'passkey@example.test', password: passwordRecord, totpEnabled: false, passkeys: [{ credentialId: 'AQID', publicKeyJwk: {}, signCount: 0 }] });
  const result = await verifyStepUpCredentials({ ownerId, projectId: 'project-audit', password });
  assert.equal(result.ok, false);
  assert.equal(result.status, 428);
  assert.equal(result.challengeType, 'passkey');
});

test('shared Redis-set TTL is monotonic and a shorter-lived member cannot expire longer-lived entries', async () => {
  const key = `arix:audit:set-ttl:${Date.now()}`;
  await setAdd(key, 'long-ban', 4);
  await setAdd(key, 'short-ban', 1);
  await new Promise((resolve) => setTimeout(resolve, 1150));
  const members = await setMembers(key);
  assert.ok(members.includes('long-ban'));
  assert.ok(members.includes('short-ban'));
  const persistentKey = `${key}:persistent`;
  await setAdd(persistentKey, 'legacy', 0);
  await setAdd(persistentKey, 'new', 2);
  await new Promise((resolve) => setTimeout(resolve, 2100));
  const persistentMembers = await setMembers(persistentKey);
  assert.ok(persistentMembers.includes('legacy') && persistentMembers.includes('new'));
});

test('capability verification rejects array-wrapped unsealed IDs and generic object-ID path segments', () => {
  process.env.ARIX_MASTER_SECRET = secret;
  const identity = { tenantId: 'tenant-a', userId: 'user-a' };
  const arrayBody = rewriteCapabilityRequest('/api/accounts', { accountId: ['unsealed-account-id'] }, identity, { method: 'PATCH', requireSealed: true });
  assert.equal(arrayBody.invalid, true);
  const mongoId = '507f1f77bcf86cd799439011';
  const path = rewriteCapabilityRequest(`/api/accounts/${mongoId}`, null, identity, { method: 'GET', requireSealed: true });
  assert.equal(path.invalid, true);
  const valid = sealResourceId(mongoId, identity, 'read');
  assert.equal(rewriteCapabilityRequest(`/api/accounts/${encodeURIComponent(valid)}`, null, identity, { method: 'GET', requireSealed: true }).invalid, false);
});

test('WAF inspects original traversal syntax and all multipart non-file fields', () => {
  const traversal = inspectRequest({ method: 'GET', url: '/files/%252e%252e/%252e%252e/etc/passwd', production: true });
  assert.ok(ids(traversal).has('PATH_TRAVERSAL'));
  const boundary = 'arix-audit-boundary';
  const fieldBody = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="comment"\r\nContent-Type: text/plain\r\n\r\n<script>alert(1)</script>\r\n--${boundary}--\r\n`);
  const fields = inspectRequest({ method: 'POST', url: '/upload', headers: { 'content-type': `multipart/form-data; boundary=${boundary}` }, rawBody: fieldBody, production: true });
  assert.ok(fields.findings.some((finding) => finding.category === 'XSS' || finding.id.includes('XSS')));
  const executableBody = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="avatar.png"\r\nContent-Type: image/png\r\n\r\nMZ\x00\x00\r\n--${boundary}--\r\n`, 'binary');
  const executable = inspectRequest({ method: 'POST', url: '/upload', headers: { 'content-type': `multipart/form-data; boundary=${boundary}` }, rawBody: executableBody, production: true });
  assert.ok(ids(executable).has('UPLOAD_EXECUTABLE_SIGNATURE'));
});

test('PostgreSQL SQL guard does not desynchronize on comments, string escapes, or procedural SQL', () => {
  assert.throws(() => assertTenantScopedQuery(["SELECT '/*'; SET LOCAL arix.tenant_id = 'other'; SELECT '*/'"]), { code: 'ARIX_RLS_CONTEXT_MUTATION_BLOCKED' });
  assert.doesNotThrow(() => assertTenantScopedQuery(["SELECT 'SET LOCAL arix.tenant_id = other'"]));
  assert.throws(() => assertTenantScopedQuery(["SELECT 1 /* outer /* nested */ */; RESET ROLE"]), { code: 'ARIX_RLS_CONTEXT_MUTATION_BLOCKED' });
  // With standard_conforming_strings enabled, a backslash does not escape the
  // terminating quote in an ordinary string; the guard must see the SET.
  assert.throws(() => assertTenantScopedQuery(["SELECT 'ordinary\\'; SET LOCAL arix.tenant_id = 'other'"]), { code: 'ARIX_RLS_CONTEXT_MUTATION_BLOCKED' });
  assert.throws(() => assertTenantScopedQuery(["DO $$ BEGIN PERFORM set_config('arix.tenant_id', 'other', false); END $$"]), { code: 'ARIX_RLS_CONTEXT_MUTATION_BLOCKED' });
  assert.throws(() => assertTenantScopedQuery(['CALL change_tenant_context()']), { code: 'ARIX_RLS_CONTEXT_MUTATION_BLOCKED' });
  assert.throws(() => assertTenantScopedQuery([`SELECT pg_catalog."set_config"('arix.tenant_id', 'other', true)`]), { code: 'ARIX_RLS_CONTEXT_MUTATION_BLOCKED' });
  assert.throws(() => assertTenantScopedQuery(['TRUNCATE tenant_records']), { code: 'ARIX_RLS_CONTEXT_MUTATION_BLOCKED' });
  assert.throws(() => assertTenantScopedQuery(['ALTER TABLE tenant_records DISABLE ROW LEVEL SECURITY']), { code: 'ARIX_RLS_CONTEXT_MUTATION_BLOCKED' });
});

 test('WAF applies non-SQL exploit checks even to bounded opaque credential fields', () => {
  const json = inspectRequest({ method: 'POST', url: '/login', headers: { 'content-type': 'application/json' }, body: { token: '<script>alert(1)</script>' }, production: true });
  assert.ok(json.findings.some((finding) => finding.category === 'XSS'));
  const boundary = 'opaque-audit-boundary';
  const multipart = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="token"\r\nContent-Type: text/plain\r\n\r\n<script>alert(1)</script>\r\n--${boundary}--\r\n`);
  const form = inspectRequest({ method: 'POST', url: '/login', headers: { 'content-type': `multipart/form-data; boundary=${boundary}` }, rawBody: multipart, production: true });
  assert.ok(form.findings.some((finding) => finding.category === 'XSS'));
});

test('db-guard PostgreSQL callback receives only a role-verified scoped query facade', async () => {
  const calls = [];
  const client = {
    async query(sql, params) {
      calls.push({ sql, params });
      if (String(sql).startsWith('SELECT rolsuper')) return { rows: [{ rolsuper: false, rolbypassrls: false }] };
      return { rows: [] };
    }
  };
  await runWithArixContext({ tenantId: 'tenant-guard', userId: 'user-guard' }, async () => {
    await withTenantTransaction(client, { tenantId: 'tenant-guard', userId: 'user-guard' }, async (tx) => {
      assert.equal(tx.release, undefined);
      await tx.query('SELECT 1');
      assert.throws(() => tx.query("SELECT '/*'; SET LOCAL arix.tenant_id = 'attacker'; SELECT '*/'"), { code: 'ARIX_RLS_CONTEXT_MUTATION_BLOCKED' });
    }, { driver: 'pg' });
  });
  assert.ok(calls.some(({ sql }) => String(sql).startsWith('SELECT rolsuper')));
  assert.ok(!calls.some(({ sql }) => String(sql).includes('SET LOCAL arix.tenant_id = \'attacker\'')));
});

test('local alert outbox supports claim, crash recovery with attempt increment, and acknowledgement', async () => {
  const projectId = `audit-alert-${Date.now()}`;
  await enqueueIncidentAlert(projectId, { type: 'TEST_INCIDENT' });
  const first = await claimIncidentAlert(projectId);
  assert.ok(first);
  assert.equal(await recoverIncidentAlertClaims(projectId, 10, 3), 1);
  const recovered = await claimIncidentAlert(projectId);
  const payload = JSON.parse(recovered);
  assert.equal(payload.attempts, 1);
  assert.equal(typeof payload.recoveredAt, 'string');
  assert.equal(await ackIncidentAlert(projectId, recovered), 1);
  assert.deepEqual(await listRange(`arix:outbox:alerts:${projectId}:processing`, 0, -1), []);
});

test('BOLA resource extraction and API route normalization recognize ObjectId, ULID and CUID formats', () => {
  const objectId = '507f1f77bcf86cd799439011';
  const ulid = '01ARZ3NDEKTSV4RRFFQ69G5FAV';
  const cuid = 'c123456789012345678901234';
  assert.equal(extractResourceId(`/api/orders/${objectId}`), objectId);
  assert.equal(extractResourceId(`/api/orders/${ulid}`), ulid);
  assert.equal(extractResourceId(`/api/orders/${cuid}`), cuid);
  assert.equal(normalizeRoute(`/api/orders/${objectId}`), '/api/orders/:id');
  assert.equal(normalizeRoute(`/api/orders/${ulid}`), '/api/orders/:id');
  assert.equal(normalizeRoute(`/api/orders/${cuid}`), '/api/orders/:id');
});

test('browser automation verdict is actionable and does not misclassify isolated weak signals', () => {
  assert.equal(isSuspiciousAutomation({ strongAutomationSignal: true, signalCount: 1, keyboardHumanSignal: false }), true);
  assert.equal(isSuspiciousAutomation({ strongAutomationSignal: false, signalCount: 2, keyboardHumanSignal: false }), true);
  assert.equal(isSuspiciousAutomation({ strongAutomationSignal: false, signalCount: 1, keyboardHumanSignal: false }), false);
  // A fabricated keyboard/focus sample cannot cancel unrelated automation indicators.
  assert.equal(isSuspiciousAutomation({ strongAutomationSignal: false, signalCount: 2, keyboardHumanSignal: true }), true);
});


test('incident alert drain defers a failed item after one attempt per invocation and continues safely', async () => {
  const projectId = `alert-drain-${Date.now()}`;
  await setJson(`arix:project:${projectId}`, { id: projectId, ownerId: 'owner-alert-test', policy: { alertWebhookUrl: 'https://127.0.0.1/blocked-by-safe-fetch' } });
  await enqueueIncidentAlert(projectId, { incident: { type: 'TEST_ALERT' } });
  const result = await drainIncidentAlertOutbox([projectId], { maxPerProject: 10, maxAttempts: 4 });
  assert.equal(result.retried, 1);
  assert.equal(result.deadLettered, 0);
  const queued = await listRange(`arix:outbox:alerts:${projectId}`, 0, 10);
  assert.equal(queued.length, 1);
  assert.equal(JSON.parse(queued[0]).attempts, 1);
});
