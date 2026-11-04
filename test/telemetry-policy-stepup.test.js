import test from 'node:test';
import assert from 'node:assert/strict';
import { createSession } from '../api/_lib/session.js';
import { derivePassword } from '../api/_lib/crypto-trap.js';
import { setJson, getJson, getAuditChainSnapshot } from '../api/_lib/redis.js';

function responseRecorder() {
  return {
    statusCode: 200, headers: {}, body: '',
    setHeader(name, value) { this.headers[String(name).toLowerCase()] = value; },
    getHeader(name) { return this.headers[String(name).toLowerCase()]; },
    end(value = '') { this.body = String(value); }
  };
}

function requestFor(token, body) {
  return {
    method: 'POST', url: '/api/telemetry',
    headers: { host: 'localhost', origin: 'http://localhost', 'content-type': 'application/json', cookie: `arix_session=${token}` },
    socket: { encrypted: false, remoteAddress: '127.0.0.1' }, body
  };
}

test('security policy changes require fresh authentication and are recorded in the tamper-evident audit chain', async () => {
  const previous = { nodeEnv: process.env.NODE_ENV, vercel: process.env.VERCEL, master: process.env.ARIX_MASTER_SECRET };
  process.env.NODE_ENV = 'test'; delete process.env.VERCEL; process.env.ARIX_MASTER_SECRET = 'P'.repeat(48);
  try {
    const ownerId = `policy-stepup-owner-${Date.now()}`;
    const projectId = `policy-stepup-project-${Date.now()}`;
    const password = 'Policy-Change-Strong-Password-2026!';
    const passwordRecord = await derivePassword(password);
    await setJson(`arix:user:${ownerId}`, { id: ownerId, email: `${ownerId}@example.test`, password: passwordRecord, totpEnabled: false, passkeys: [] });
    const initialPolicy = { mode: 'ENFORCE', rateLimitPerMinute: 120, abuseProtectionEnabled: true, threatFeedEnabled: true, alertWebhookUrl: 'https://hooks.example.test/old?secret=never-log-this' };
    await setJson(`arix:project:${projectId}`, { id: projectId, ownerId, origin: 'https://app.example.test', policy: initialPolicy });
    const session = await createSession(ownerId, projectId, { headers: { 'user-agent': 'policy-stepup-test' }, socket: { remoteAddress: '127.0.0.1' } });
    const handler = (await import('../api/telemetry.js')).default;

    const payload = { action: 'policy', mode: 'ENFORCE', rateLimitPerMinute: 10000, abuseProtectionEnabled: false, threatFeedEnabled: true, alertWebhookUrl: '' };
    const denied = responseRecorder();
    await handler(requestFor(session.token, payload), denied);
    assert.equal(denied.statusCode, 401, denied.body);
    assert.equal((await getJson(`arix:project:${projectId}`)).policy.rateLimitPerMinute, 120, 'policy remains unchanged without re-authentication');

    const accepted = responseRecorder();
    await handler(requestFor(session.token, { ...payload, password }), accepted);
    assert.equal(accepted.statusCode, 200, accepted.body);
    const response = JSON.parse(accepted.body);
    assert.equal(response.auditRecorded, true);
    const saved = await getJson(`arix:project:${projectId}`);
    assert.equal(saved.policy.rateLimitPerMinute, 10000);
    assert.equal(saved.policy.abuseProtectionEnabled, false);

    const audit = await getAuditChainSnapshot(projectId, 20);
    assert.equal(audit.verified, true);
    const row = audit.rows.at(-1);
    assert.equal(row.event.type, 'SECURITY_POLICY_CHANGED');
    assert.deepEqual(row.event.changedFields.sort(), ['abuseProtectionEnabled', 'alertWebhookUrl', 'rateLimitPerMinute'].sort());
    assert.equal(JSON.stringify(row.event).includes('never-log-this'), false, 'webhook secrets are not written to audit records');
    assert.equal(row.event.previousPolicy.alertWebhookConfigured, true);
    assert.equal(row.event.updatedPolicy.alertWebhookConfigured, false);
  } finally {
    if (previous.nodeEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = previous.nodeEnv;
    if (previous.vercel === undefined) delete process.env.VERCEL; else process.env.VERCEL = previous.vercel;
    if (previous.master === undefined) delete process.env.ARIX_MASTER_SECRET; else process.env.ARIX_MASTER_SECRET = previous.master;
  }
});

test('passkey-only owners cannot change security policy with password alone', async () => {
  const previous = { nodeEnv: process.env.NODE_ENV, vercel: process.env.VERCEL, master: process.env.ARIX_MASTER_SECRET };
  process.env.NODE_ENV = 'test'; delete process.env.VERCEL; process.env.ARIX_MASTER_SECRET = 'Q'.repeat(48);
  try {
    const ownerId = `policy-passkey-owner-${Date.now()}`;
    const projectId = `policy-passkey-project-${Date.now()}`;
    const password = 'Policy-Passkey-Strong-Password-2026!';
    const passwordRecord = await derivePassword(password);
    await setJson(`arix:user:${ownerId}`, { id: ownerId, email: `${ownerId}@example.test`, password: passwordRecord, totpEnabled: false, passkeys: [{ credentialId: 'AQID', publicKeyJwk: {}, signCount: 0 }] });
    await setJson(`arix:project:${projectId}`, { id: projectId, ownerId, origin: 'https://app.example.test', policy: { mode: 'ENFORCE', rateLimitPerMinute: 120 } });
    const session = await createSession(ownerId, projectId);
    const handler = (await import('../api/telemetry.js')).default;
    const res = responseRecorder();
    await handler(requestFor(session.token, { action: 'policy', rateLimitPerMinute: 500, password }), res);
    assert.equal(res.statusCode, 428, res.body);
    assert.equal(JSON.parse(res.body).challengeType, 'passkey');
    assert.equal((await getJson(`arix:project:${projectId}`)).policy.rateLimitPerMinute, 120);
  } finally {
    if (previous.nodeEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = previous.nodeEnv;
    if (previous.vercel === undefined) delete process.env.VERCEL; else process.env.VERCEL = previous.vercel;
    if (previous.master === undefined) delete process.env.ARIX_MASTER_SECRET; else process.env.ARIX_MASTER_SECRET = previous.master;
  }
});
