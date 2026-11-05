import test from 'node:test';
import assert from 'node:assert/strict';
import { cidrContains, buildPrefixTrie, prefixTrieHas, parseCidr } from '../api/_lib/cidr.js';
import { inspectRequest, validateJsonSchema, redactSensitiveText, canonicalizeSecurityText } from '../api/_lib/waf-engine.js';
import { compileOpenApiRequestSchema, validatePayloadSchema } from '../api/_lib/schema.js';
import { merkleRoot } from '../api/_lib/audit.js';
import { recordRequestOutcome, isActorBackedOff, banActorForHoneypot, recordThreatCorrelation } from '../api/_lib/abuse.js';
import { verifyConfiguredProviderIp, checkIpReputation, getThreatFeedStatus } from '../api/_lib/reputation.js';
import { createInvisibleWatermarkMarker, decodeInvisibleWatermark, watermarkPayloadWithMarker, createChameleonCanaryId, storeChameleonCanary, spliceCanaryRow, getChameleonRowIdentifier, storeChameleonExposedId, lookupChameleonCanaryByExposedId } from '../api/_lib/watermark.js';
import { sealResourceId, verifyResourceId, rewriteCapabilityPath, rewriteCapabilityRequest, sealResourceIdsInPayload, findOwnershipMismatch, sha256Hex } from '../api/_lib/crypto-trap.js';
import { getStrings, setAdd, setMembers, setCard, setRemoveMany, recordAuditChainEvent, getAuditChainSnapshot, setJson } from '../api/_lib/redis.js';
process.env.NODE_ENV = 'test';
test('CIDR matching supports IPv4 and IPv6 prefixes', () => { assert.equal(cidrContains('192.0.2.0/24', '192.0.2.42'), true); assert.equal(cidrContains('192.0.2.0/24', '192.0.3.42'), false); assert.equal(cidrContains('2001:db8::/32', '2001:db8::1'), true); assert.equal(cidrContains('2001:db8::/32', '2001:dead::1'), false); assert.equal(parseCidr('10.0.0.0/33'), null); });
test('binary prefix trie returns membership for both address families', () => { const trie = buildPrefixTrie(['203.0.113.0/24', '2001:db8:abcd::/48', 'invalid']); assert.equal(trie.count, 2); assert.equal(prefixTrieHas(trie, '203.0.113.99'), true); assert.equal(prefixTrieHas(trie, '203.0.114.1'), false); assert.equal(prefixTrieHas(trie, '2001:db8:abcd::4'), true); });
test('WAF does not misclassify unrelated sequential resource IDs as BOLA', () => { const result = inspectRequest({ method: 'GET', url: '/api/orders/1001/1002/1003' }); assert.equal(result.findings.some((finding) => finding.category === 'BOLA'), false); assert.equal(result.findings.length, 0); });
test('opaque credentials and rich-text SQL/Markdown do not trigger SQL heuristics, while XSS remains enforceable', () => {
  const benign = inspectRequest({ method: 'POST', url: '/api/notes', headers: { 'content-type': 'application/json' }, body: { password: 'P@ssw0rd!#$%^&*()--', newPassword: "x' OR 1=1 --", content: "Tutorial: SELECT * FROM users WHERE id = '1' OR '1'='1' --\n---\n# Passwords and code samples" } });
  assert.equal(benign.findings.some((finding) => finding.category === 'SQL_INJECTION'), false);
  const xss = inspectRequest({ method: 'POST', url: '/api/notes', headers: { 'content-type': 'application/json' }, body: { content: '<script>alert(1)</script>' } });
  assert.ok(xss.findings.some((finding) => finding.category === 'XSS'));
});

test('WAF detects representative SSRF and SQLi payloads', () => { const ssrf = inspectRequest({ method: 'GET', url: '/fetch?url=http://169.254.169.254/latest/meta-data' }); const sqli = inspectRequest({ method: 'POST', url: '/api/search', headers: { 'content-type': 'application/json' }, body: { q: "' OR 1=1" } }); assert.ok(ssrf.findings.some((finding) => finding.category === 'SSRF')); assert.ok(sqli.findings.some((finding) => finding.category === 'SQL_INJECTION')); });

test('WAF does not classify ordinary prose or unrelated metadata as SSRF', () => {
  const prose = 'For local development, localhost and 127.0.0.1 are common examples; cloud metadata is often at 169.254.169.254 or metadata.google.internal.';
  const samples = [
    inspectRequest({ method: 'POST', url: '/api/chat', headers: { 'content-type': 'text/plain', 'user-agent': prose }, body: prose, production: true }),
    inspectRequest({ method: 'POST', url: '/api/messages', headers: { 'content-type': 'application/json' }, body: { message: prose, title: '127.0.0.1 is a loopback address' }, production: true }),
    inspectRequest({ method: 'GET', url: `/search?q=${encodeURIComponent(prose)}`, production: true }),
    inspectRequest({ method: 'GET', url: '/search?message=http%3A%2F%2F127.0.0.1%2Fadmin', production: true }),
    inspectRequest({ method: 'GET', url: '/search', headers: { 'x-note': 'http://127.0.0.1 is shown as an example' }, production: true })
  ];
  for (const result of samples) assert.equal(result.findings.some((finding) => finding.category === 'SSRF'), false, JSON.stringify(result.findings));
});

test('WAF still blocks unsafe hosts in explicit SSRF destination sinks', () => {
  const samples = [
    inspectRequest({ method: 'GET', url: '/fetch?url=http%3A%2F%2F127.0.0.1%2Fadmin', production: true }),
    inspectRequest({ method: 'GET', url: '/fetch?target=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data', production: true }),
    inspectRequest({ method: 'POST', url: '/api/import', headers: { 'content-type': 'application/json' }, body: { sourceUrl: 'https://metadata.google.internal/computeMetadata/v1/' }, production: true }),
    inspectRequest({ method: 'POST', url: '/api/webhooks', headers: { 'content-type': 'application/json' }, body: { webhookUrl: 'http://100.100.100.200/latest/meta-data' }, production: true }),
    inspectRequest({ method: 'POST', url: '/api/import', headers: { 'content-type': 'application/json' }, body: { url: 'http://2130706433/admin' }, production: true }),
    inspectRequest({ method: 'POST', url: '/api/import', headers: { 'content-type': 'application/json' }, body: { url: 'https%253A%252F%252Flocalhost%252Fadmin' }, production: true }),
    inspectRequest({ method: 'POST', url: '/api/import', headers: { 'content-type': 'application/json' }, body: { url: '//localhost/admin' }, production: true }),
    inspectRequest({ method: 'GET', url: '/fetch', headers: { 'x-fetch-url': 'http://localhost:8080/private' }, production: true })
  ];
  for (const result of samples) assert.ok(result.findings.some((finding) => finding.category === 'SSRF'), JSON.stringify(result.findings));
});

test('WAF applies destination-aware SSRF inspection to multipart fields only', () => {
  const boundary = 'ssrf-field-test';
  const makeMultipart = (fieldName) => Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name=\"${fieldName}\"\r\n\r\nhttp://127.0.0.1/private\r\n--${boundary}--\r\n`);
  const headers = { 'content-type': `multipart/form-data; boundary=${boundary}` };
  const destination = inspectRequest({ method: 'POST', url: '/upload', headers, rawBody: makeMultipart('url'), production: true });
  const prose = inspectRequest({ method: 'POST', url: '/upload', headers, rawBody: makeMultipart('comment'), production: true });
  assert.ok(destination.findings.some((finding) => finding.category === 'SSRF'));
  assert.equal(prose.findings.some((finding) => finding.category === 'SSRF'), false);
});

test('WAF evaluates only URL hosts in destination fields and does not confuse userinfo or path text with a local destination', () => {
  const publicDestination = inspectRequest({ method: 'POST', url: '/api/import', headers: { 'content-type': 'application/json' }, body: { url: 'https://127.0.0.1.example.com/path' }, production: true });
  const userinfo = inspectRequest({ method: 'POST', url: '/api/import', headers: { 'content-type': 'application/json' }, body: { url: 'https://127.0.0.1@public.example.com/path' }, production: true });
  const ordinaryPath = inspectRequest({ method: 'GET', url: '/articles/localhost/127.0.0.1/169.254.169.254', production: true });
  for (const result of [publicDestination, userinfo, ordinaryPath]) assert.equal(result.findings.some((finding) => finding.category === 'SSRF'), false, JSON.stringify(result.findings));
});

test('JSON schema validator enforces required fields, bounds and additionalProperties', () => { const schema = { type: 'object', required: ['name'], additionalProperties: false, properties: { name: { type: 'string', minLength: 2 }, age: { type: 'integer', minimum: 0, maximum: 120 } } }; assert.equal(validateJsonSchema({ name: 'Ada', age: 30 }, schema).valid, true); assert.equal(validateJsonSchema({ name: 'A', age: 200, admin: true }, schema).valid, false); });
test('parsed OpenAPI operations resolve local references and Zod-like safeParse schemas', () => { const spec = { openapi: '3.0.3', paths: { '/api/users/{id}': { patch: { operationId: 'updateUser', requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/UserPatch' } } } } } } }, components: { schemas: { UserPatch: { type: 'object', required: ['displayName'], additionalProperties: false, properties: { displayName: { type: 'string', minLength: 2 } } } } } }; const compiled = compileOpenApiRequestSchema(spec, 'PATCH', '/api/users/44'); assert.equal(compiled.operationId, 'updateUser'); assert.equal(validatePayloadSchema({ displayName: 'Ada' }, compiled).valid, true); assert.equal(validatePayloadSchema({ displayName: 'A' }, compiled).valid, false); const zodLike = { safeParse: (value) => value?.ok ? { success: true } : { success: false, error: { issues: [{ path: ['ok'], message: 'required' }] } } }; assert.equal(validatePayloadSchema({ ok: true }, zodLike).valid, true); assert.equal(validatePayloadSchema({}, zodLike).valid, false); });
test('DLP redacts common provider secrets, email, SSN and valid Luhn cards', () => { const fakeStripeKey = ['sk', 'live', '1234567890abcdefghijkl'].join('_'); const input = `AKIAIOSFODNN7EXAMPLE ${fakeStripeKey} user@example.com 123-45-6789 4111 1111 1111 1111`; const result = redactSensitiveText(input); for (const type of ['AWS_ACCESS_KEY', 'STRIPE_SECRET', 'EMAIL', 'US_SSN', 'CARD_CANDIDATE']) assert.ok(result.detected.includes(type)); assert.ok(!result.text.includes('user@example.com')); });
test('Merkle roots are deterministic and validate leaf hashes', () => { const a = 'a'.repeat(64); const b = 'b'.repeat(64); assert.equal(merkleRoot([a, b]), merkleRoot([a, b])); assert.notEqual(merkleRoot([a, b]), merkleRoot([b, a])); assert.match(merkleRoot([]), /^[a-f0-9]{64}$/); });
test('BOLA detection aggregates distinct denied IDs across a session window', async () => { const projectId = 'test-bola-project'; let last; for (let id = 1001; id <= 1012; id++) last = await recordRequestOutcome({ projectId, actorId: 'user-1', path: `/api/orders/${id}`, method: 'GET', status: 404 }); assert.equal(last.bolaTriggered, true); assert.equal((await isActorBackedOff(projectId, 'user-1')).blocked, true); });
test('configured provider CIDR allowlisting only trusts an explicit operator entry', () => { process.env.ARIX_TRUSTED_PROVIDER_CIDRS_JSON = JSON.stringify({ github: ['192.0.2.0/24'] }); assert.equal(verifyConfiguredProviderIp('192.0.2.8', 'github').verified, true); assert.equal(verifyConfiguredProviderIp('198.51.100.8', 'github').verified, false); });
test('WAF requires an explicit content type for a non-empty body and rejects malformed JSON media', () => { const missing = inspectRequest({ method: 'POST', url: '/api/items', headers: {}, body: { name: 'x' } }); assert.ok(missing.findings.some((finding) => finding.id === 'CONTENT_TYPE')); const malformed = inspectRequest({ method: 'POST', url: '/api/items', headers: { 'content-type': 'application/json' }, body: '{not-json' }); assert.ok(malformed.findings.some((finding) => finding.id === 'JSON_PARSE')); });
test('Next.js request DLP rewrites the handler request body when explicitly enabled', async () => { const { withArixShield } = await import('../sdk/next.js'); const handler = withArixShield(async (request) => Response.json(await request.json()), { mode: 'DRY_RUN', requestDlp: true, globalRateLimit: false }); const request = new Request('https://example.test/api/submit', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'customer@example.com', message: 'hello' }) }); const response = await handler(request); const body = await response.json(); assert.equal(body.email, '[REDACTED_EMAIL]'); assert.equal(body.message, 'hello'); });

test('Next.js adapter rejects bodies over the configured byte cap before invoking the route', async () => { const { withArixShield } = await import('../sdk/next.js'); let called = false; const handler = withArixShield(async () => { called = true; return Response.json({ ok: true }); }, { mode: 'DRY_RUN', globalRateLimit: false, maxBodyBytes: 32768 }); const request = new Request('https://example.test/api/submit', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ data: 'x'.repeat(40000) }) }); const response = await handler(request); assert.equal(response.status, 413); assert.equal(called, false); });

test('Next.js adapter scans an explicitly permitted larger JSON body instead of truncating at 32 KiB', async () => { const { withArixShield } = await import('../sdk/next.js'); const handler = withArixShield(async (request) => Response.json({ length: (await request.json()).data.length }), { mode: 'DRY_RUN', globalRateLimit: false, maxBodyBytes: 65536, maxLeafBytes: 50000, allowedLongFields: ['data'] }); const request = new Request('https://example.test/api/submit', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ data: 'x'.repeat(40000) }) }); const response = await handler(request); assert.equal(response.status, 200); assert.equal((await response.json()).length, 40000); });
test('OpenAPI route matcher recognizes documented templates and flags unlisted paths', async () => { const { isOpenApiOperation } = await import('../api/_lib/schema.js'); const document = { paths: { '/api/orders/{orderId}': { get: {}, patch: {} }, '/api/orders': { post: {} } } }; assert.equal(isOpenApiOperation(document, 'GET', '/api/orders/123'), true); assert.equal(isOpenApiOperation(document, 'POST', '/api/orders'), true); assert.equal(isOpenApiOperation(document, 'DELETE', '/api/orders/123'), false); assert.equal(isOpenApiOperation(document, 'GET', '/api/internal/debug'), false); });
test('JSON schema supports enum, formats, nested additionalProperties and unique arrays', () => { const schema = { type: 'object', required: ['owner'], properties: { owner: { type: 'string', format: 'email' }, state: { type: 'string', enum: ['open', 'closed'] }, ids: { type: 'array', uniqueItems: true, items: { type: 'integer' } } }, additionalProperties: { type: 'string', maxLength: 8 } }; assert.equal(validateJsonSchema({ owner: 'a@example.com', state: 'open', ids: [1, 2], label: 'short' }, schema).valid, true); assert.equal(validateJsonSchema({ owner: 'bad-email', state: 'pending', ids: [1, 1], label: 'way-too-long-label' }, schema).valid, false); });
test('honeypot bans are actor-scoped and never hard-ban a shared source IP', async () => { const projectId = 'project_honeypot_test'; await banActorForHoneypot(projectId, 'user-123', '203.0.113.44'); const byActor = await isActorBackedOff(projectId, 'user-123'); const byPeer = await isActorBackedOff(projectId, 'another-user', '203.0.113.44'); assert.equal(byActor.blocked, true); assert.equal(byPeer.blocked, false); assert.ok(byActor.retryAfterMs > 23 * 60 * 60 * 1000); });
test('anonymous honeypot hits do not collapse unrelated visitors behind a shared IP', async () => { const projectId = 'project_anonymous_honeypot_test'; await banActorForHoneypot(projectId, 'anonymous', ''); assert.equal((await isActorBackedOff(projectId, 'anonymous', '')).blocked, false); await banActorForHoneypot(projectId, 'anonymous', '203.0.113.99'); assert.equal((await isActorBackedOff(projectId, 'anonymous', '203.0.113.99')).blocked, false); assert.equal((await isActorBackedOff(projectId, 'another-user', '203.0.113.99')).blocked, false); });
test('ephemeral anonymous request identities do not create ineffective persistent honeypot bans', async () => { const projectId = 'project_ephemeral_actor_test'; const actor = 'anonymous:ephemeral-request-1'; const result = await banActorForHoneypot(projectId, actor, '203.0.113.101'); assert.equal(result.scope, 'none'); assert.equal(result.actorHash, null); assert.equal((await isActorBackedOff(projectId, actor, '203.0.113.101')).blocked, false); });
test('watermark markers are stable per session and attribution decodes', async () => { const projectId = 'project_watermark_test'; const context = { projectId, sessionId: 'session-stable-1', userId: 'user-42', ip: '203.0.113.20' }; const markerA = await createInvisibleWatermarkMarker(context); const markerB = await createInvisibleWatermarkMarker(context); assert.equal(markerA, markerB); const decoded = await decodeInvisibleWatermark(`A${markerA}B`, projectId); assert.equal(decoded.found, true); assert.equal(decoded.attributed, true); assert.equal(decoded.userId, 'user-42'); });
test('watermarking touches safe display text but preserves IDs, emails and credentials', async () => { const marker = await createInvisibleWatermarkMarker({ projectId: 'watermark-field-test', sessionId: 'session-1', userId: 'user-1' }); const original = { data: [{ id: 'order-123', email: 'person@example.com', title: 'Invoice', api_token: 'secret-token' }] }; const marked = watermarkPayloadWithMarker(original, marker); assert.equal(marked.data[0].id, 'order-123'); assert.equal(marked.data[0].email, 'person@example.com'); assert.equal(marked.data[0].api_token, 'secret-token'); assert.notEqual(marked.data[0].title, 'Invoice'); assert.equal(original.data[0].title, 'Invoice'); });


test('WAF canonicalizes nested encodings and removes SQL comments before grammar tokenization', () => {
  const canonical = canonicalizeSecurityText('%2527%2520UN%252F%252Acomment%252A%252FION%2520%252F%252A!50000SELECT%252A%252F');
  assert.match(canonical.value.toUpperCase(), /UN ION SELECT/);
  const result = inspectRequest({ method: 'POST', url: '/api/search', headers: { 'content-type': 'application/json' }, body: { q: "' OR 1=1 --" } });
  assert.ok(result.findings.some((finding) => finding.id === 'SQLI_GRAMMAR' || finding.id === 'SQLI_BOOLEAN'));
});

test('WAF scans beyond the standard cutoff when a route explicitly allows a larger payload', () => {
  const body = { query: `${'a'.repeat(34000)} ' OR 1=1 --` };
  const standard = inspectRequest({ method: 'POST', url: '/upload', headers: { 'content-type': 'application/json' }, body, contentLength: 34000 });
  const largeRoute = inspectRequest({ method: 'POST', url: '/upload', headers: { 'content-type': 'application/json' }, body, contentLength: 34000, maxBodyBytes: 262144, maxLeafBytes: 65536, allowedLongFields: ['query'] });
  assert.ok(standard.findings.some((finding) => finding.id === 'BODY_SIZE'));
  assert.ok(largeRoute.findings.some((finding) => finding.category === 'SQL_INJECTION'));
});

test('WAF rejects NoSQL operator and prototype-pollution object keys structurally', () => {
  for (const body of [{ filter: { $gt: '' } }, { constructor: { prototype: { polluted: true } } }, { 'profile.name': 'Alice' }]) {
    const result = inspectRequest({ method: 'POST', url: '/api/search', headers: { 'content-type': 'application/json' }, body });
    assert.ok(result.findings.some((finding) => finding.id === 'NOSQL_OPERATOR' || finding.id === 'PROTOTYPE_POLLUTION' || finding.id === 'DOTTED_OBJECT_KEY'));
  }
});

test('HMAC capability IDs bind to the authenticated subject and reject unsealed or foreign IDs', () => {
  process.env.ARIX_MASTER_SECRET = 'A'.repeat(48);
  const sealed = sealResourceId('1055', 'user-a');
  assert.match(sealed, /^1055~[a-f0-9]{32}$/);
  assert.equal(verifyResourceId(sealed, 'user-a'), '1055');
  assert.equal(verifyResourceId(sealed, 'user-b'), null);
  assert.deepEqual(rewriteCapabilityPath(`/api/orders/${sealed}`, 'user-a'), { url: '/api/orders/1055', invalid: false });
  assert.deepEqual(rewriteCapabilityPath(`/api/orders/${sealed}/items`, 'user-a'), { url: '/api/orders/1055/items', invalid: false });
  assert.equal(rewriteCapabilityPath('/api/orders/1055', 'user-a').invalid, true);
  assert.equal(rewriteCapabilityPath('/api/orders/1055/items', 'user-a').invalid, true);
  assert.equal(rewriteCapabilityPath('/api/orders/c123456789012345678901234/items', 'user-a', { idPattern: /^c[a-z0-9]{24}$/i }).invalid, true);
  assert.equal(rewriteCapabilityPath(`/api/orders/${sealed}`, 'user-b').invalid, true);
  assert.equal(sealResourceIdsInPayload({ data: [{ id: 1055 }] }, 'user-a').data[0].id, sealed);
  assert.ok(findOwnershipMismatch({ data: [{ userId: 'user-b' }] }, 'user-a'));
});

test('verified HMAC capability request reports a seal and may skip BOLA velocity', () => {
  process.env.ARIX_MASTER_SECRET = 'A'.repeat(48);
  const sealed = sealResourceId('3001', 'reader-capability');
  const rewritten = rewriteCapabilityRequest(`/api/orders/${sealed}`, null, 'reader-capability', { method: 'GET' });
  assert.equal(rewritten.invalid, false);
  assert.equal(rewritten.capabilityVerified, true);
  assert.equal(rewritten.verifiedResourceIds, 1);
  assert.equal(rewritten.url, '/api/orders/3001');
});

test('BOLA detector watches successful sequential IDs as well as denied IDs', async () => {
  const projectId = 'test-bola-success-project';
  let outcome;
  for (let id = 3001; id <= 3003; id++) outcome = await recordRequestOutcome({ projectId, actorId: 'reader-1', path: `/api/items/${id}`, method: 'GET', status: 200 });
  assert.equal(outcome.bolaObserved, true);
  assert.equal(outcome.bolaTriggered, false);
  assert.equal(outcome.sequentialHits, 2);
  assert.equal((await isActorBackedOff(projectId, 'reader-1')).blocked, false);
});


test('ban snapshot index helpers read active values and remove stale set members', async () => {
  const key = `arix:test:ban-index:${Date.now()}`;
  await setAdd(key, 'active-hash', 60);
  await setAdd(key, 'stale-hash', 60);
  assert.deepEqual(await getStrings('arix:test:missing-value'), [null]);
  assert.deepEqual((await setMembers(key)).sort(), ['active-hash', 'stale-hash']);
  assert.equal(await setCard(key), 2);
  await setRemoveMany(key, ['stale-hash']);
  assert.deepEqual(await setMembers(key), ['active-hash']);
});


test('chameleon canaries preserve numeric ID schema and register exposed identifiers for attribution', async () => {
  process.env.ARIX_MASTER_SECRET = 'A'.repeat(48);
  const projectId = `chameleon-numeric-${Date.now()}`;
  const canaryId = await createChameleonCanaryId(projectId, 'session-numeric');
  const attribution = { sessionIdHash: 'a'.repeat(64), userId: 'user-17', ip: '203.0.113.17' };
  await storeChameleonCanary(projectId, canaryId, attribution);
  const payload = { data: Array.from({ length: 10 }, (_, index) => ({ id: index + 1, name: `Client ${index}`, email: `client${index}@acme.test`, createdAt: '2025-04-01T00:00:00.020Z', active: true })) };
  const output = await spliceCanaryRow(payload, { projectId, sessionId: 'session-numeric' }, true, canaryId);
  assert.equal(output.data.length, 11);
  const inserted = output.data[5];
  assert.deepEqual(Object.keys(inserted), Object.keys(payload.data[0]));
  assert.equal(typeof inserted.id, 'number');
  assert.ok(Number.isSafeInteger(inserted.id));
  assert.notEqual(inserted.id, payload.data[0].id);
  const serialized = JSON.stringify(inserted);
  assert.doesNotMatch(serialized, /ArixShield|canary|synthetic|example\.invalid/i);
  const identifier = getChameleonRowIdentifier(inserted);
  await storeChameleonExposedId(projectId, canaryId, String(identifier.value));
  const recovered = await lookupChameleonCanaryByExposedId(projectId, String(identifier.value));
  assert.equal(recovered?.userId, attribution.userId);
  assert.equal(recovered?.sessionIdHash, attribution.sessionIdHash);
});

test('chameleon canaries preserve UUID field shape and reject rows without stable identifiers', async () => {
  process.env.ARIX_MASTER_SECRET = 'B'.repeat(48);
  const projectId = `chameleon-uuid-${Date.now()}`;
  const canaryId = await createChameleonCanaryId(projectId, 'session-uuid');
  const template = { uuid: '7c9e6679-7425-40de-944b-e07fc1f90ae7', displayName: 'Example Person', createdAt: '2025-04-01T00:00:00.020Z' };
  const payload = { data: Array.from({ length: 10 }, (_, index) => ({ ...template, uuid: `7c9e6679-7425-40de-944b-e07fc1f90a${String(index).padStart(2, '0')}` })) };
  const output = await spliceCanaryRow(payload, { projectId }, true, canaryId);
  const inserted = output.data[5];
  assert.match(inserted.uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$/i);
  assert.deepEqual(Object.keys(inserted), Object.keys(template));
  const noId = { data: Array.from({ length: 10 }, () => ({ name: 'Person', email: 'person@example.org' })) };
  assert.equal(await spliceCanaryRow(noId, { projectId }, true, canaryId), noId);
});

test('real-time audit HMAC chain is sequential and snapshot-verifiable', async () => {
  process.env.ARIX_MASTER_SECRET = 'C'.repeat(48);
  const projectId = `audit-chain-${Date.now()}`;
  const first = await recordAuditChainEvent(projectId, { type: 'SECURITY_TEST_EVENT', value: 1 });
  const second = await recordAuditChainEvent(projectId, { type: 'SECURITY_TEST_EVENT', value: 2 });
  assert.equal(first.seq, 1);
  assert.equal(second.seq, 2);
  assert.equal(second.prevChainMac, first.chainMac);
  const snapshot = await getAuditChainSnapshot(projectId, 10);
  assert.equal(snapshot.verified, true);
  assert.equal(snapshot.sequence, 2);
  assert.equal(snapshot.head, second.chainMac);
  assert.equal(snapshot.rows.length, 2);
});


test('cross-endpoint correlation challenges the subnet and backs off an actor at the 65-point threshold', async () => {
  const projectId = `risk-correlation-${Date.now()}`;
  const ip = '198.51.100.44';
  const actorHash = await sha256Hex(`${projectId}:risk-actor`);
  await recordThreatCorrelation(projectId, actorHash, ip, 20, 'WAF_SEARCH_WARNING');
  await recordThreatCorrelation(projectId, actorHash, ip, 25, 'ADMIN_ROUTE_404');
  const threshold = await recordThreatCorrelation(projectId, actorHash, ip, 20, 'LOGIN_ROUTE');
  assert.equal(threshold.actorScore, 65);
  assert.equal(threshold.subnetScore, 65);
  const actor = await isActorBackedOff(projectId, 'risk-actor', ip);
  assert.equal(actor.blocked, true);
  assert.equal(actor.reason, 'CROSS_ENDPOINT_RISK_THRESHOLD');
  const sameSubnetPeer = await isActorBackedOff(projectId, 'unrelated-peer', ip);
  assert.equal(sameSubnetPeer.blocked, false);
  assert.equal(sameSubnetPeer.challenge, true);
  assert.equal(sameSubnetPeer.subnetScore, 65);
});

test('threat-feed confidence halves after 24 hours and stale-feed status is exposed', async () => {
  const now = Date.now();
  const staleAt = new Date(now - 25 * 60 * 60 * 1000).toISOString();
  await setJson('arix:threat-feed:spamhaus-drop-v4', { name: 'spamhaus-drop-v4', cidrs: ['198.51.100.0/24'], sourceCount: 1, fetchedAt: staleAt, expiresAt: now + 23 * 60 * 60 * 1000 }, 9 * 24 * 60 * 60);
  await setJson('arix:threat-feed:spamhaus-drop-v6', { name: 'spamhaus-drop-v6', cidrs: [], sourceCount: 0, fetchedAt: staleAt, expiresAt: now + 23 * 60 * 60 * 1000 }, 9 * 24 * 60 * 60);
  for (const name of ['firehol-level1', 'tor-exit']) await setJson(`arix:threat-feed:${name}`, { name, cidrs: [], sourceCount: 0, fetchedAt: staleAt, expiresAt: now + 23 * 60 * 60 * 1000 }, 9 * 24 * 60 * 60);
  globalThis.__ARIX_REPUTATION_CACHE__.at = 0;
  const reputation = await checkIpReputation('198.51.100.44');
  assert.equal(reputation.threatConfidence, 42);
  assert.equal(reputation.action, 'challenge');
  const status = await getThreatFeedStatus();
  assert.equal(status.warning, true);
  assert.ok(status.staleFeeds.includes('spamhaus-drop-v4'));
});
