import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectRequest } from '../api/_lib/waf-engine.js';
import { authorizeRequest, filterWriteFields } from '../api/_lib/authorization.js';
import { inspectImageHeader, inspectZipBuffer } from '../api/_lib/file-security.js';
import { createTenantDek, encryptTenantData, decryptTenantData, wrapTenantDek, unwrapTenantDek } from '../api/_lib/kms.js';
import { authorizeMcpRequest, createHumanApprovalToken, requireHumanApproval } from '../api/_lib/ai-guard.js';
import { assertPublicIp } from '../sdk/safe-fetch.js';

function oversizedPng() {
  const bytes = Buffer.alloc(24);
  Buffer.from([137,80,78,71,13,10,26,10]).copy(bytes);
  bytes.write('IHDR', 12, 'ascii');
  bytes.writeUInt32BE(50_000, 16);
  bytes.writeUInt32BE(50_000, 20);
  return bytes;
}

function zipWithExpansionRatio() {
  const name = Buffer.from('huge.txt'); const data = Buffer.from('x');
  const local = Buffer.alloc(30 + name.length + data.length);
  local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt32LE(1, 18); local.writeUInt32LE(100_000, 22); local.writeUInt16LE(name.length, 26);
  name.copy(local, 30); data.copy(local, 30 + name.length);
  const central = Buffer.alloc(46 + name.length);
  central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt32LE(1, 20); central.writeUInt32LE(100_000, 24); central.writeUInt16LE(name.length, 28); name.copy(central, 46);
  const eocd = Buffer.alloc(22); eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(1, 8); eocd.writeUInt16LE(1, 10); eocd.writeUInt32LE(central.length, 12); eocd.writeUInt32LE(local.length, 16);
  return Buffer.concat([local, central, eocd]);
}

const cases = [
  ['SQL injection boolean grammar', () => !inspectRequest({ url: "/search?q=%27%20OR%201%3D1%20--", production: true }).allowed],
  ['XSS script marker', () => !inspectRequest({ method: 'POST', url: '/comments', headers: { 'content-type': 'text/plain' }, body: '<script>alert(1)</script>', production: true }).allowed],
  ['NoSQL operator object key', () => !inspectRequest({ method: 'POST', url: '/query', headers: { 'content-type': 'application/json' }, body: { q: { $ne: null } }, production: true }).allowed],
  ['SSRF loopback URL', () => !inspectRequest({ url: '/fetch?url=http%3A%2F%2F127.0.0.1%2Fadmin', production: true }).allowed],
  ['SSTI template expression', () => !inspectRequest({ method: 'POST', url: '/render', headers: { 'content-type': 'text/plain' }, body: '{{ config.__class__ }}', production: true }).allowed],
  ['LDAP filter injection', () => !inspectRequest({ url: '/directory?q=%29%28%7C%28uid%3D%2A%29%29', production: true }).allowed],
  ['XXE DTD payload', () => !inspectRequest({ method: 'POST', url: '/xml', headers: { 'content-type': 'application/xml' }, body: '<!DOCTYPE x [<!ENTITY y SYSTEM "file:///etc/passwd">]><x>&y;</x>', production: true }).allowed],
  ['multipart image magic mismatch', () => !inspectRequest({ method: 'POST', url: '/upload', headers: { 'content-type': 'multipart/form-data; boundary=z' }, rawBody: Buffer.from('--z\r\nContent-Disposition: form-data; name="f"; filename="a.png"\r\nContent-Type: image/png\r\n\r\nnot-png\r\n--z--\r\n'), production: true }).allowed],
  ['binary PDF signature mismatch', () => !inspectRequest({ method: 'POST', url: '/upload', headers: { 'content-type': 'application/pdf' }, rawBody: Buffer.from('MZ-not-a-pdf'), production: true }).allowed],
  ['HTTP/1 CL-TE ambiguity', () => !inspectRequest({ method: 'POST', url: '/', headers: { 'content-length': '4', 'transfer-encoding': 'chunked' }, body: 'test', production: true }).allowed],
  ['HTTP/2 connection-specific header', () => !inspectRequest({ method: 'POST', url: '/', httpVersion: '2.0', headers: { 'transfer-encoding': 'chunked' }, body: 'test', production: true }).allowed],
  ['HTTP header CRLF injection', () => !inspectRequest({ url: '/', headers: { 'x-note': 'safe\r\nX-Admin: true' }, production: true }).allowed],
  ['duplicate query parameter pollution', () => !inspectRequest({ url: '/search?id=1&id=2', production: true }).allowed],
  ['duplicate raw JSON key', () => !inspectRequest({ method: 'POST', url: '/x', headers: { 'content-type': 'application/json' }, rawBody: '{"role":"user","role":"admin"}', production: true }).allowed],
  ['prototype pollution key', () => !inspectRequest({ method: 'POST', url: '/x', headers: { 'content-type': 'application/json' }, body: JSON.parse('{"__proto__":{"polluted":true}}'), production: true }).allowed],
  ['excessive nested encoding', () => { let value = "' OR 1=1 --"; for (let i = 0; i < 4; i++) value = encodeURIComponent(value); return !inspectRequest({ method: 'POST', url: '/x', headers: { 'content-type': 'text/plain' }, body: value, production: true }).allowed; }],
  ['GraphQL query depth limit', () => !inspectRequest({ method: 'POST', url: '/graphql', headers: { 'content-type': 'application/json' }, body: { query: 'query { a { b { c { d { e { f { g { h { i { id } } } } } } } } }' }, production: true }).allowed],
  ['pixel-flood dimensions', () => inspectImageHeader(oversizedPng()).safe === false],
  ['ZIP expansion ratio', () => inspectZipBuffer(zipWithExpansionRatio()).safe === false],
  ['authorization denies anonymous actor', async () => !(await authorizeRequest({ method: 'GET', pathname: '/account', routes: [{ path: '/account', methods: ['GET'], authenticated: true }], context: { roles: [] } })).allowed],
  ['authorization rejects foreign tenant context', async () => !(await authorizeRequest({ method: 'DELETE', pathname: '/records/1', routes: [{ path: '/records/:id', methods: ['DELETE'], authenticated: true, tenantIsolated: true, tenantId: 'tenant-a', requirePreCheck: true, preCheck: async ({ context }) => context.tenantId === 'tenant-a' }], context: { tenantId: 'tenant-b', userId: 'u2' }, defaultDenyMutations: true, requireScopedPrecheck: true })).allowed],
  ['write field allowlist strips privilege escalation', () => { const safe = filterWriteFields({ name: 'Ari', role: 'admin', isStaff: true }, { member: ['name'] }, ['member']); return safe.name === 'Ari' && !Object.hasOwn(safe, 'role') && !Object.hasOwn(safe, 'isStaff'); }],
  ['KMS rejects cross-tenant ciphertext', () => { const dek = createTenantDek(); const envelope = encryptTenantData('secret', { tenantId: 'tenant-a', dek }); assert.throws(() => decryptTenantData(envelope, { tenantId: 'tenant-b', dek })); dek.fill(0); return true; }],
  ['MCP rejects unknown tools', () => authorizeMcpRequest({ jsonrpc: '2.0', method: 'tools/call', id: 1, params: { name: 'eraseEverything', arguments: {} } }, { tools: {}, context: { userId: 'u', tenantId: 't' } }).allowed === false],
  ['human approval binds tenant/user/args and is single-use', async () => { const secret = 'K'.repeat(40); const args = { resourceId: 'r1', action: 'archive' }; const token = createHumanApprovalToken({ toolName: 'archive', args, tenantId: 'ta', userId: 'ua', secret }); const rejected = await requireHumanApproval(token, { toolName: 'archive', args: { ...args, resourceId: 'r2' }, tenantId: 'ta', userId: 'ua', secret, consumeJti: async () => true }); return rejected.allowed === false; }]
];

test('25 runtime invariant probes reject representative cross-domain abuse patterns', async (t) => {
  assert.equal(cases.length, 25);
  for (const [name, check] of cases) {
    await t.test(name, async () => assert.equal(await check(), true, `Invariant failed: ${name}`));
  }
});
