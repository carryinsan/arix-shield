import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectRequest, canonicalizeSecurityText } from '../api/_lib/waf-engine.js';

const attacks = [
  { name: 'Content-Length plus Transfer-Encoding', request: { headers: { 'content-length': '12', 'transfer-encoding': 'chunked' } }, finding: 'HTTP_SMUGGLING_HEADERS' },
  { name: 'duplicate Content-Length raw fields', request: { rawHeaders: ['Content-Length', '4', 'content-length', '9'] }, finding: 'DUPLICATE_HEADER' },
  { name: 'duplicate Host raw fields', request: { rawHeaders: ['Host', 'a.example.test', 'host', 'b.example.test'] }, finding: 'DUPLICATE_HEADER' },
  { name: 'HTTP/2 Transfer-Encoding', request: { httpVersion: '2.0', headers: { 'transfer-encoding': 'chunked' } }, finding: 'HTTP2_CONNECTION_SPECIFIC_HEADER' },
  { name: 'HTTP/3 Connection header', request: { httpVersion: '3.0', headers: { connection: 'keep-alive' } }, finding: 'HTTP2_CONNECTION_SPECIFIC_HEADER' },
  { name: 'CRLF in field value', request: { headers: { 'x-comment': 'a\r\nX-Role: admin' } }, finding: 'HTTP_HEADER_INJECTION' },
  { name: 'invalid header token', request: { headers: { 'bad name': 'x' } }, finding: 'HTTP_HEADER_INJECTION' },
  { name: 'method override', request: { headers: { 'x-http-method-override': 'DELETE' } }, finding: 'METHOD_OVERRIDE' },
  { name: 'duplicate query names', request: { url: '/api?tenant=mine&tenant=victim' }, finding: 'HTTP_PARAMETER_POLLUTION' },
  { name: 'invalid URL encoding in path', request: { url: '/files/%E0%A4%A' }, finding: 'URL_PATH_NORMALIZATION' }
];

test('HTTP parser differential corpus is rejected or explicitly surfaced', () => {
  for (const item of attacks) {
    const result = inspectRequest({ method: 'POST', url: '/', headers: { 'content-type': 'text/plain', ...(item.request.headers || {}) }, body: 'x', production: true, ...item.request });
    assert.ok(result.findings.some((finding) => finding.id === item.finding), `${item.name}: expected ${item.finding}, got ${result.findings.map((f) => f.id).join(',')}`);
    assert.equal(result.allowed, false, `${item.name} should be rejected`);
  }
});

test('canonicalization is bounded and flags still-changing nested encodings', () => {
  let value = '%25252525253Cscript%25252525253E';
  const output = canonicalizeSecurityText(value);
  assert.equal(output.passes, 3);
  assert.equal(output.excessiveEncoding, true);
  assert.ok(output.value.length > 0);
});

test('documented HTTP syntax remains parseable without creating contradictory framing', () => {
  const result = inspectRequest({ method: 'POST', url: '/api/records', headers: { 'content-type': 'application/json', 'content-length': '17' }, body: { title: 'safe' }, production: true });
  assert.equal(result.findings.some((finding) => finding.id === 'HTTP_SMUGGLING_HEADERS'), false);
});
