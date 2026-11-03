import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalizeSecurityText, inspectRequest, validateJsonSchema } from '../api/_lib/waf-engine.js';

const findingIds = (result) => new Set(result.findings.map((finding) => finding.id));

test('WAF rejects non-finite values in materialized JSON and overflow literals in raw JSON', () => {
  const parsed = JSON.parse('{"amount":1e309}');
  assert.equal(Number.isFinite(parsed.amount), false);

  const materialized = inspectRequest({
    method: 'POST',
    url: '/payments',
    headers: { 'content-type': 'application/json' },
    body: parsed
  });
  assert.equal(materialized.allowed, false);
  assert.ok(findingIds(materialized).has('JSON_NON_FINITE_NUMBER'));

  const raw = inspectRequest({
    method: 'POST',
    url: '/payments',
    headers: { 'content-type': 'application/json' },
    rawBody: Buffer.from('{"amount":1e309}')
  });
  assert.equal(raw.allowed, false);
  assert.ok(findingIds(raw).has('JSON_NON_FINITE_NUMBER'));

  const root = inspectRequest({ method: 'POST', url: '/number', body: Infinity });
  assert.equal(root.allowed, false);
  assert.ok(findingIds(root).has('JSON_NON_FINITE_NUMBER'));
});

test('JSON schema validation rejects non-finite numbers but preserves finite negative zero', () => {
  assert.equal(validateJsonSchema(Infinity, { type: 'number' }).valid, false);
  assert.equal(validateJsonSchema(-0, { type: 'number' }).valid, true);
});

test('NFKC fast path preserves stable Unicode and still folds compatibility and combining forms', () => {
  const stable = 'ordinary text é 🔐 remains stable';
  assert.equal(canonicalizeSecurityText(stable).value, stable);
  assert.equal(canonicalizeSecurityText('０Ｒ 1=1').value, '0R 1=1');
  assert.equal(canonicalizeSecurityText('e\u0301').value, 'é');
});
