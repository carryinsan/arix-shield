import { inspectRequest } from './waf-engine.js';
import { verifyRequestDpopProof, rewriteCapabilityPath } from './crypto-trap.js';

/** Small deterministic canary suite; it tests controls in memory and makes no network calls. */
export async function runSecuritySelfTest() {
  const results = [];
  const check = (name, passed, detail = '') => results.push({ name, passed: Boolean(passed), ...(detail ? { detail: String(detail).slice(0, 160) } : {}) });
  const vectors = [
    ['/search?q=%27%20OR%201%3D1%20--', 'SQLI_BOOLEAN'],
    ['/api?q=UNION%20SELECT%20password%20FROM%20users', 'SQLI_UNION'],
    ['/x?q=%253Cscript%253Ealert(1)%253C/script%253E', 'XSS_SCRIPT'],
    ['/x?foo=1&foo=2', 'HTTP_PARAMETER_POLLUTION'],
    ['/api?q=%2527%2520OR%25201%253D1%2520--', 'SQLI_BOOLEAN'],
    ['/api?x=%00', 'NULL_BYTE']
  ];
  for (const [url, expected] of vectors) {
    const result = inspectRequest({ method: 'GET', url, headers: {}, production: true });
    check(`waf:${expected}`, result.findings.some((finding) => finding.id === expected));
  }
  const prototype = inspectRequest({ method: 'POST', url: '/api/profile', headers: { 'content-type': 'application/json' }, body: JSON.parse('{"__proto__":{"polluted":true}}'), production: true });
  check('waf:PROTOTYPE_POLLUTION', prototype.findings.some((finding) => finding.id === 'PROTOTYPE_POLLUTION'));
  const duplicate = inspectRequest({ method: 'POST', url: '/api/data', headers: { 'content-type': 'application/json' }, rawBody: '{"role":"user","role":"admin"}', production: true });
  check('waf:JSON_DUPLICATE_KEY', duplicate.findings.some((finding) => finding.id === 'JSON_DUPLICATE_KEY'));
  const dpop = await verifyRequestDpopProof({ proof: 'malformed.proof.value', method: 'GET', url: 'https://example.invalid/', bodyBytes: new Uint8Array() });
  check('dpop:malformed-proof-rejected', dpop.valid === false);
  const capability = rewriteCapabilityPath('/api/users/123', null, { requireSealed: true, method: 'GET' });
  check('capability:unsealed-id-rejected', capability.invalid === true);
  const passed = results.every((result) => result.passed);
  return { passed, total: results.length, failed: results.filter((result) => !result.passed), results, checkedAt: new Date().toISOString() };
}
