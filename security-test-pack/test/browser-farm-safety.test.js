import test from 'node:test';
import assert from 'node:assert/strict';
import { assertLabTarget } from '../scripts/run-browser-farm.mjs';

test('browser farm only permits localhost, loopback, and reserved .test origins', () => {
  assert.equal(assertLabTarget('http://localhost:3000').hostname, 'localhost');
  assert.equal(assertLabTarget('https://127.0.0.1:8443').hostname, '127.0.0.1');
  assert.equal(assertLabTarget('https://arix-staging.test').hostname, 'arix-staging.test');
  assert.throws(() => assertLabTarget('https://example.com'), /public targets are refused/);
  assert.throws(() => assertLabTarget('https://user:pass@localhost'), /Credentials must not/);
  assert.throws(() => assertLabTarget('file:///etc/passwd'), /absolute URL|must be/);
});
