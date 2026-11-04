import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { readBoundedResponseBody, arixSafeFetch } from '../sdk/safe-fetch.js';
import { installProcessEgressFirewall } from '../sdk/process-egress-firewall.js';

test('process fetch egress guard routes URL fetches through the injected safe transport and restores cleanly', async () => {
  const calls = [];
  const original = async () => new Response('unguarded');
  const target = { fetch: original };
  const guard = installProcessEgressFirewall({
    target,
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return new Response('guarded', { status: 200 });
    },
    allowedPorts: [443, 8443]
  });
  assert.equal(guard.active, true);
  assert.equal(installProcessEgressFirewall({ target, fetchImpl: async () => new Response('other') }), guard);
  const response = await target.fetch('https://api.example.test/v1', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{"ok":true}'
  });
  assert.equal(await response.text(), 'guarded');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://api.example.test/v1');
  assert.equal(calls[0].options.method, 'POST');
  assert.equal(Buffer.from(calls[0].options.body).toString(), '{"ok":true}');
  assert.deepEqual(calls[0].options.allowedPorts, [443, 8443]);
  assert.equal(guard.uninstall(), true);
  assert.equal(target.fetch, original);
  assert.equal(guard.uninstall(), false);
});


test('process fetch egress guard forwards the configured response byte ceiling', async () => {
  let captured;
  const target = { fetch: async () => new Response('original') };
  const guard = installProcessEgressFirewall({
    target,
    maxResponseBytes: 1024,
    safeFetch: async (url, options) => {
      captured = { url, options };
      return new Response('ok');
    }
  });
  await target.fetch('https://api.example.test/limited');
  assert.equal(captured.options.maxResponseBytes, 1024);
  guard.uninstall();
});

test('safe fetch response reader enforces configured streaming byte ceilings', async () => {
  const exactResponse = Readable.from([Buffer.alloc(512, 0x61), Buffer.alloc(512, 0x62)]);
  exactResponse.headers = {};
  const exact = await readBoundedResponseBody(exactResponse, { destroy() {} }, 1024);
  assert.equal(exact.length, 1024);

  const tooLargeResponse = Readable.from([Buffer.alloc(700), Buffer.alloc(325)]);
  tooLargeResponse.headers = {};
  let destroyed = false;
  await assert.rejects(
    readBoundedResponseBody(tooLargeResponse, { destroy() { destroyed = true; } }, 1024),
    /configured 1024-byte limit/
  );
  assert.equal(destroyed, true, 'oversized response aborts the underlying request');

  const declaredLargeResponse = Readable.from([]);
  declaredLargeResponse.headers = { 'content-length': '2048' };
  await assert.rejects(
    readBoundedResponseBody(declaredLargeResponse, { destroy() {} }, 1024),
    /configured 1024-byte limit/
  );
});

test('safe fetch validates direct maxResponseBytes configuration before network access', async () => {
  await assert.rejects(arixSafeFetch('https://example.com/', { maxResponseBytes: 1023 }), /maxResponseBytes/);
  await assert.rejects(arixSafeFetch('https://example.com/', { maxResponseBytes: 8 * 1024 * 1024 + 1 }), /maxResponseBytes/);
});

test('process fetch egress guard supports Request inputs and enforces method policy', async () => {
  let captured;
  const target = { fetch: async () => new Response('original') };
  const guard = installProcessEgressFirewall({
    target,
    fetchImpl: async (url, options) => {
      captured = { url, options };
      return new Response('ok');
    }
  });
  const request = new Request('https://api.example.test/items', {
    method: 'PUT', headers: { 'content-type': 'text/plain' }, body: 'value'
  });
  await target.fetch(request);
  assert.equal(captured.url, request.url);
  assert.equal(captured.options.method, 'PUT');
  assert.equal(Buffer.from(captured.options.body).toString(), 'value');
  await assert.rejects(() => target.fetch('https://api.example.test/items', { method: 'TRACE' }), /method is not allowed/i);
  guard.uninstall();
});

test('process fetch egress guard refuses oversized request streams before invoking transport', async () => {
  let invoked = false;
  const target = { fetch: async () => new Response('original') };
  const guard = installProcessEgressFirewall({
    target,
    maxRequestBytes: 4,
    fetchImpl: async () => { invoked = true; return new Response('unexpected'); }
  });
  const request = new Request('https://api.example.test/upload', { method: 'POST', body: '12345' });
  await assert.rejects(() => target.fetch(request), /body exceeds/i);
  assert.equal(invoked, false);
  guard.uninstall();
});

test('process fetch egress guard configuration fails closed', () => {
  assert.throws(() => installProcessEgressFirewall({ target: {}, fetchImpl: async () => new Response() }), /does not provide fetch/i);
  assert.throws(() => installProcessEgressFirewall({ target: { fetch() {} }, allowedPorts: [] }), /allowedPorts/i);
  assert.throws(() => installProcessEgressFirewall({ target: { fetch() {} }, maxRequestBytes: 1_048_577 }), /maxRequestBytes/i);
});

test('default process fetch guard blocks loopback and cleartext HTTP destinations', async () => {
  const target = { fetch: async () => new Response('original') };
  const guard = installProcessEgressFirewall({ target });
  await assert.rejects(() => target.fetch('http://127.0.0.1:1/internal'), /only credential-free HTTPS/i);
  guard.uninstall();
});
