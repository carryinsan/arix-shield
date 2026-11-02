import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { generateKeyPairSync } from 'node:crypto';
import { createEdgeGatewayServer } from '../edge/gateway.mjs';
import { createCompatibleHandler } from '../api/_lib/vercel-handler.js';
import { readJson } from '../api/_lib/http.js';

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}
function close(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

test('edge gateway signs exact raw requests and origin adapter verifies and consumes proof', async (t) => {
  const original = {
    key: process.env.ARIX_ORIGIN_PUBLIC_KEY,
    required: process.env.ARIX_ORIGIN_LOCK_REQUIRED,
    nodeEnv: process.env.NODE_ENV,
    redisUrl: process.env.UPSTASH_REDIS_REST_URL,
    redisToken: process.env.UPSTASH_REDIS_REST_TOKEN
  };
  process.env.NODE_ENV = 'test';
  delete process.env.UPSTASH_REDIS_REST_URL;
  delete process.env.UPSTASH_REDIS_REST_TOKEN;
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  process.env.ARIX_ORIGIN_PUBLIC_KEY = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  process.env.ARIX_ORIGIN_LOCK_REQUIRED = 'true';

  const origin = http.createServer(createCompatibleHandler(async (req, res) => {
    const data = await readJson(req, 4096);
    res.statusCode = 200;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ data, raw: req.rawBody.toString('utf8'), clientIp: req.headers['x-arix-client-ip'], hasForwarded: Boolean(req.headers['x-forwarded-for']) }));
  }, { maxBodyBytes: 4096 }));
  const originPort = await listen(origin);
  const gateway = createEdgeGatewayServer({
    upstreamUrl: `http://127.0.0.1:${originPort}/`,
    privateKey,
    allowInsecureUpstream: true,
    maxBodyBytes: 4096,
    maxConcurrentRequests: 8,
    maxBufferedBytes: 1048576
  });
  const gatewayPort = await listen(gateway);
  t.after(async () => {
    await close(gateway);
    await close(origin);
    if (original.key === undefined) delete process.env.ARIX_ORIGIN_PUBLIC_KEY; else process.env.ARIX_ORIGIN_PUBLIC_KEY = original.key;
    if (original.required === undefined) delete process.env.ARIX_ORIGIN_LOCK_REQUIRED; else process.env.ARIX_ORIGIN_LOCK_REQUIRED = original.required;
    if (original.nodeEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = original.nodeEnv;
    if (original.redisUrl === undefined) delete process.env.UPSTASH_REDIS_REST_URL; else process.env.UPSTASH_REDIS_REST_URL = original.redisUrl;
    if (original.redisToken === undefined) delete process.env.UPSTASH_REDIS_REST_TOKEN; else process.env.UPSTASH_REDIS_REST_TOKEN = original.redisToken;
  });

  const raw = '{"message":"edge proof works","count":3}';
  const response = await fetch(`http://127.0.0.1:${gatewayPort}/api/check?mode=exact`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-forwarded-for': '198.51.100.99',
      'x-arix-origin-proof': 'attacker-controlled'
    },
    body: raw
  });
  assert.equal(response.status, 200);
  const value = await response.json();
  assert.deepEqual(value.data, { message: 'edge proof works', count: 3 });
  assert.equal(value.raw, raw);
  assert.equal(value.clientIp, '127.0.0.1');
  assert.equal(value.hasForwarded, false);

  const oversized = await fetch(`http://127.0.0.1:${gatewayPort}/api/check`, {
    method: 'POST', headers: { 'content-type': 'application/octet-stream' }, body: Buffer.alloc(4097)
  });
  assert.equal(oversized.status, 413);

  const duplicateHeaderResponse = await new Promise((resolve, reject) => {
    const socket = net.connect(gatewayPort, '127.0.0.1');
    let responseText = '';
    socket.setTimeout(3000, () => socket.destroy(new Error('Duplicate-header test timed out.')));
    socket.once('connect', () => socket.write('POST /duplicate HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'));
    socket.on('data', (chunk) => { responseText += chunk.toString('latin1'); });
    socket.once('end', () => resolve(responseText));
    socket.once('error', reject);
  });
  assert.match(duplicateHeaderResponse, /^HTTP\/1\.1 400 /);
});

test('origin adapter fails closed for direct requests and rejects a replayed edge proof', async (t) => {
  const originalKey = process.env.ARIX_ORIGIN_PUBLIC_KEY;
  const originalRequired = process.env.ARIX_ORIGIN_LOCK_REQUIRED;
  const originalNodeEnv = process.env.NODE_ENV;
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  process.env.NODE_ENV = 'test';
  process.env.ARIX_ORIGIN_PUBLIC_KEY = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  process.env.ARIX_ORIGIN_LOCK_REQUIRED = 'true';
  const origin = http.createServer(createCompatibleHandler(async (_req, res) => { res.statusCode = 200; res.end('reached'); }));
  const port = await listen(origin);
  t.after(async () => {
    await close(origin);
    if (originalKey === undefined) delete process.env.ARIX_ORIGIN_PUBLIC_KEY; else process.env.ARIX_ORIGIN_PUBLIC_KEY = originalKey;
    if (originalRequired === undefined) delete process.env.ARIX_ORIGIN_LOCK_REQUIRED; else process.env.ARIX_ORIGIN_LOCK_REQUIRED = originalRequired;
    if (originalNodeEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = originalNodeEnv;
  });

  const direct = await fetch(`http://127.0.0.1:${port}/private`);
  assert.equal(direct.status, 403);

  const { createOriginProof } = await import('../api/_lib/origin-lock.js');
  const nonce = Buffer.alloc(16, 7).toString('base64url');
  const body = Buffer.from('{"x":1}');
  const proof = createOriginProof({ privateKey, timestamp: Date.now(), nonce, method: 'POST', url: '/private', clientIp: '127.0.0.1', body });
  const send = () => fetch(`http://127.0.0.1:${port}/private`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'content-length': String(body.length), 'x-arix-client-ip': '127.0.0.1', 'x-arix-origin-proof': proof },
    body
  });
  assert.equal((await send()).status, 200);
  assert.equal((await send()).status, 403);
});

test('edge gateway refuses non-loopback plaintext upstreams and unsafe URL configuration', () => {
  const { privateKey } = generateKeyPairSync('ed25519');
  assert.throws(() => createEdgeGatewayServer({ upstreamUrl: 'http://origin.example.test/', privateKey, allowInsecureUpstream: true }), /HTTPS/);
  assert.throws(() => createEdgeGatewayServer({ upstreamUrl: 'https://user:pass@origin.example.test/', privateKey }), /without credentials/);
  assert.throws(() => createEdgeGatewayServer({ upstreamUrl: 'https://origin.example.test/base-path', privateKey }), /without credentials/);
});
