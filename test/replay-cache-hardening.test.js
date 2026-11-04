import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { BoundedReplayCache, BoundedWindowQuotaStore } from '../api/_lib/bounded-replay-cache.js';
import { base64urlEncode, sha256Hex, verifyRequestDpopProof } from '../api/_lib/crypto-trap.js';
import { makeOutageChallenge, verifyOutageProof } from '../sdk/security-runtime.js';

process.env.ARIX_MASTER_SECRET = 'R'.repeat(64);

async function solveChallenge(challenge) {
  for (let solution = 0; solution < 1_000_000; solution++) {
    const digest = await sha256Hex(`${challenge.nonce}:${solution}`);
    const bits = challenge.difficulty;
    const full = Math.floor(bits / 4);
    const rem = bits % 4;
    if (digest.startsWith('0'.repeat(full)) && (!rem || (parseInt(digest[full], 16) >> (4 - rem)) === 0)) {
      return `${challenge.token}:${solution}`;
    }
  }
  throw new Error('Unable to solve test proof-of-work challenge.');
}

function encodeJson(value) {
  return base64urlEncode(new TextEncoder().encode(JSON.stringify(value)));
}

async function makeRequestDpop(pair, { jti, url, bodyBytes = new Uint8Array() }) {
  const jwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const header = encodeJson({ typ: 'dpop+jwt', alg: 'ES256', jwk });
  const payload = encodeJson({
    htm: 'GET', htu: url, iat: Math.floor(Date.now() / 1000), jti,
    ath: base64urlEncode(await webcrypto.subtle.digest('SHA-256', bodyBytes))
  });
  const input = `${header}.${payload}`;
  const signature = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode(input));
  return `${input}.${base64urlEncode(new Uint8Array(signature))}`;
}

test('bounded replay cache prunes by expiry heap and never evicts live entries', () => {
  const cache = new BoundedReplayCache({ maxEntries: 4, maxPerNamespace: 2, maxPerPartition: 1 });
  assert.equal(cache.consume('a1', { namespace: 'project-a', partition: 'device-1', ttlMs: 100, now: 1000 }).accepted, true);
  assert.equal(cache.consume('a2', { namespace: 'project-a', partition: 'device-2', ttlMs: 100, now: 1001 }).accepted, true);
  assert.equal(cache.consume('a3', { namespace: 'project-a', partition: 'device-3', ttlMs: 100, now: 1002 }).reason, 'NAMESPACE_CAPACITY');
  assert.equal(cache.consume('b1', { namespace: 'project-b', partition: 'device-1', ttlMs: 100, now: 1003 }).accepted, true);
  assert.equal(cache.consume('a1', { namespace: 'project-a', partition: 'device-1', ttlMs: 100, now: 1004 }).reason, 'REPLAY');
  assert.equal(cache.size, 3);
  assert.equal(cache.consume('a3', { namespace: 'project-a', partition: 'device-3', ttlMs: 100, now: 1101 }).accepted, true);
  assert.equal(cache.size, 2); // b1 remains live; a2 expired; a3 inserted.
});

test('replay cache callback admission is atomic and denied admission stores no replay record', () => {
  const cache = new BoundedReplayCache({ maxEntries: 2, maxPerNamespace: 2, maxPerPartition: 2 });
  let admitted = false;
  const denied = cache.admit('proof-1', { namespace: 'project', partition: 'requester', ttlMs: 1000, now: 5000 }, () => admitted);
  assert.equal(denied.reason, 'ADMISSION_DENIED');
  assert.equal(cache.size, 0);
  admitted = true;
  assert.equal(cache.admit('proof-1', { namespace: 'project', partition: 'requester', ttlMs: 1000, now: 5001 }, () => admitted).accepted, true);
  assert.equal(cache.size, 1);
});

test('bounded replay cache enforces global capacity without evicting unexpired entries', () => {
  const cache = new BoundedReplayCache({ maxEntries: 2, maxPerNamespace: 2, maxPerPartition: 2 });
  assert.equal(cache.consume('one', { namespace: 'a', partition: 'x', ttlMs: 5000, now: 10 }).accepted, true);
  assert.equal(cache.consume('two', { namespace: 'b', partition: 'y', ttlMs: 5000, now: 11 }).accepted, true);
  assert.equal(cache.consume('three', { namespace: 'c', partition: 'z', ttlMs: 5000, now: 12 }).reason, 'GLOBAL_CAPACITY');
  assert.equal(cache.consume('one', { namespace: 'a', partition: 'x', ttlMs: 5000, now: 13 }).reason, 'REPLAY');
  assert.equal(cache.size, 2);
});

test('outage proof is project/requester-bound and replay is consumed only after quota admission', async () => {
  const projectId = `outage-project-${Date.now()}`;
  const requesterKey = '203.0.113.0/24';
  const quotaKey = `${projectId}:${requesterKey}:actor:degraded-read`;
  const challenge = await makeOutageChallenge({ method: 'GET', pathname: '/docs', difficulty: 8, projectId, requesterKey });
  const proof = await solveChallenge(challenge);
  const cache = globalThis.__ARIX_OUTAGE_REPLAY_CACHE__;
  const before = cache.size;

  const accepted = await verifyOutageProof(proof, 'GET', '/docs', { projectId, requesterKey, quotaKey, limit: 4, windowMs: 60000 });
  assert.equal(accepted.valid, true);
  assert.equal(accepted.quota.allowed, true);
  assert.equal(cache.size, before + 1);

  const replay = await verifyOutageProof(proof, 'GET', '/docs', { projectId, requesterKey, quotaKey, limit: 4, windowMs: 60000 });
  assert.equal(replay.valid, false);
  assert.equal(replay.reason, 'OUTAGE_POW_REPLAY');

  const deniedChallenge = await makeOutageChallenge({ method: 'GET', pathname: '/catalog', difficulty: 8, projectId, requesterKey });
  const deniedProof = await solveChallenge(deniedChallenge);
  const denied = await verifyOutageProof(deniedProof, 'GET', '/catalog', { projectId, requesterKey, quotaKey, limit: 4, windowMs: 60000 });
  assert.equal(denied.valid, false);
  assert.equal(denied.reason, 'OUTAGE_LOCAL_QUOTA');
  assert.equal(cache.size, before + 1, 'quota denial must not allocate a replay-cache entry');

  const wrongRequester = await verifyOutageProof(proof, 'GET', '/docs', { projectId, requesterKey: '198.51.100.0/24', quotaKey: `${projectId}:other:actor`, limit: 4 });
  assert.equal(wrongRequester.reason, 'OUTAGE_POW_SCOPE_MISMATCH');
});

test('outage local quota store has hard global and per-project bounds', () => {
  const store = new BoundedWindowQuotaStore({ maxEntries: 2, maxPerNamespace: 1 });
  assert.equal(store.consume({ key: 'a1', namespace: 'project-a', limit: 40, windowMs: 60000 }).allowed, true);
  assert.equal(store.consume({ key: 'a2', namespace: 'project-a', limit: 40, windowMs: 60000 }).reason, 'STORE_CAPACITY');
  assert.equal(store.consume({ key: 'b1', namespace: 'project-b', limit: 40, windowMs: 60000 }).allowed, true);
  assert.equal(store.consume({ key: 'c1', namespace: 'project-c', limit: 40, windowMs: 60000 }).reason, 'STORE_CAPACITY');
  assert.equal(store.size, 2);
});

test('request DPoP uses durable replay consumption when supplied and stays project-isolated', async () => {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const url = 'https://app.example.test/docs';
  const bodyBytes = new Uint8Array();
  const proofA = await makeRequestDpop(pair, { jti: `durable-${Date.now()}-a`, url, bodyBytes });
  let consumed = 0;
  const durable = await verifyRequestDpopProof({ proof: proofA, method: 'GET', url, bodyBytes, projectId: 'durable-project-a', consumeReplay: async () => { consumed++; return true; } });
  assert.equal(durable.valid, true);
  assert.equal(durable.replayConsumed, true);
  assert.equal(consumed, 1);

  const proofB = await makeRequestDpop(pair, { jti: `durable-${Date.now()}-b`, url, bodyBytes });
  const replayed = await verifyRequestDpopProof({ proof: proofB, method: 'GET', url, bodyBytes, projectId: 'durable-project-a', consumeReplay: async () => false });
  assert.equal(replayed.valid, false);
  assert.equal(replayed.reason, 'DPOP_REPLAY');

  const proofC = await makeRequestDpop(pair, { jti: `durable-${Date.now()}-c`, url, bodyBytes });
  const unavailable = await verifyRequestDpopProof({ proof: proofC, method: 'GET', url, bodyBytes, projectId: 'durable-project-a', consumeReplay: async () => { throw new Error('redis unavailable'); } });
  assert.equal(unavailable.valid, false);
  assert.equal(unavailable.reason, 'DPOP_REPLAY_SERVICE_UNAVAILABLE');
});
