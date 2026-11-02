import test from 'node:test';
import assert from 'node:assert/strict';
import { acquireConcurrency, releaseConcurrency, rateLimitMulti } from '../api/_lib/redis.js';
import { runWithCircuit, getCircuitState, resetCircuit, CircuitOpenError } from '../api/_lib/circuit-breaker.js';

process.env.NODE_ENV = 'test';
delete process.env.UPSTASH_REDIS_REST_URL;
delete process.env.UPSTASH_REDIS_REST_TOKEN;

test('1,000 concurrent quota attempts never exceed the local adapter budget', async () => {
  const key = `arix:lab:1000:${Date.now()}`;
  const decisions = await Promise.all(Array.from({ length: 1000 }, () => rateLimitMulti({ dimensions: [{ key, limit: 37, windowMs: 60_000 }] })));
  assert.equal(decisions.filter((decision) => decision.allowed).length, 37);
  assert.equal(decisions.filter((decision) => !decision.allowed).length, 963);
});

test('1,000 concurrent lease requests never exceed a 23-lease cap', async () => {
  const key = `arix:lab:lease1000:${Date.now()}`;
  const leases = await Promise.all(Array.from({ length: 1000 }, (_, i) => acquireConcurrency(key, `actor-${i}`, { maximum: 23, ttlMs: 10_000 })));
  const allowed = leases.filter((lease) => lease.allowed);
  assert.equal(allowed.length, 23);
  await Promise.all(allowed.map((lease) => releaseConcurrency(lease.key, lease.member)));
});

test('injected DNS, timeout, reset, 429 and truncated-body failures are treated as explicit fault states', async () => {
  const faults = [
    Object.assign(new Error('DNS lookup failed'), { code: 'ENOTFOUND' }),
    Object.assign(new Error('socket timeout'), { code: 'ETIMEDOUT' }),
    Object.assign(new Error('connection reset'), { code: 'ECONNRESET' }),
    Object.assign(new Error('rate limited'), { status: 429 }),
    Object.assign(new Error('truncated response'), { code: 'ERR_STREAM_PREMATURE_CLOSE' })
  ];
  for (let i = 0; i < faults.length; i++) {
    const key = `arix:lab:fault-${i}-${Date.now()}`;
    resetCircuit(key);
    await assert.rejects(runWithCircuit(key, async () => { throw faults[i]; }, { failureThreshold: 1, openMs: 200, timeoutMs: 100 }));
    assert.equal(getCircuitState(key).state, 'OPEN');
    await assert.rejects(runWithCircuit(key, async () => 'should-not-run'), CircuitOpenError);
    resetCircuit(key);
  }
});

test('slow backend operations trip the circuit and abort cooperative work', async () => {
  const key = `arix:lab:slow-${Date.now()}`;
  resetCircuit(key);
  let sawAbort = false;
  await assert.rejects(runWithCircuit(key, (signal) => new Promise((resolve, reject) => {
    signal.addEventListener('abort', () => { sawAbort = true; reject(signal.reason); }, { once: true });
  }), { timeoutMs: 50, tripAfterMs: 50, openMs: 300 }), /timed out|latency budget/i);
  assert.equal(sawAbort, true);
  assert.equal(getCircuitState(key).state, 'OPEN');
  resetCircuit(key);
});
