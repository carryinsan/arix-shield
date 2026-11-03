import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectLinuxHostHardening } from '../api/_lib/host-attestation.js';

const secureStatus = 'Name:\tnode\nUid:\t65532\t65532\t65532\t65532\nNoNewPrivs:\t1\nCapEff:\t0000000000000000\n';

test('Linux host attestation accepts a non-root, no-new-privileges, zero-capability process', async () => {
  const result = await inspectLinuxHostHardening({ uid: 65532, readStatus: async () => secureStatus });
  assert.equal(result.supported, true);
  assert.equal(result.ok, true);
  assert.deepEqual(result.issues, []);
});

test('Linux host attestation reports each missing host hardening control', async () => {
  const result = await inspectLinuxHostHardening({
    uid: 0,
    readStatus: async () => 'Uid:\t0\t0\t0\t0\nNoNewPrivs:\t0\nCapEff:\t0000000000000001\n'
  });
  assert.equal(result.ok, false);
  assert.deepEqual(result.issues, [
    'HOST_PROCESS_MUST_NOT_RUN_AS_ROOT',
    'HOST_NO_NEW_PRIVILEGES_NOT_SET',
    'HOST_EFFECTIVE_CAPABILITIES_NOT_ZERO'
  ]);
});

test('Linux host attestation fails closed when proc status cannot be read', async () => {
  const result = await inspectLinuxHostHardening({ uid: 65532, readStatus: async () => { throw new Error('denied'); } });
  assert.equal(result.ok, false);
  assert.deepEqual(result.issues, ['HOST_STATUS_UNREADABLE']);
});
