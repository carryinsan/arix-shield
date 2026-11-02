import test from 'node:test';
import assert from 'node:assert/strict';
import { deleteKeys, getJson, getString, setJson, setString } from '../api/_lib/redis.js';
import { randomUUID } from 'node:crypto';

const originalSecret = process.env.ARIX_MASTER_SECRET;
process.env.ARIX_MASTER_SECRET ||= 'test-only-master-secret-at-least-32-bytes-long';

function id(prefix) { return `${prefix}_${randomUUID().replaceAll('-', '')}`; }

// Keep the tests isolated from shared local-Redis state and never use production data.
test('user and project records are encrypted at rest and transparently decrypted', async (t) => {
  const ownerId = id('tenant');
  const userKey = `arix:user:${ownerId}`;
  const projectId = id('project');
  const projectKey = `arix:project:${projectId}`;
  t.after(async () => {
    await deleteKeys(userKey, projectKey);
    if (originalSecret === undefined) delete process.env.ARIX_MASTER_SECRET;
    else process.env.ARIX_MASTER_SECRET = originalSecret;
  });

  const user = { id: ownerId, email: 'private-user@example.invalid', passwordHash: 'test-hash', roles: ['owner'] };
  const project = { id: projectId, ownerId, name: 'Confidential project', secretSetting: 'do-not-store-in-plaintext' };
  await setJson(userKey, user);
  await setJson(projectKey, project);

  const userAtRest = await getString(userKey);
  const projectAtRest = await getString(projectKey);
  assert.ok(userAtRest && projectAtRest);
  assert.equal(JSON.parse(userAtRest).schema, 'arix.customer-record.v1');
  assert.equal(JSON.parse(projectAtRest).schema, 'arix.customer-record.v1');
  assert.equal(userAtRest.includes(user.email), false);
  assert.equal(userAtRest.includes(user.passwordHash), false);
  assert.equal(projectAtRest.includes(project.secretSetting), false);
  assert.deepEqual(await getJson(userKey), user);
  assert.deepEqual(await getJson(projectKey), project);
});

test('legacy plaintext customer records migrate atomically on first read', async (t) => {
  const ownerId = id('legacy');
  const key = `arix:user:${ownerId}`;
  t.after(async () => {
    await deleteKeys(key);
    if (originalSecret === undefined) delete process.env.ARIX_MASTER_SECRET;
    else process.env.ARIX_MASTER_SECRET = originalSecret;
  });
  const record = { id: ownerId, email: 'legacy-user@example.invalid', passwordHash: 'legacy-test-hash' };
  await setString(key, JSON.stringify(record));
  assert.deepEqual(await getJson(key), record);
  const migrated = await getString(key);
  assert.equal(JSON.parse(migrated).schema, 'arix.customer-record.v1');
  assert.equal(migrated.includes(record.email), false);
});
