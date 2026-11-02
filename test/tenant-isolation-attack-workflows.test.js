import test from 'node:test';
import assert from 'node:assert/strict';
import { scopeQuery, authorizeRequest, filterReadFields, filterWriteFields } from '../api/_lib/authorization.js';
import { sealResourceId, rewriteCapabilityRequest } from '../api/_lib/crypto-trap.js';

const routePolicy = [{
  path: '/api/vault/:id', methods: ['GET', 'POST', 'PATCH', 'DELETE'], authenticated: true,
  roles: ['owner', 'admin'], tenantIsolated: true, requirePreCheck: true,
  preCheck: async ({ context, request }) => request?.tenantId === context.tenantId && request?.ownerId === context.userId && request?.capabilityValid === true
}];

function actors(tenantId, ownerId) {
  return [
    { label: 'resource owner', context: { tenantId, userId: ownerId, roles: ['owner'] }, allow: true },
    { label: 'same-tenant peer', context: { tenantId, userId: `${ownerId}-peer`, roles: ['owner'] }, allow: false },
    { label: 'foreign tenant administrator', context: { tenantId: 'tenant-foreign', userId: 'root-foreign', roles: ['admin'] }, allow: false },
    { label: 'same-tenant member', context: { tenantId, userId: `${ownerId}-member`, roles: ['member'] }, allow: false },
    { label: 'anonymous', context: { tenantId, userId: '', roles: [] }, allow: false }
  ];
}

test('500 tenant-scoped database queries preserve non-overridable tenant and owner predicates', () => {
  for (let i = 0; i < 500; i++) {
    const tenantId = `tenant-${i.toString(36)}`;
    const userId = `user-${i.toString(36)}`;
    const attackerWhere = { OR: [{ tenantId: 'tenant-victim' }, { ownerId: 'victim' }], status: 'OPEN' };
    const prisma = scopeQuery({ where: attackerWhere, take: 20 }, { tenantId, userId });
    const mongo = scopeQuery({ $or: [{ tenantId: 'tenant-victim' }, { ownerId: 'victim' }], state: 'OPEN' }, { tenantId, userId }, { adapter: 'mongo' });
    assert.deepEqual(prisma.where.AND[1], { tenantId, ownerId: userId });
    assert.deepEqual(mongo.$and[1], { tenantId, ownerId: userId });
    assert.throws(() => scopeQuery('SELECT * FROM private_records', { tenantId, userId }), /structured query/);
  }
});

test('authenticated owner/peer/foreign-admin/roleless/anonymous workflows fail closed across methods', async () => {
  let evaluated = 0;
  for (let tenantIndex = 0; tenantIndex < 25; tenantIndex++) {
    const tenantId = `tenant-${tenantIndex}`;
    const ownerId = `owner-${tenantIndex}`;
    const owner = { tenantId, userId: ownerId, roles: ['owner'] };
    const capability = sealResourceId(`record-${tenantIndex}`, owner, 'read');
    for (const actor of actors(tenantId, ownerId)) {
      for (const method of ['GET', 'POST', 'PATCH', 'DELETE']) {
        const mode = method === 'DELETE' ? 'delete' : ['POST', 'PATCH'].includes(method) ? 'write' : 'read';
        const token = sealResourceId(`record-${tenantIndex}`, owner, mode);
        const rewritten = rewriteCapabilityRequest(`/api/vault/${encodeURIComponent(token)}`, null, actor.context, { method, requireSealed: true });
        const expected = actor.allow;
        const decision = await authorizeRequest({
          method, pathname: `/api/vault/${encodeURIComponent(token)}`, routes: routePolicy, context: actor.context,
          defaultDenyMutations: true, requireScopedPrecheck: true,
          request: { tenantId, ownerId, capabilityValid: !rewritten.invalid }
        });
        assert.equal(rewritten.invalid, !expected, `${actor.label}: capability ${method}`);
        assert.equal(decision.allowed, expected, `${actor.label}: authorization ${method}`);
        evaluated++;
      }
    }
    // A valid capability is bound to its originating tenant and owner.
    assert.equal(rewriteCapabilityRequest(`/api/vault/${encodeURIComponent(capability)}`, null, { tenantId: 'tenant-attacker', userId: 'intruder' }, { method: 'GET', requireSealed: true }).invalid, true);
  }
  assert.equal(evaluated, 500);
});

test('read and write field policies prevent property-level escalation and leakage', () => {
  const update = { displayName: 'Ari', roles: ['admin'], tenantId: 'tenant-b', billingPlan: 'enterprise', isStaff: true };
  const filteredWrite = filterWriteFields(update, { member: ['displayName'] }, ['member']);
  assert.equal(filteredWrite.displayName, 'Ari');
  assert.deepEqual(Object.keys(filteredWrite), ['displayName']);
  const filteredRead = filterReadFields({ id: 'r1', displayName: 'Ari', apiKey: 'secret', tenantId: 'tenant-a' }, { member: ['apiKey', 'tenantId'] }, ['member']);
  assert.equal(filteredRead.apiKey, undefined);
  assert.equal(filteredRead.tenantId, undefined);
});
