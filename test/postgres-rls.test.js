import test from 'node:test';
import assert from 'node:assert/strict';
import { provisionPostgresTenantRls, withPostgresTenantTransaction } from '../api/_lib/postgres-rls.js';
import { runWithArixContext } from '../sdk/context.js';

function fakeMigrationClient({ role = { rolsuper: false, rolbypassrls: false }, existingPolicy = null } = {}) {
  const calls = [];
  return {
    calls,
    async query(sql, values = []) {
      calls.push({ sql, values });
      if (sql.startsWith('SELECT rolsuper')) return { rows: [role] };
      if (sql.startsWith('SELECT 1 FROM information_schema.columns')) return { rows: [{ '?column?': 1 }] };
      if (sql.includes('FROM pg_policy')) return { rows: existingPolicy ? [{ expectedTenantAttnum: 4, referencedAttnums: [4], ...existingPolicy }] : [] };
      if (sql.includes('FROM pg_class')) return { rows: [{ enabled: true, forced: true }] };
      return { rows: [] };
    }
  };
}

test('PostgreSQL RLS provisioner applies restrictive tenant policies to only the explicit allowlist', async () => {
  const client = fakeMigrationClient();
  const result = await provisionPostgresTenantRls(client, [{ schema: 'public', table: 'orders', tenantColumn: 'tenant_id' }]);
  assert.equal(result.applied, 1);
  assert.deepEqual(result.tables, [{ schema: 'public', table: 'orders', tenantColumn: 'tenant_id' }]);
  assert.ok(client.calls.some(({ sql }) => sql === 'ALTER TABLE "public"."orders" ENABLE ROW LEVEL SECURITY'));
  assert.ok(client.calls.some(({ sql }) => sql === 'ALTER TABLE "public"."orders" FORCE ROW LEVEL SECURITY'));
  assert.ok(client.calls.some(({ sql }) => sql.includes('CREATE POLICY "arix_tenant_scope_v1"') && sql.includes('AS RESTRICTIVE')));
  assert.equal(client.calls.at(-1).sql, 'COMMIT');
});

test('PostgreSQL RLS provisioner is idempotent for an exact restrictive policy', async () => {
  const expression = String.raw`((tenant_id)::text = NULLIF(current_setting('arix.tenant_id'::text, true), ''::text))`;
  const client = fakeMigrationClient({ existingPolicy: { permissive: false, command: '*', roles: '{0}', usingExpression: expression, checkExpression: expression } });
  const result = await provisionPostgresTenantRls(client, [{ table: 'orders' }]);
  assert.equal(result.applied, 1);
  assert.equal(client.calls.some(({ sql }) => sql.startsWith('CREATE POLICY')), false);
});


test('PostgreSQL RLS provisioner distinguishes case-sensitive quoted tenant columns', async () => {
  const lowerCasePolicy = String.raw`((tenantid)::text = NULLIF(current_setting('arix.tenant_id'::text, true), ''::text))`;
  const wrongClient = fakeMigrationClient({ existingPolicy: {
    permissive: false, command: '*', roles: '{0}',
    usingExpression: lowerCasePolicy, checkExpression: lowerCasePolicy,
    expectedTenantAttnum: 5, referencedAttnums: [4]
  } });
  await assert.rejects(() => provisionPostgresTenantRls(wrongClient, [{ table: 'orders', tenantColumn: 'TenantId' }]), /Conflicting/i);
  const catalogCheck = wrongClient.calls.find(({ sql }) => sql.includes('FROM pg_policy'));
  assert.match(catalogCheck.sql, /pg_depend/);
  assert.match(catalogCheck.sql, /pg_attribute/);
  assert.deepEqual(catalogCheck.values, ['public', 'orders', 'arix_tenant_scope_v1', 'TenantId']);
  assert.equal(wrongClient.calls.at(-1).sql, 'ROLLBACK');
  assert.equal(wrongClient.calls.some(({ sql }) => sql.startsWith('CREATE POLICY')), false);

  const quotedPolicy = String.raw`(("TenantId")::text = NULLIF(current_setting('arix.tenant_id'::text, true), ''::text))`;
  const correctClient = fakeMigrationClient({ existingPolicy: {
    permissive: false, command: '*', roles: '{0}',
    usingExpression: quotedPolicy, checkExpression: quotedPolicy,
    expectedTenantAttnum: 5, referencedAttnums: [5]
  } });
  const result = await provisionPostgresTenantRls(correctClient, [{ table: 'orders', tenantColumn: 'TenantId' }]);
  assert.equal(result.applied, 1);
  assert.equal(correctClient.calls.some(({ sql }) => sql.startsWith('CREATE POLICY')), false);
});

test('PostgreSQL RLS provisioner rejects privileged roles and rolls back', async () => {
  const client = fakeMigrationClient({ role: { rolsuper: true, rolbypassrls: false } });
  await assert.rejects(() => provisionPostgresTenantRls(client, [{ table: 'orders' }]), /superuser|BYPASSRLS/i);
  assert.equal(client.calls.at(-1).sql, 'ROLLBACK');
});

test('PostgreSQL RLS provisioner rejects unsafe identifiers before issuing SQL', async () => {
  const client = fakeMigrationClient();
  await assert.rejects(() => provisionPostgresTenantRls(client, [{ schema: 'public; DROP TABLE users', table: 'orders' }]), /identifier/i);
  assert.equal(client.calls.length, 0);
});

test('tenant transaction binds trusted AsyncLocalStorage identity locally and commits/releases', async () => {
  const calls = [];
  let released = false;
  const pool = {
    async connect() {
      return {
        async query(sql, values) { calls.push({ sql, values }); if (sql.startsWith('SELECT rolsuper')) return { rows: [{ rolsuper: false, rolbypassrls: false }] }; return { rows: [] }; },
        release() { released = true; }
      };
    }
  };
  const result = await runWithArixContext({ tenantId: 'tenant-7', userId: 'user-9' }, () =>
    withPostgresTenantTransaction(pool, async (db) => {
      await db.query('SELECT * FROM orders');
      return 'done';
    })
  );
  assert.equal(result, 'done');
  assert.equal(calls[0].sql, 'BEGIN');
  assert.equal(calls[1].sql, 'SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user');
  assert.deepEqual(calls[2].values, ['tenant-7', 'user-9']);
  assert.equal(calls[3].sql, 'SELECT * FROM orders');
  assert.equal(calls[4].sql, 'COMMIT');
  assert.equal(released, true);
});

test('tenant transaction refuses absent context and rolls back callback failures', async () => {
  let acquired = false;
  const pool = { async connect() { acquired = true; return { query: async () => ({}), release() {} }; } };
  await assert.rejects(() => withPostgresTenantTransaction(pool, async () => {}), /ARIX_UNSCOPED_DB_ACCESS/);
  assert.equal(acquired, false);

  const calls = [];
  const failingPool = { async connect() { return { async query(sql) { calls.push(sql); if (sql.startsWith('SELECT rolsuper')) return { rows: [{ rolsuper: false, rolbypassrls: false }] }; return { rows: [] }; }, release() { calls.push('RELEASE'); } }; } };
  await assert.rejects(() => runWithArixContext({ tenantId: 't1', userId: 'u1' }, () =>
    withPostgresTenantTransaction(failingPool, async () => { throw new Error('callback failed'); })
  ), /callback failed/);
  assert.ok(calls.includes('ROLLBACK'));
  assert.ok(calls.includes('RELEASE'));
});


test('tenant transaction rejects a runtime database role that bypasses RLS', async () => {
  let callbackCalled = false;
  const calls = [];
  const pool = { async connect() { return {
    async query(sql) {
      calls.push(sql);
      if (sql.startsWith('SELECT rolsuper')) return { rows: [{ rolsuper: false, rolbypassrls: true }] };
      return { rows: [] };
    },
    release() { calls.push('RELEASE'); }
  }; } };
  await assert.rejects(() => runWithArixContext({ tenantId: 'tenant-x', userId: 'user-y' }, () =>
    withPostgresTenantTransaction(pool, async () => { callbackCalled = true; })
  ), /BYPASSRLS/i);
  assert.equal(callbackCalled, false);
  assert.ok(calls.includes('ROLLBACK'));
  assert.ok(calls.includes('RELEASE'));
});

test('PostgreSQL RLS provisioner stops on a conflicting pre-existing policy', async () => {
  const client = fakeMigrationClient({ existingPolicy: {
    permissive: true,
    command: '*',
    roles: '{0}',
    usingExpression: 'true',
    checkExpression: 'true'
  } });
  await assert.rejects(() => provisionPostgresTenantRls(client, [{ table: 'orders' }]), /Conflicting/i);
  assert.equal(client.calls.at(-1).sql, 'ROLLBACK');
  assert.equal(client.calls.some(({ sql }) => sql.startsWith('CREATE POLICY')), false);
});

test('PostgreSQL RLS provisioner fails closed when the allowlisted tenant column is absent', async () => {
  const client = fakeMigrationClient();
  client.query = async function (sql, values = []) {
    this.calls.push({ sql, values });
    if (sql.startsWith('SELECT rolsuper')) return { rows: [{ rolsuper: false, rolbypassrls: false }] };
    if (sql.startsWith('SELECT 1 FROM information_schema.columns')) return { rows: [] };
    return { rows: [] };
  };
  await assert.rejects(() => provisionPostgresTenantRls(client, [{ table: 'orders' }]), /tenant column not found/i);
  assert.equal(client.calls.at(-1).sql, 'ROLLBACK');
});


test('tenant transaction blocks callback SQL from altering the RLS context or transaction boundary', async () => {
  const calls = [];
  const pool = { async connect() { return {
    async query(sql) {
      calls.push(sql);
      if (sql.startsWith('SELECT rolsuper')) return { rows: [{ rolsuper: false, rolbypassrls: false }] };
      return { rows: [] };
    },
    release() { calls.push('RELEASE'); }
  }; } };
  await runWithArixContext({ tenantId: 'tenant-safe', userId: 'user-safe' }, () =>
    withPostgresTenantTransaction(pool, async (db) => {
      assert.throws(() => db.query("SELECT set_config('arix.tenant_id', 'tenant-victim', true)"), /ARIX_RLS_CONTEXT_MUTATION_BLOCKED/);
      assert.throws(() => db.query('SELECT 1; COMMIT'), /ARIX_RLS_CONTEXT_MUTATION_BLOCKED/);
      await db.query('SELECT * FROM orders WHERE id = $1', ['order-1']);
    })
  );
  assert.equal(calls.filter((sql) => sql === 'SELECT * FROM orders WHERE id = $1').length, 1);
  assert.ok(calls.includes('COMMIT'));
});


test('PostgreSQL RLS provisioner rejects a matching expression restricted to non-PUBLIC roles', async () => {
  const expression = String.raw`(tenant_id::text = NULLIF(current_setting('arix.tenant_id', true), ''))`;
  const client = fakeMigrationClient({ existingPolicy: { permissive: false, command: '*', roles: '{42}', usingExpression: expression, checkExpression: expression } });
  await assert.rejects(() => provisionPostgresTenantRls(client, [{ table: 'orders' }]), /Conflicting/i);
  assert.equal(client.calls.at(-1).sql, 'ROLLBACK');
});
