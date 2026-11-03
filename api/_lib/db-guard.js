import { recordScopedDataReceipt, getArixContext } from '../../sdk/context-internal.js';

function identity(context) {
  const tenantId = String(context?.tenantId || context?.projectId || '').trim();
  const userId = String(context?.userId || context?.ownerId || '').trim();
  if (!tenantId || !userId || userId === 'anonymous') {
    throw Object.assign(new Error('ARIX_UNSCOPED_DB_ACCESS: verified tenant and user identifiers are required.'), { code: 'ARIX_UNSCOPED_DB_ACCESS' });
  }
  const active = getArixContext();
  if (!active || active.tenantId !== tenantId || active.userId !== userId || !active.requestId) {
    throw Object.assign(new Error('ARIX_SCOPE_CONTEXT_MISMATCH: transaction context does not match the active request.'), { code: 'ARIX_SCOPE_CONTEXT_MISMATCH' });
  }
  return { tenantId, userId };
}

function driverName(client, options) {
  const explicit = String(options.driver || client?.$arixDriver || '').toLowerCase();
  if (explicit) return explicit;
  const name = String(client?.constructor?.name || '').toLowerCase();
  if (name.includes('prisma')) return 'prisma';
  if (name.includes('pool') || name.includes('client')) return 'pg';
  if (name.includes('database')) return 'sqlite';
  return '';
}

async function pgTransaction(client, ctx, fn, options) {
  const isPool = options.pool === true || (typeof client.connect === 'function' && Number.isInteger(client.totalCount));
  const connection = isPool ? await client.connect() : client;
  if (!connection || typeof connection.query !== 'function') throw new TypeError('PostgreSQL transaction requires a pg Pool or connected Client.');
  let began = false;
  try {
    await connection.query('BEGIN'); began = true;
    await connection.query("SELECT set_config('arix.tenant_id', $1, true), set_config('arix.user_id', $2, true)", [ctx.tenantId, ctx.userId]);
    const result = await fn(connection);
    await connection.query('COMMIT'); began = false;
    return result;
  } catch (error) {
    if (began) { try { await connection.query('ROLLBACK'); } catch { /* Preserve the original failure. */ } }
    throw error;
  } finally {
    if (isPool && typeof connection.release === 'function') connection.release();
  }
}

async function mysqlTransaction(client, ctx, fn, options) {
  const connection = typeof client.getConnection === 'function' ? await client.getConnection() : client;
  if (!connection || typeof connection.beginTransaction !== 'function' || typeof connection.query !== 'function') {
    throw new TypeError('MySQL support requires mysql2/promise Pool or Connection.');
  }
  let began = false;
  try {
    await connection.beginTransaction(); began = true;
    await connection.query('SET @arix_tenant_id = ?, @arix_user_id = ?', [ctx.tenantId, ctx.userId]);
    const result = await fn(connection);
    await connection.commit(); began = false;
    return result;
  } catch (error) {
    if (began) { try { await connection.rollback(); } catch { /* Preserve the original failure. */ } }
    throw error;
  } finally {
    let cleanupFailed = false;
    try { await connection.query('SET @arix_tenant_id = NULL, @arix_user_id = NULL'); }
    catch { cleanupFailed = true; }
    if (connection !== client) {
      if (cleanupFailed && typeof connection.destroy === 'function') connection.destroy();
      else if (typeof connection.release === 'function') connection.release();
    } else if (cleanupFailed && typeof connection.destroy === 'function') {
      connection.destroy();
    }
    if (cleanupFailed) throw Object.assign(new Error('ARIX_MYSQL_SCOPE_CLEANUP_FAILED: the database connection was retired because tenant session variables could not be cleared.'), { code: 'ARIX_MYSQL_SCOPE_CLEANUP_FAILED' });
  }
}

async function sqliteTransaction(client, ctx, fn, options) {
  if (!client || typeof client.exec !== 'function') throw new TypeError('SQLite support requires a node:sqlite DatabaseSync connection.');
  const scopeAdapter = options.sqliteScopeAdapter || client.arixSetTenantContext;
  if (typeof scopeAdapter !== 'function') {
    throw Object.assign(new Error('ARIX_SQLITE_SCOPE_ADAPTER_REQUIRED: SQLite has no native row-level security; provide a reviewed connection-local enforcement adapter.'), { code: 'ARIX_SQLITE_SCOPE_ADAPTER_REQUIRED' });
  }
  let began = false;
  try {
    client.exec('BEGIN IMMEDIATE'); began = true;
    await scopeAdapter.call(client, client, Object.freeze({ ...ctx }));
    const result = await fn(client);
    client.exec('COMMIT'); began = false;
    return result;
  } catch (error) {
    if (began) { try { client.exec('ROLLBACK'); } catch { /* Preserve the original failure. */ } }
    throw error;
  }
}

async function prismaTransaction(client, ctx, fn, options) {
  if (typeof client?.$transaction !== 'function') throw new TypeError('Prisma support requires a PrismaClient instance.');
  const provider = String(options.provider || '').toLowerCase();
  if (!['postgresql', 'mysql', 'sqlite'].includes(provider)) throw new TypeError('Prisma provider must be explicitly set to postgresql, mysql, or sqlite.');
  let result;
  await client.$transaction(async (tx) => {
    if (provider === 'postgresql') {
      if (typeof tx.$queryRawUnsafe !== 'function') throw new TypeError('Prisma PostgreSQL transaction client does not expose $queryRawUnsafe.');
      await tx.$queryRawUnsafe("SELECT set_config('arix.tenant_id', $1, true), set_config('arix.user_id', $2, true)", ctx.tenantId, ctx.userId);
    } else if (provider === 'mysql') {
      if (typeof tx.$executeRawUnsafe !== 'function') throw new TypeError('Prisma MySQL transaction client does not expose $executeRawUnsafe.');
      await tx.$executeRawUnsafe('SET @arix_tenant_id = ?, @arix_user_id = ?', ctx.tenantId, ctx.userId);
    } else {
      const adapter = options.sqliteScopeAdapter;
      if (typeof adapter !== 'function') throw Object.assign(new Error('ARIX_SQLITE_SCOPE_ADAPTER_REQUIRED: SQLite has no native row-level security.'), { code: 'ARIX_SQLITE_SCOPE_ADAPTER_REQUIRED' });
      await adapter(tx, Object.freeze({ ...ctx }));
    }
    if (provider === 'mysql') {
      try { result = await fn(tx); }
      finally { await tx.$executeRawUnsafe('SET @arix_tenant_id = NULL, @arix_user_id = NULL'); }
    } else result = await fn(tx);
  }, options.transactionOptions || {});
  return result;
}

/**
 * Run database work in one transaction bound to the active ArixShield request.
 * PostgreSQL uses SET LOCAL semantics via set_config(..., true), which only has
 * effect when reviewed RLS policies consume current_setting('arix.tenant_id').
 * MySQL sets transaction-session variables for reviewed policies/views.
 * SQLite requires a caller-supplied connection-local scope adapter because it
 * has no native RLS. This helper cannot protect arbitrary unwrapped connections.
 */
export async function withTenantTransaction(client, context, fn, options = {}) {
  if (typeof fn !== 'function') throw new TypeError('withTenantTransaction requires a callback.');
  if (!client || typeof client !== 'object') throw new TypeError('withTenantTransaction requires a database client.');
  const ctx = identity(context);
  const driver = driverName(client, options);
  let result;
  switch (driver) {
    case 'pg': case 'postgres': case 'postgresql':
      result = await pgTransaction(client, ctx, fn, options);
      break;
    case 'mysql': case 'mysql2':
      result = await mysqlTransaction(client, ctx, fn, options);
      break;
    case 'sqlite': case 'node:sqlite':
      result = await sqliteTransaction(client, ctx, fn, options);
      break;
    case 'prisma':
      result = await prismaTransaction(client, ctx, fn, options);
      break;
    default:
      throw new TypeError('Unsupported database driver. Set options.driver to pg, mysql2, sqlite, or prisma.');
  }
  recordScopedDataReceipt(driver, result);
  return result;
}

/** Verify FORCE RLS for every named PostgreSQL tenant table and the current role. */
export async function verifyDatabaseRlsActive(pgClient, tables, { schema = 'public', throwOnFailure = true } = {}) {
  if (!pgClient || typeof pgClient.query !== 'function') throw new TypeError('verifyDatabaseRlsActive requires a PostgreSQL query executor.');
  if (!Array.isArray(tables) || !tables.length || tables.length > 500 || tables.some((name) => typeof name !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(name))) throw new TypeError('tables must be a non-empty list of valid unqualified PostgreSQL table names.');
  if (typeof schema !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(schema)) throw new TypeError('schema is invalid.');
  const result = await pgClient.query(
    `SELECT current_user AS role_name, r.rolsuper, r.rolbypassrls, requested.table_name,
            (c.oid IS NOT NULL) AS table_exists,
            COALESCE(c.relrowsecurity, false) AS row_security,
            COALESCE(c.relforcerowsecurity, false) AS force_row_security
       FROM (SELECT unnest($1::text[]) AS table_name) AS requested
       CROSS JOIN pg_roles AS r
       LEFT JOIN pg_namespace AS n ON n.nspname = $2
       LEFT JOIN pg_class AS c ON c.relnamespace = n.oid AND c.relname = requested.table_name AND c.relkind IN ('r','p')
      WHERE r.rolname = current_user`, [tables, schema]
  );
  const rows = Array.isArray(result?.rows) ? result.rows : [];
  const role = rows[0] ? { name: rows[0].role_name, superuser: rows[0].rolsuper === true, bypassRls: rows[0].rolbypassrls === true } : null;
  const issues = [];
  if (!role) issues.push('DATABASE_CURRENT_ROLE_UNAVAILABLE');
  if (role?.superuser) issues.push('DATABASE_ROLE_IS_SUPERUSER');
  if (role?.bypassRls) issues.push('DATABASE_ROLE_BYPASSES_RLS');
  const byName = new Map(rows.map((row) => [row.table_name, row]));
  for (const table of tables) {
    const row = byName.get(table);
    if (!row) issues.push(`RLS_TABLE_MISSING:${table}`);
    else if (row.table_exists === false) issues.push(`RLS_TABLE_MISSING:${table}`);
    else {
      if (row.row_security !== true) issues.push(`RLS_DISABLED:${table}`);
      if (row.force_row_security !== true) issues.push(`RLS_FORCE_DISABLED:${table}`);
    }
  }
  const report = Object.freeze({ ok: issues.length === 0, schema, role, tables: tables.slice(), issues });
  if (!report.ok && throwOnFailure) throw Object.assign(new Error(`PostgreSQL RLS verification failed: ${issues.join(', ')}`), { code: 'ARIX_DATABASE_RLS_ATTESTATION_FAILED', report });
  return report;
}
