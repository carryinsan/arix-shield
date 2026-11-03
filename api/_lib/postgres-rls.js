import { getArixContext } from '../../sdk/context.js';

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const ADVISORY_LOCK_ID = 1_095_911_768; // ASCII-like "ARIX" lock namespace.
const POLICY_NAME = 'arix_tenant_scope_v1';

function identifier(value, label) {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) throw new TypeError(`Invalid PostgreSQL ${label} identifier.`);
  return `"${value}"`;
}

function normalizePolicyExpression(value) {
  return String(value || '').toLowerCase().replaceAll('"', '').replace(/'([^']*)'::text/g, "'$1'").replace(/\s+/g, '').replace(/[()]/g, '');
}

function isExpectedTenantPolicy(policy, column) {
  if (!policy || policy.permissive !== false || policy.command !== '*' || policy.roles !== '{0}') return false;
  const expected = normalizePolicyExpression(`(${column}::text = NULLIF(current_setting('arix.tenant_id', true), ''))`);
  const using = normalizePolicyExpression(policy.usingExpression);
  const check = normalizePolicyExpression(policy.checkExpression);
  return using === expected && check === expected;
}

function splitSqlStatementsOutsideLiterals(sql) {
  const statements = [];
  let current = '';
  let index = 0;
  let blockDepth = 0;
  let quote = '';
  let quoteBackslashEscapes = false;
  while (index < sql.length) {
    const char = sql[index];
    const next = sql[index + 1];
    if (blockDepth > 0) {
      if (char === '/' && next === '*') { blockDepth++; current += '  '; index += 2; continue; }
      if (char === '*' && next === '/') { blockDepth--; current += '  '; index += 2; continue; }
      current += char === '\n' ? '\n' : ' '; index++; continue;
    }
    if (quote) {
      if (char === quote) {
        const quoteChar = quote;
        if (next === quote) { current += quoteChar === '"' ? '""' : '  '; index += 2; continue; }
        quote = ''; quoteBackslashEscapes = false; current += quoteChar === '"' ? '"' : ' '; index++; continue;
      }
      // Preserve quoted identifiers so policy checks can recognize e.g.
      // pg_catalog."set_config". String literals stay blanked. PostgreSQL
      // treats backslash escapes only in E'...' strings when
      // standard_conforming_strings is enabled (the PostgreSQL default).
      if (quote === '"') { current += char; index++; continue; }
      // Treat ordinary string backslashes literally; otherwise a quote after
      // a backslash can terminate SQL at the server while this lexer hides the
      // remaining statement inside the string. E-strings retain escape rules.
      if (char === '\\' && quote === "'" && quoteBackslashEscapes && index + 1 < sql.length) { current += '  '; index += 2; continue; }
      current += char === '\n' ? '\n' : ' '; index++; continue;
    }
    if (char === '-' && next === '-') {
      while (index < sql.length && sql[index] !== '\n') { current += ' '; index++; }
      continue;
    }
    if (char === '/' && next === '*') { blockDepth = 1; current += '  '; index += 2; continue; }
    if (char === "'" || char === '"') {
      quote = char;
      quoteBackslashEscapes = char === "'" && /[eE]/.test(sql[index - 1] || '') && !/[A-Za-z0-9_$]/.test(sql[index - 2] || '');
      current += char === '"' ? '"' : ' '; index++; continue;
    }
    if (char === '$') {
      const match = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(index));
      if (match) {
        const delimiter = match[0];
        const close = sql.indexOf(delimiter, index + delimiter.length);
        if (close < 0) throw new TypeError('Malformed PostgreSQL dollar-quoted string.');
        const literal = sql.slice(index, close + delimiter.length);
        current += literal.replace(/[^\n]/g, ' ');
        index = close + delimiter.length;
        continue;
      }
    }
    if (char === ';') { statements.push(current); current = ''; index++; continue; }
    current += char;
    index++;
  }
  if (blockDepth > 0 || quote) throw new TypeError('Malformed PostgreSQL SQL literal or comment.');
  if (current.trim()) statements.push(current);
  return statements;
}

export function assertTenantScopedQuery(args) {
  const candidate = args[0];
  const sql = typeof candidate === 'string' ? candidate : typeof candidate?.text === 'string' ? candidate.text : '';
  if (!sql || sql.length > 1_000_000) throw new TypeError('Tenant-scoped PostgreSQL queries require bounded SQL text.');
  for (const statement of splitSqlStatementsOutsideLiterals(sql)) {
    const trimmed = statement.trim();
    if (!trimmed) continue;
    if (/^(?:BEGIN|START\s+TRANSACTION|COMMIT|END|ROLLBACK|ABORT|SAVEPOINT|RELEASE|SET|RESET|DISCARD|DO|CALL|EXECUTE|PREPARE|DEALLOCATE|CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|COMMENT|VACUUM|ANALYZE|CLUSTER|REFRESH|LOCK|COPY|LISTEN|UNLISTEN|NOTIFY|LOAD)\b/i.test(trimmed)
      || /(?:"?[A-Za-z_][A-Za-z0-9_$]*"?\s*\.\s*)*"?set_config"?\s*\(/i.test(trimmed)) {
      throw Object.assign(new Error('ARIX_RLS_CONTEXT_MUTATION_BLOCKED: transaction control and tenant-context mutation are reserved to ArixShield.'), { code: 'ARIX_RLS_CONTEXT_MUTATION_BLOCKED' });
    }
  }
}

/**
 * Explicit, migration-time PostgreSQL RLS provisioning. Tables are an operator
 * allowlist; this helper never discovers tables and never alters every table in
 * a database. The migration role must own each listed table and must not be a
 * superuser or BYPASSRLS role. Existing conflicting policies fail closed.
 */
export async function provisionPostgresTenantRls(client, tables) {
  if (!client || typeof client.query !== 'function') throw new TypeError('A PostgreSQL migration client with query() is required.');
  if (!Array.isArray(tables) || tables.length < 1 || tables.length > 500) throw new RangeError('Provide an explicit allowlist of 1..500 PostgreSQL tables.');
  const normalized = tables.map((item) => {
    const schema = item?.schema ?? 'public';
    const table = item?.table;
    const column = item?.tenantColumn ?? 'tenant_id';
    return {
      schema,
      table,
      column,
      schemaSql: identifier(schema, 'schema'),
      tableSql: identifier(table, 'table'),
      columnSql: identifier(column, 'tenant column')
    };
  });
  const unique = new Set(normalized.map((item) => `${item.schema}.${item.table}`));
  if (unique.size !== normalized.length) throw new TypeError('The PostgreSQL RLS table allowlist contains duplicates.');

  let transactionOpen = false;
  try {
    await client.query('BEGIN');
    transactionOpen = true;
    await client.query('SELECT pg_advisory_xact_lock($1)', [ADVISORY_LOCK_ID]);
    const roleResult = await client.query('SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user');
    const role = roleResult?.rows?.[0];
    if (!role || role.rolsuper === true || role.rolbypassrls === true) {
      throw Object.assign(new Error('RLS provisioning refused: migration role is missing, superuser, or BYPASSRLS.'), { code: 'ARIX_RLS_PRIVILEGED_ROLE' });
    }

    for (const item of normalized) {
      const columnResult = await client.query(
        'SELECT 1 FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 AND column_name = $3',
        [item.schema, item.table, item.column]
      );
      if (!columnResult?.rows?.length) throw Object.assign(new Error(`RLS table or tenant column not found: ${item.schema}.${item.table}.${item.column}`), { code: 'ARIX_RLS_SCHEMA_MISMATCH' });

      const qualifiedTable = `${item.schemaSql}.${item.tableSql}`;
      await client.query(`ALTER TABLE ${qualifiedTable} ENABLE ROW LEVEL SECURITY`);
      await client.query(`ALTER TABLE ${qualifiedTable} FORCE ROW LEVEL SECURITY`);

      const existingResult = await client.query(
        `SELECT p.polpermissive AS permissive, p.polcmd AS command, p.polroles::text AS roles, pg_get_expr(p.polqual, p.polrelid) AS "usingExpression", pg_get_expr(p.polwithcheck, p.polrelid) AS "checkExpression" FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = $2 AND p.polname = $3`,
        [item.schema, item.table, POLICY_NAME]
      );
      if (existingResult?.rows?.length) {
        if (existingResult.rows.length !== 1 || !isExpectedTenantPolicy(existingResult.rows[0], item.column)) {
          throw Object.assign(new Error(`Conflicting ${POLICY_NAME} policy on ${item.schema}.${item.table}; manual review is required.`), { code: 'ARIX_RLS_POLICY_CONFLICT' });
        }
      } else {
        const expression = `(${item.columnSql}::text = NULLIF(current_setting('arix.tenant_id', true), ''))`;
        await client.query(`CREATE POLICY ${identifier(POLICY_NAME, 'policy')} ON ${qualifiedTable} AS RESTRICTIVE FOR ALL USING ${expression} WITH CHECK ${expression}`);
      }

      const verifyResult = await client.query(
        `SELECT c.relrowsecurity AS enabled, c.relforcerowsecurity AS forced FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind IN ('r','p')`,
        [item.schema, item.table]
      );
      const verified = verifyResult?.rows?.[0];
      if (!verified || verified.enabled !== true || verified.forced !== true) {
        throw Object.assign(new Error(`PostgreSQL did not confirm ENABLE and FORCE ROW LEVEL SECURITY for ${item.schema}.${item.table}.`), { code: 'ARIX_RLS_VERIFY_FAILED' });
      }
    }

    await client.query('COMMIT');
    transactionOpen = false;
    return Object.freeze({ applied: normalized.length, policy: POLICY_NAME, tables: normalized.map(({ schema, table, column }) => ({ schema, table, tenantColumn: column })) });
  } catch (error) {
    if (transactionOpen) {
      try { await client.query('ROLLBACK'); } catch { /* preserve the original migration failure */ }
    }
    throw error;
  }
}

/**
 * Runs application queries in a PostgreSQL transaction with transaction-local
 * tenant/user settings sourced only from ArixShield AsyncLocalStorage context.
 * The callback receives a query-only facade, not the pool or a releasable client.
 */
export async function withPostgresTenantTransaction(pool, callback) {
  if (!pool || typeof pool.connect !== 'function') throw new TypeError('A PostgreSQL pool with connect() is required.');
  if (typeof callback !== 'function') throw new TypeError('A transaction callback is required.');
  const context = getArixContext();
  const tenantId = String(context?.tenantId || '').trim();
  const userId = String(context?.userId || '').trim();
  if (!tenantId || !userId || userId === 'anonymous') {
    throw Object.assign(new Error('ARIX_UNSCOPED_DB_ACCESS: a verified tenant and user context is required.'), { code: 'ARIX_UNSCOPED_DB_ACCESS' });
  }
  if (tenantId.length > 256 || userId.length > 256 || /[\u0000-\u001f\u007f]/.test(tenantId + userId)) throw new TypeError('Invalid tenant or user context.');

  const client = await pool.connect();
  if (!client || typeof client.query !== 'function' || typeof client.release !== 'function') {
    try { client?.release?.(); } catch { /* invalid client cleanup is best effort */ }
    throw new TypeError('The PostgreSQL pool returned an invalid client.');
  }
  let transactionOpen = false;
  try {
    await client.query('BEGIN');
    transactionOpen = true;
    const roleResult = await client.query('SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user');
    const role = roleResult?.rows?.[0];
    if (!role || role.rolsuper === true || role.rolbypassrls === true) {
      throw Object.assign(new Error('RLS transaction refused: runtime role is missing, superuser, or BYPASSRLS.'), { code: 'ARIX_RLS_PRIVILEGED_ROLE' });
    }
    await client.query("SELECT set_config('arix.tenant_id', $1, true), set_config('arix.user_id', $2, true)", [tenantId, userId]);
    const scopedClient = Object.freeze({ query: (...args) => { assertTenantScopedQuery(args); return client.query(...args); } });
    const result = await callback(scopedClient);
    await client.query('COMMIT');
    transactionOpen = false;
    return result;
  } catch (error) {
    if (transactionOpen) {
      try { await client.query('ROLLBACK'); } catch { /* preserve the original query failure */ }
    }
    throw error;
  } finally {
    client.release();
  }
}
