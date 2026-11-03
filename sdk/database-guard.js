import { getArixContext } from './context.js';

const protectedPools = new WeakMap();
const BLOCKED_COMMANDS = new Set([
  'ALTER', 'BEGIN', 'CALL', 'CLUSTER', 'COMMIT', 'COPY', 'CREATE', 'DEALLOCATE',
  'DISCARD', 'DO', 'DROP', 'EXECUTE', 'GRANT', 'PREPARE', 'REINDEX', 'RELEASE',
  'RESET', 'REVOKE', 'ROLLBACK', 'SAVEPOINT', 'SET', 'TRUNCATE', 'VACUUM'
]);
const BLOCKED_FUNCTIONS = new Set([
  'SET_CONFIG', 'PG_RELOAD_CONF', 'PG_TERMINATE_BACKEND', 'PG_CANCEL_BACKEND',
  'PG_READ_FILE', 'PG_READ_BINARY_FILE', 'PG_LS_DIR', 'PG_WRITE_FILE', 'LO_IMPORT',
  'LO_EXPORT', 'DBLINK_CONNECT', 'DBLINK_EXEC'
]);
const ALLOWED_START = new Set(['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'WITH', 'VALUES', 'EXPLAIN']);

function fail(code, message) {
  return Object.assign(new Error(message), { code });
}

function safeIdentity(value, label) {
  const result = String(value || '').trim();
  if (!result || result.toLowerCase() === 'anonymous' || result.length > 256 || /[\u0000-\u001f\u007f]/.test(result)) {
    throw fail('ARIX_UNSCOPED_DB_ACCESS', `A verified ${label} is required for a tenant-scoped PostgreSQL transaction.`);
  }
  return result;
}

/**
 * Small SQL lexical gate for the scoped pg adapter. It is intentionally not an
 * SQL parser: PostgreSQL RLS is the data-isolation authority. This gate forbids
 * transaction/session control, tenant-GUC mutation, administrative statements,
 * and multiple statements in one driver call.
 */
function sqlTokens(source) {
  if (typeof source !== 'string' || !source.trim() || source.length > 1_000_000) {
    throw fail('ARIX_SQL_REJECTED', 'PostgreSQL query must be a non-empty string no larger than 1 MiB.');
  }
  const tokens = [];
  let semicolons = 0;
  for (let i = 0; i < source.length;) {
    const ch = source[i];
    if (/\s/.test(ch)) { i++; continue; }
    if (ch === '-' && source[i + 1] === '-') {
      i += 2;
      while (i < source.length && source[i] !== '\n') i++;
      continue;
    }
    if (ch === '/' && source[i + 1] === '*') {
      i += 2;
      let depth = 1;
      while (i < source.length && depth) {
        if (source[i] === '/' && source[i + 1] === '*') { depth++; i += 2; }
        else if (source[i] === '*' && source[i + 1] === '/') { depth--; i += 2; }
        else i++;
      }
      if (depth) throw fail('ARIX_SQL_REJECTED', 'Unterminated SQL comment.');
      continue;
    }
    if (ch === "'") {
      i++;
      let closed = false;
      while (i < source.length) {
        if (source[i] === "'" && source[i + 1] === "'") { i += 2; continue; }
        if (source[i] === "'") { i++; closed = true; break; }
        if (source[i] === '\\' && i + 1 < source.length) i += 2;
        else i++;
      }
      if (!closed) throw fail('ARIX_SQL_REJECTED', 'Unterminated SQL string literal.');
      continue;
    }
    if (ch === '$') {
      const delimiter = /^\$[A-Za-z_][A-Za-z0-9_]*\$|^\$\$/.exec(source.slice(i))?.[0];
      if (delimiter) {
        const end = source.indexOf(delimiter, i + delimiter.length);
        if (end < 0) throw fail('ARIX_SQL_REJECTED', 'Unterminated dollar-quoted SQL literal.');
        i = end + delimiter.length;
        continue;
      }
    }
    if (ch === '"') {
      i++;
      let identifier = '';
      let closed = false;
      while (i < source.length) {
        if (source[i] === '"' && source[i + 1] === '"') { identifier += '"'; i += 2; continue; }
        if (source[i] === '"') { i++; closed = true; break; }
        identifier += source[i++];
      }
      if (!closed) throw fail('ARIX_SQL_REJECTED', 'Unterminated quoted SQL identifier.');
      if (identifier) tokens.push(identifier.toUpperCase());
      continue;
    }
    if (ch === ';') { semicolons++; tokens.push(';'); i++; continue; }
    if (/[A-Za-z_]/.test(ch)) {
      let end = i + 1;
      while (end < source.length && /[A-Za-z0-9_$]/.test(source[end])) end++;
      tokens.push(source.slice(i, end).toUpperCase());
      i = end;
      continue;
    }
    i++;
  }
  if (semicolons > 1 || (semicolons === 1 && !source.trimEnd().endsWith(';'))) {
    throw fail('ARIX_SQL_REJECTED', 'Multiple PostgreSQL statements are not permitted in a scoped query.');
  }
  return tokens.filter((token) => token !== ';');
}

function normalizeQuery(query, values) {
  if (typeof query === 'string') return { text: query, values };
  if (!query || typeof query !== 'object' || Array.isArray(query) || typeof query.text !== 'string') {
    throw fail('ARIX_SQL_REJECTED', 'Only parameterized PostgreSQL query strings or {text, values} configurations are supported.');
  }
  const keys = Object.keys(query);
  if (keys.some((key) => !['text', 'values'].includes(key))) {
    throw fail('ARIX_SQL_REJECTED', 'Custom PostgreSQL query configurations are not supported by the tenant guard.');
  }
  return { text: query.text, values: query.values };
}

function assertScopedDml(text) {
  const tokens = sqlTokens(text);
  const first = tokens[0];
  if (BLOCKED_COMMANDS.has(first)) {
    throw fail('ARIX_SQL_CONTROL_BLOCKED', `PostgreSQL session, transaction, or administrative command (${first}) is blocked.`);
  }
  if (!ALLOWED_START.has(first)) throw fail('ARIX_SQL_REJECTED', `PostgreSQL command ${String(first || 'EMPTY')} is not allowed through the scoped request adapter.`);
  for (const token of tokens) {
    if (BLOCKED_FUNCTIONS.has(token)) {
      throw fail('ARIX_SQL_CONTROL_BLOCKED', `PostgreSQL session, transaction, administrative, or tenant-context control (${token}) is blocked.`);
    }
  }
}

function boundedTimeout(value, fallback, label) {
  const number = Number(value ?? fallback);
  if (!Number.isInteger(number) || number < 100 || number > 120_000) throw new RangeError(`${label} must be an integer from 100 to 120000 ms.`);
  return number;
}

async function runTenantTransaction(pool, callback, options) {
  if (typeof callback !== 'function') throw new TypeError('withTenantTransaction requires an async callback.');
  const context = getArixContext();
  if (!context) throw fail('ARIX_UNSCOPED_DB_ACCESS', 'A verified ArixShield request context is required.');
  const tenantId = safeIdentity(context.tenantId, 'tenant identity');
  const userId = safeIdentity(context.userId, 'user identity');
  const isolation = String(options.isolation || 'READ COMMITTED').toUpperCase();
  if (!['READ COMMITTED', 'REPEATABLE READ', 'SERIALIZABLE'].includes(isolation)) throw new TypeError('Unsupported PostgreSQL transaction isolation level.');
  const statementTimeoutMs = boundedTimeout(options.statementTimeoutMs, 5000, 'statementTimeoutMs');
  const lockTimeoutMs = boundedTimeout(options.lockTimeoutMs, 2000, 'lockTimeoutMs');
  const client = await pool.connect();
  let transactionOpen = false;
  let discardClient = false;
  try {
    await client.query(`BEGIN ISOLATION LEVEL ${isolation}${options.readOnly === true ? ' READ ONLY' : ''}`);
    transactionOpen = true;
    await client.query(
      "SELECT set_config('arix.tenant_id', $1, true), set_config('arix.user_id', $2, true), set_config('statement_timeout', $3, true), set_config('lock_timeout', $4, true)",
      [tenantId, userId, String(statementTimeoutMs), String(lockTimeoutMs)]
    );
    const scopedClient = Object.freeze({
      query(query, values) {
        const normalized = normalizeQuery(query, values);
        assertScopedDml(normalized.text);
        if (normalized.values !== undefined && !Array.isArray(normalized.values)) {
          throw fail('ARIX_SQL_REJECTED', 'PostgreSQL query values must be an array.');
        }
        return client.query(normalized.text, normalized.values);
      }
    });
    const result = await callback(scopedClient);
    await client.query('COMMIT');
    transactionOpen = false;
    return result;
  } catch (error) {
    if (transactionOpen) {
      try { await client.query('ROLLBACK'); }
      catch { discardClient = true; }
    }
    throw error;
  } finally {
    client.release?.(discardClient ? new Error('ArixShield tenant transaction rollback failed; discard connection.') : undefined);
  }
}

/**
 * Returns a deliberately narrow facade over a node-postgres Pool. The raw pool
 * is not exposed: callers must enter an AsyncLocalStorage-verified request scope
 * and use transaction-local PostgreSQL RLS context for every query.
 */
export function protectPgPool(pool, defaults = {}) {
  if (!pool || typeof pool.connect !== 'function') throw new TypeError('protectPgPool requires a node-postgres Pool with connect().');
  const facade = Object.freeze({
    withTenantTransaction(callback, options = {}) {
      return runTenantTransaction(pool, callback, { ...defaults, ...options });
    },
    async end() {
      if (typeof pool.end === 'function') return pool.end();
    }
  });
  protectedPools.set(facade, pool);
  return facade;
}

/** Runs a tenant transaction using a facade returned by protectPgPool(). */
export function withTenantTransaction(protectedPool, callback, options = {}) {
  const pool = protectedPools.get(protectedPool);
  if (!pool) throw new TypeError('withTenantTransaction requires a pool returned by protectPgPool().');
  return runTenantTransaction(pool, callback, options);
}
