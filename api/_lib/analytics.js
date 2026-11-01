function validIdentifier(value, fallback) {
  const candidate = String(value || fallback);
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(candidate)) throw new Error('Invalid analytics table identifier.');
  return candidate;
}

function sanitizeEvent(projectId, event) {
  const timestamp = Number.isFinite(Date.parse(event.timestamp)) ? new Date(event.timestamp).toISOString() : new Date().toISOString();
  const details = JSON.stringify({
    findings: Array.isArray(event.findings) ? event.findings.slice(0, 20).map((finding) => ({
      id: String(finding?.id || '').slice(0, 64),
      category: String(finding?.category || '').slice(0, 48),
      severity: String(finding?.severity || '').slice(0, 16),
      detail: String(finding?.detail || '').slice(0, 180)
    })) : [],
    reason: typeof event.reason === 'string' ? event.reason.slice(0, 120) : undefined,
    riskScore: Math.max(0, Math.min(100, Number(event.riskScore) || 0))
  });
  return {
    timestamp,
    project_id: String(projectId).slice(0, 80),
    event_type: String(event.type || 'REQUEST').slice(0, 64),
    blocked: event.blocked === true ? 1 : 0,
    status: Math.max(0, Math.min(599, Number(event.status) || 0)),
    latency_ms: Math.max(0, Math.min(600000, Number(event.latencyMs) || 0)),
    route: String(event.path || '/').split('?')[0].slice(0, 240),
    method: String(event.method || 'GET').toUpperCase().slice(0, 12),
    ip: String(event.ip || '').slice(0, 64),
    country: String(event.country || '').slice(0, 2),
    city: String(event.city || '').slice(0, 80),
    asn: String(event.asn || '').slice(0, 24),
    actor_hash: String(event.actorHash || '').slice(0, 96),
    details
  };
}

export function analyticsConfigured() {
  return Boolean(process.env.ARIX_CLICKHOUSE_URL && process.env.ARIX_CLICKHOUSE_DATABASE && process.env.ARIX_CLICKHOUSE_USER && process.env.ARIX_CLICKHOUSE_PASSWORD)
    || Boolean(process.env.ARIX_TINYBIRD_INGEST_URL && process.env.ARIX_TINYBIRD_TOKEN);
}

export async function writeAnalyticsBatch(projectId, events) {
  if (!Array.isArray(events) || !events.length) return { accepted: 0, provider: 'none' };
  const rows = events.map((event) => sanitizeEvent(projectId, event));
  if (process.env.ARIX_CLICKHOUSE_URL && process.env.ARIX_CLICKHOUSE_DATABASE && process.env.ARIX_CLICKHOUSE_USER && process.env.ARIX_CLICKHOUSE_PASSWORD) {
    const database = validIdentifier(process.env.ARIX_CLICKHOUSE_DATABASE, 'default');
    const table = validIdentifier(process.env.ARIX_CLICKHOUSE_TABLE, 'arixshield_events');
    const endpoint = new URL(process.env.ARIX_CLICKHOUSE_URL);
    endpoint.searchParams.set('query', `INSERT INTO ${database}.${table} FORMAT JSONEachRow`);
    const auth = Buffer.from(`${process.env.ARIX_CLICKHOUSE_USER}:${process.env.ARIX_CLICKHOUSE_PASSWORD}`).toString('base64');
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-ndjson' },
      body: `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`,
      signal: AbortSignal.timeout(12000)
    });
    if (!response.ok) throw new Error(`ClickHouse insert failed (${response.status}): ${(await response.text()).slice(0, 180)}`);
    return { accepted: rows.length, provider: 'clickhouse' };
  }
  if (process.env.ARIX_TINYBIRD_INGEST_URL && process.env.ARIX_TINYBIRD_TOKEN) {
    const response = await fetch(process.env.ARIX_TINYBIRD_INGEST_URL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.ARIX_TINYBIRD_TOKEN}`, 'Content-Type': 'application/x-ndjson' },
      body: `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`,
      signal: AbortSignal.timeout(12000)
    });
    if (!response.ok) throw new Error(`Tinybird ingest failed (${response.status}): ${(await response.text()).slice(0, 180)}`);
    return { accepted: rows.length, provider: 'tinybird' };
  }
  throw new Error('No complete ClickHouse or Tinybird analytics configuration is available.');
}

export async function queryClickHouseSnapshot(projectId) {
  if (!process.env.ARIX_CLICKHOUSE_URL || !process.env.ARIX_CLICKHOUSE_DATABASE || !process.env.ARIX_CLICKHOUSE_USER || !process.env.ARIX_CLICKHOUSE_PASSWORD) return null;
  const database = validIdentifier(process.env.ARIX_CLICKHOUSE_DATABASE, 'default');
  const table = validIdentifier(process.env.ARIX_CLICKHOUSE_TABLE, 'arixshield_events');
  const safeProject = String(projectId).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 80);
  const query = `SELECT count() AS requests, countIf(blocked) AS blocked, quantile(0.50)(latency_ms) AS p50, quantile(0.95)(latency_ms) AS p95, quantile(0.99)(latency_ms) AS p99, countIf(status >= 400 AND status < 500) AS errors_4xx, countIf(status >= 500) AS errors_5xx FROM ${database}.${table} WHERE project_id = '${safeProject}' AND timestamp >= now() - INTERVAL 24 HOUR FORMAT JSON`;
  const endpoint = new URL(process.env.ARIX_CLICKHOUSE_URL);
  endpoint.searchParams.set('query', query);
  const auth = Buffer.from(`${process.env.ARIX_CLICKHOUSE_USER}:${process.env.ARIX_CLICKHOUSE_PASSWORD}`).toString('base64');
  const response = await fetch(endpoint, { headers: { Authorization: `Basic ${auth}` }, signal: AbortSignal.timeout(7000) });
  if (!response.ok) throw new Error(`ClickHouse analytics query failed (${response.status}).`);
  const payload = await response.json();
  return payload?.data?.[0] ?? null;
}

export async function queryTinybirdSnapshot(projectId) {
  if (!process.env.ARIX_TINYBIRD_QUERY_URL || !process.env.ARIX_TINYBIRD_TOKEN) return null;
  const endpoint = new URL(process.env.ARIX_TINYBIRD_QUERY_URL);
  endpoint.searchParams.set('project_id', String(projectId).slice(0, 80));
  const response = await fetch(endpoint, { headers: { Authorization: `Bearer ${process.env.ARIX_TINYBIRD_TOKEN}` }, signal: AbortSignal.timeout(7000) });
  if (!response.ok) throw new Error(`Tinybird dashboard query failed (${response.status}).`);
  const payload = await response.json();
  return Array.isArray(payload?.data) ? (payload.data[0] ?? null) : (payload && typeof payload === 'object' ? payload : null);
}
