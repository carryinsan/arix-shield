import { createCompatibleHandler } from './_lib/vercel-handler.js';
import { sendJson, readJson, methodNotAllowed, sameOriginRequest, getNetworkHints, normalizeOrigin } from './_lib/http.js';
import { requireSession } from './_lib/session.js';
import { getJson, setJson, getProjectDashboardSnapshot } from './_lib/redis.js';
import { queryClickHouseSnapshot, queryTinybirdSnapshot } from './_lib/analytics.js';
import { getThreatFeedStatus } from './_lib/reputation.js';
import { createHmac } from 'node:crypto';
import { verifyStepUpCredentials } from './_lib/step-up.js';

function parseEvents(values) {
  return (values ?? []).flatMap((value) => {
    try {
      const row = JSON.parse(value);
      return row && typeof row === 'object' ? [row] : [];
    } catch {
      return [];
    }
  });
}

function buildAllowedOrigins(body) {
  const primary = normalizeOrigin(body.origin);
  if (!primary) {
    return { error: 'Primary app origin must be a valid HTTPS origin (localhost is allowed for development).' };
  }

  if (body.customOrigins !== undefined && typeof body.customOrigins !== 'string') {
    return { error: 'Additional origins must be a comma-separated string.' };
  }

  const rawOrigins = String(body.customOrigins ?? '')
    .split(/[\n,]+/)
    .map((value) => value.trim())
    .filter(Boolean);
  const custom = [];

  for (const rawOrigin of rawOrigins) {
    const normalized = normalizeOrigin(rawOrigin);
    if (!normalized) {
      return { error: `Invalid origin: ${rawOrigin.slice(0, 120)}. Use an exact HTTPS origin without a path, query, or fragment.` };
    }
    if (normalized !== primary && !custom.includes(normalized)) custom.push(normalized);
    if (custom.length > 10) {
      return { error: 'You can add a maximum of 10 additional origins.' };
    }
  }

  return { origin: primary, allowedOrigins: [primary, ...custom] };
}

async function handler(req, res) {
  if (!['GET', 'POST'].includes(req.method)) return methodNotAllowed(res, ['GET', 'POST']);

  try {
    const auth = await requireSession(req);
    if (!auth) return sendJson(res, 401, { error: 'Sign in to view project telemetry.' });

    const { project } = auth;
    if (req.method === 'GET') {
      const snapshot = await getProjectDashboardSnapshot(project.id);
      const visitors = parseEvents(snapshot.visitors);
      const threats = parseEvents(snapshot.threats);
      const metrics = snapshot.metrics;
      let analytics = null;
      let threatFeedStatus = null;
      try { threatFeedStatus = await getThreatFeedStatus(); } catch { threatFeedStatus = { loaded: false, warning: true, staleFeeds: ['status-unavailable'] }; }
      try { analytics = await queryClickHouseSnapshot(project.id) || await queryTinybirdSnapshot(project.id); } catch (error) { console.warn('[ArixShield] External analytics dashboard query unavailable:', error?.message || error); }
      const cutoff = Date.now() - 60_000;
      const active = new Map();

      for (const event of visitors) {
        if (Date.parse(event.timestamp) >= cutoff && event.visitorId) {
          const old = active.get(event.visitorId);
          if (!old || Date.parse(old.timestamp) < Date.parse(event.timestamp)) active.set(event.visitorId, event);
        }
      }

      const allowedOrigins = Array.isArray(project.allowedOrigins) && project.allowedOrigins.length
        ? project.allowedOrigins
        : [project.origin].filter(Boolean);

      return sendJson(res, 200, {
        ok: true,
        project: {
          id: project.id,
          name: project.name,
          origin: project.origin,
          allowedOrigins
        },
        policy: project.policy,
        metrics: { ...metrics, activeVisitors: active.size },
        visitors: [...active.values()]
          .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))
          .slice(0, 100),
        threats: threats.slice(0, 100),
        forensicReplay: parseEvents(snapshot.forensicReplay).slice(0, 100),
        apiCatalog: Array.isArray(snapshot.apiCatalog) ? snapshot.apiCatalog : [],
        auditAnchor: snapshot.auditAnchor || null,
        auditChain: snapshot.auditChain || null,
        threatFeedStatus,
        analytics
      });
    }

    if (!sameOriginRequest(req)) return sendJson(res, 403, { error: 'Cross-origin request rejected.' });

    const body = await readJson(req, 8000);

    if (body.action === 'audit-bundle') {
      const chain = await getProjectDashboardSnapshot(project.id);
      if (!chain.auditChain?.verified) return sendJson(res, 409, { error: 'Audit chain did not verify; evidence export was refused.' });
      const secret = process.env.ARIX_MASTER_SECRET;
      if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32) return sendJson(res, 503, { error: 'ARIX_MASTER_SECRET >= 32 bytes is required to sign evidence.' });
      const bundle = { schema: 'arixshield.audit-evidence.v1', projectId: String(project.id), createdAt: new Date().toISOString(), auditChain: chain.auditChain };
      const signature = createHmac('sha256', secret).update(JSON.stringify(bundle)).digest('hex');
      return sendJson(res, 200, { ok: true, bundle, signature: { algorithm: 'HMAC-SHA256', value: signature } });
    }

    if (body.action === 'origins') {
      const nextOrigins = buildAllowedOrigins(body);
      if (nextOrigins.error) return sendJson(res, 400, { error: nextOrigins.error });
      const stepUp = await verifyStepUpCredentials({ ownerId: auth.session?.ownerId || project.ownerId, password: body.password, totpCode: body.totpCode });
      if (!stepUp.ok) return sendJson(res, stepUp.status, { error: stepUp.error });

      project.origin = nextOrigins.origin;
      project.allowedOrigins = nextOrigins.allowedOrigins;
      project.updatedAt = new Date().toISOString();
      await setJson(`arix:project:${project.id}`, project);

      return sendJson(res, 200, {
        ok: true,
        project: {
          id: project.id,
          name: project.name,
          origin: project.origin,
          allowedOrigins: project.allowedOrigins
        },
        effective: 'The updated allowlist is used by the next browser telemetry request.'
      });
    }

    if (body.action !== 'policy') return sendJson(res, 400, { error: 'Unknown telemetry action.' });

    const nextPolicy = { ...project.policy };
    if (body.mode !== undefined) {
      if (!['ENFORCE', 'DRY_RUN'].includes(body.mode)) {
        return sendJson(res, 400, { error: 'Invalid enforcement mode.' });
      }
      nextPolicy.mode = body.mode;
    }
    if (body.rateLimitPerMinute !== undefined) {
      const value = Number(body.rateLimitPerMinute);
      if (!Number.isInteger(value) || value < 10 || value > 10000) {
        return sendJson(res, 400, { error: 'Rate limit must be between 10 and 10,000 requests per minute.' });
      }
      nextPolicy.rateLimitPerMinute = value;
    }
    if (body.blockDatacenterAsn !== undefined) {
      if (typeof body.blockDatacenterAsn !== 'boolean') {
        return sendJson(res, 400, { error: 'blockDatacenterAsn must be boolean.' });
      }
      nextPolicy.blockDatacenterAsn = body.blockDatacenterAsn;
    }
    if (body.canaryRowsEnabled !== undefined) {
      if (typeof body.canaryRowsEnabled !== 'boolean') {
        return sendJson(res, 400, { error: 'canaryRowsEnabled must be boolean.' });
      }
      nextPolicy.canaryRowsEnabled = body.canaryRowsEnabled;
    }
    if (body.deceptionEnabled !== undefined) {
      if (typeof body.deceptionEnabled !== 'boolean') {
        return sendJson(res, 400, { error: 'deceptionEnabled must be boolean.' });
      }
      nextPolicy.deceptionEnabled = body.deceptionEnabled;
    }
    for (const flag of ['abuseProtectionEnabled', 'geoVelocityEnabled', 'threatFeedEnabled', 'shadowApiCatalogEnabled', 'forensicReplayEnabled']) {
      if (body[flag] !== undefined) {
        if (typeof body[flag] !== 'boolean') return sendJson(res, 400, { error: `${flag} must be boolean.` });
        nextPolicy[flag] = body[flag];
      }
    }
    if (body.autoContainmentEnabled !== undefined) {
      if (typeof body.autoContainmentEnabled !== 'boolean') return sendJson(res, 400, { error: 'autoContainmentEnabled must be boolean.' });
      nextPolicy.autoContainmentEnabled = body.autoContainmentEnabled;
    }
    if (body.alertWebhookUrl !== undefined) {
      const raw = String(body.alertWebhookUrl || '').trim();
      if (!raw) nextPolicy.alertWebhookUrl = null;
      else {
        if (raw.length > 2048) return sendJson(res, 400, { error: 'Alert webhook URL exceeds 2048 characters.' });
        let parsed;
        try { parsed = new URL(raw); } catch { return sendJson(res, 400, { error: 'Alert webhook URL is invalid.' }); }
        if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash) return sendJson(res, 400, { error: 'Alert webhook must be an HTTPS URL without credentials or a fragment.' });
        nextPolicy.alertWebhookUrl = parsed.href;
      }
    }

    if (body.mode === 'DRY_RUN' && project.policy?.mode !== 'DRY_RUN') {
      const stepUp = await verifyStepUpCredentials({ ownerId: auth.session?.ownerId || project.ownerId, password: body.password, totpCode: body.totpCode });
      if (!stepUp.ok) return sendJson(res, stepUp.status, { error: stepUp.error });
    }
    project.policy = nextPolicy;
    project.updatedAt = new Date().toISOString();
    await setJson(`arix:project:${project.id}`, project);
    return sendJson(res, 200, { ok: true, policy: nextPolicy });
  } catch (error) {
    console.error('[ArixShield] /api/telemetry request failed:', error?.stack || error);
    const status = Number(error.statusCode) || 503;
    return sendJson(res, status, {
      error: status === 503
        ? 'Telemetry service unavailable. Verify Upstash REST URL/token and inspect Vercel Function logs.'
        : error.message
    });
  }
}

export default createCompatibleHandler(handler);

// Keep raw request bytes available for origin-proof verification in the shared adapter.
export const config = { api: { bodyParser: false } };
