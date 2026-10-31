import { createCompatibleHandler } from './_lib/vercel-handler.js';
import { sendJson, readJson, methodNotAllowed, sameOriginRequest, getNetworkHints, normalizeOrigin } from './_lib/http.js';
import { requireSession } from './_lib/session.js';
import { getJson, setJson, getProjectDashboardSnapshot } from './_lib/redis.js';

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
        threats: threats.slice(0, 100)
      });
    }

    if (!sameOriginRequest(req)) return sendJson(res, 403, { error: 'Cross-origin request rejected.' });

    const body = await readJson(req, 8000);

    if (body.action === 'origins') {
      const nextOrigins = buildAllowedOrigins(body);
      if (nextOrigins.error) return sendJson(res, 400, { error: nextOrigins.error });

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
