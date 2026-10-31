import { getJSON, setJSON, readRing, readHash, command, getActiveVisitorCount, assertProductionStore } from './_lib/redis.js';
import { requireSession } from './_lib/session.js';
import { assertMasterSecret } from './_lib/crypto-trap.js';
import { jsonResponse, readJson, errorResponse, sameOriginRequest, normalizeOrigin } from './_lib/http.js';

const POLICY_FIELDS = new Set(['mode', 'rateLimitRPM', 'rateAlgorithm', 'blockDatacenter', 'backendDnaLock', 'tarpitEnabled', 'canaryRows', 'redactSecrets', 'redactEmails', 'blockBots']);

function normalizePolicy(input, current) {
  const next = { ...current };
  for (const [key, value] of Object.entries(input || {})) {
    if (!POLICY_FIELDS.has(key)) continue;
    if (key === 'mode') {
      if (!['ENFORCE', 'DRY_RUN'].includes(value)) throw Object.assign(new Error('Mode must be ENFORCE or DRY_RUN.'), { status: 400 });
      next.mode = value;
    } else if (key === 'rateLimitRPM') {
      const limit = Number(value);
      if (!Number.isInteger(limit) || limit < 10 || limit > 10000) throw Object.assign(new Error('Rate limit must be from 10 to 10000 requests per minute.'), { status: 400 });
      next.rateLimitRPM = limit;
    } else if (key === 'rateAlgorithm') {
      if (!['TOKEN_BUCKET', 'SLIDING_WINDOW', 'FIXED_WINDOW', 'LEAKY_BUCKET'].includes(value)) throw Object.assign(new Error('Unsupported rate-limit algorithm.'), { status: 400 });
      next.rateAlgorithm = value;
    } else {
      if (typeof value !== 'boolean') throw Object.assign(new Error(`${key} must be true or false.`), { status: 400 });
      next[key] = value;
    }
  }
  return next;
}

async function getDashboardData(project) {
  const projectId = project.id;
  const visitors = await readRing(`arix:live_visitors:${projectId}`, 0, 199);
  const threats = await readRing(`arix:threat_logs:${projectId}`, 0, 199);
  const metrics = await readHash(`arix:metrics:${projectId}`);
  const activeCount = await getActiveVisitorCount(`arix:active:${projectId}`, 90000);
  const activeIds = await command('ZRANGE', `arix:active:${projectId}`, 0, -1);
  const activeSet = new Set(Array.isArray(activeIds) ? activeIds : []);
  const liveVisitors = visitors.filter((visitor) => activeSet.has(visitor.visitorId));
  const normalizedMetrics = {
    totalRequests: Number(metrics.totalRequests || 0),
    blockedAttacks: Number(metrics.blockedAttacks || 0),
    trappedHackers: Number(metrics.trappedHackers || 0),
    tarpitMsServed: Number(metrics.tarpitMsServed || 0),
    activeVisitorCount: activeCount
  };
  return {
    project: { id: project.id, name: project.name },
    metrics: normalizedMetrics,
    visitors: liveVisitors.slice(0, 100),
    recentVisitors: visitors.slice(0, 100),
    threats: threats.slice(0, 100),
    policy: project.policy || {}
  };
}

export default async function handler(req) {
  try {
    assertProductionStore();
    assertMasterSecret();
    if (req.method === 'GET') {
      const auth = await requireSession(req);
      if (auth.response) return auth.response;
      const project = await getJSON(`arix:project:${auth.session.account.projectId}`);
      if (!project || project.ownerId !== auth.session.account.id) return jsonResponse(req, { error: 'Project not found.' }, 404);
      return jsonResponse(req, await getDashboardData(project));
    }
    if (req.method === 'POST') {
      if (!sameOriginRequest(req)) return jsonResponse(req, { error: 'Cross-origin policy change rejected.' }, 403);
      const auth = await requireSession(req);
      if (auth.response) return auth.response;
      const body = await readJson(req, 8192);
      const project = await getJSON(`arix:project:${auth.session.account.projectId}`);
      if (!project || project.ownerId !== auth.session.account.id) return jsonResponse(req, { error: 'Project not found.' }, 404);
      if (body.action === 'policy') {
        project.policy = normalizePolicy(body.policy, project.policy || {});
        project.policy.allowedOrigins = Array.isArray(project.allowedOrigins) ? project.allowedOrigins : [];
        await setJSON(`arix:project:${project.id}`, project);
        return jsonResponse(req, { ok: true, policy: project.policy });
      }
      if (body.action === 'add_origin') {
        const origin = normalizeOrigin(body.origin);
        const origins = new Set(project.allowedOrigins || []);
        origins.add(origin);
        if (origins.size > 25) return jsonResponse(req, { error: 'A maximum of 25 origins is allowed.' }, 400);
        project.allowedOrigins = [...origins];
        project.policy = { ...(project.policy || {}), allowedOrigins: project.allowedOrigins };
        await setJSON(`arix:project:${project.id}`, project);
        return jsonResponse(req, { ok: true, allowedOrigins: project.allowedOrigins, policy: project.policy });
      }
      if (body.action === 'remove_origin') {
        const origin = normalizeOrigin(body.origin);
        project.allowedOrigins = (project.allowedOrigins || []).filter((item) => item !== origin);
        project.policy = { ...(project.policy || {}), allowedOrigins: project.allowedOrigins };
        await setJSON(`arix:project:${project.id}`, project);
        return jsonResponse(req, { ok: true, allowedOrigins: project.allowedOrigins, policy: project.policy });
      }
      return jsonResponse(req, { error: 'Unsupported telemetry action.' }, 400);
    }
    return jsonResponse(req, { error: 'Method not allowed.' }, 405, { Allow: 'GET, POST' });
  } catch (error) {
    return errorResponse(req, error, 'Telemetry service is temporarily unavailable.');
  }
}
