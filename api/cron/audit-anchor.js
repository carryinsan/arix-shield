import { createCompatibleHandler } from '../_lib/vercel-handler.js';
import { sendJson, methodNotAllowed, safeConstantStringEqual } from '../_lib/http.js';
import { setMembers } from '../_lib/redis.js';
import { anchorPendingAuditEvents } from '../_lib/audit.js';

async function handler(req, res) {
  if (req.method !== 'GET' && req.method !== 'POST') return methodNotAllowed(res, ['GET', 'POST']);
  const secret = process.env.CRON_SECRET;
  if (!secret || !safeConstantStringEqual(String(req.headers?.authorization || ''), `Bearer ${secret}`)) return sendJson(res, 401, { error: 'Unauthorized cron request.' });
  const projects = await setMembers('arix:audit:projects');
  const results = [];
  for (const projectId of (Array.isArray(projects) ? projects : []).slice(0, 500)) {
    try { results.push(await anchorPendingAuditEvents(projectId)); }
    catch (error) { results.push({ projectId, error: String(error?.message || error).slice(0, 180) }); }
  }
  return sendJson(res, 200, { ok: true, projects: results });
}

export default createCompatibleHandler(handler);
