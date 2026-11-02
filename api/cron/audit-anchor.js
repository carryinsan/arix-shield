import { createCompatibleHandler } from '../_lib/vercel-handler.js';
import { sendJson, methodNotAllowed, safeConstantStringEqual } from '../_lib/http.js';
import { setMembers } from '../_lib/redis.js';
import { anchorPendingAuditEvents } from '../_lib/audit.js';
import { runSecuritySelfTest } from '../_lib/security-self-test.js';
import { recordProjectEvent } from '../_lib/redis.js';

async function handler(req, res) {
  if (req.method !== 'GET' && req.method !== 'POST') return methodNotAllowed(res, ['GET', 'POST']);
  const secret = process.env.CRON_SECRET;
  if (!secret || !safeConstantStringEqual(String(req.headers?.authorization || ''), `Bearer ${secret}`)) return sendJson(res, 401, { error: 'Unauthorized cron request.' });
  const selfTest = await runSecuritySelfTest();
  const projects = await setMembers('arix:audit:projects');
  const projectIds = Array.isArray(projects) ? projects.slice(0, 500) : [];
  if (!selfTest.passed) {
    for (const projectId of projectIds) {
      try { await recordProjectEvent(projectId, { type: 'CRITICAL_SELF_TEST_FAILURE', blocked: true, timestamp: new Date().toISOString(), failed: selfTest.failed }, { threat: true, countRequest: false }); }
      catch (error) { console.error('[ArixShield] Could not persist self-test failure event:', String(error?.message || error).slice(0, 160)); }
    }
    return sendJson(res, 503, { ok: false, code: 'CRITICAL_SELF_TEST_FAILURE', selfTest, alertedProjects: projectIds.length });
  }
  const results = [];
  for (const projectId of projectIds) {
    try { results.push(await anchorPendingAuditEvents(projectId)); }
    catch (error) { results.push({ projectId, error: String(error?.message || error).slice(0, 180) }); }
  }
  return sendJson(res, 200, { ok: results.every((item) => !item.error), selfTest: { passed: true, total: selfTest.total }, projects: results });
}

export default createCompatibleHandler(handler);
