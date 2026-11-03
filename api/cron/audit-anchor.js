import { createCompatibleHandler } from '../_lib/vercel-handler.js';
import { sendJson, methodNotAllowed, safeConstantStringEqual } from '../_lib/http.js';
import { setMembers, recordProjectEvent } from '../_lib/redis.js';
import { anchorPendingAuditEvents } from '../_lib/audit.js';
import { runSecuritySelfTest } from '../_lib/security-self-test.js';
import { drainIncidentAlertOutbox } from '../_lib/alerts.js';

async function handler(req, res) {
  if (req.method !== 'GET' && req.method !== 'POST') return methodNotAllowed(res, ['GET', 'POST']);
  const secret = process.env.CRON_SECRET;
  if (!secret || !safeConstantStringEqual(String(req.headers?.authorization || ''), `Bearer ${secret}`)) return sendJson(res, 401, { error: 'Unauthorized cron request.' });
  const selfTest = await runSecuritySelfTest();
  const [projects, alertProjects] = await Promise.all([setMembers('arix:audit:projects'), setMembers('arix:outbox:projects')]);
  const projectIds = Array.isArray(projects) ? projects.slice(0, 500) : [];
  const alertProjectIds = Array.isArray(alertProjects) ? alertProjects.slice(0, 500) : [];
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
  let alertOutbox;
  try { alertOutbox = await drainIncidentAlertOutbox([...new Set(alertProjectIds)]); }
  catch (error) { alertOutbox = { delivered: 0, errors: [{ error: String(error?.message || error).slice(0, 180) }] }; }
  return sendJson(res, 200, { ok: results.every((item) => !item.error) && alertOutbox.errors.length === 0, selfTest: { passed: true, total: selfTest.total }, projects: results, alertOutbox });
}

export default createCompatibleHandler(handler);

// Keep raw request bytes available for origin-proof verification in the shared adapter.
export const config = { api: { bodyParser: false } };
