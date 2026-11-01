import { createCompatibleHandler } from '../_lib/vercel-handler.js';
import { sendJson, methodNotAllowed, safeConstantStringEqual } from '../_lib/http.js';
import { listPopBatch, listPushTrim, setMembers } from '../_lib/redis.js';
import { analyticsConfigured, writeAnalyticsBatch } from '../_lib/analytics.js';

async function handler(req, res) {
  if (req.method !== 'GET' && req.method !== 'POST') return methodNotAllowed(res, ['GET', 'POST']);
  const secret = process.env.CRON_SECRET;
  if (!secret || !safeConstantStringEqual(String(req.headers?.authorization || ''), `Bearer ${secret}`)) return sendJson(res, 401, { error: 'Unauthorized cron request.' });
  if (!analyticsConfigured()) return sendJson(res, 200, { ok: true, provider: 'not_configured', flushed: 0 });
  const projects = await setMembers('arix:analytics:projects');
  const output = [];
  let budget = Math.max(500, Math.min(25000, Number(process.env.ARIX_ANALYTICS_FLUSH_BUDGET) || 10000));
  for (const projectId of (Array.isArray(projects) ? projects : []).slice(0, 500)) {
    if (budget <= 0) break;
    const queueKey = `arix:analytics:queue:${projectId}`;
    let accepted = 0;
    while (budget > 0) {
      const raw = await listPopBatch(queueKey, Math.min(500, budget));
      const events = raw.flatMap((value) => { try { return [typeof value === 'string' ? JSON.parse(value) : value]; } catch { return []; } });
      if (!events.length) break;
      try {
        const result = await writeAnalyticsBatch(projectId, events);
        accepted += result.accepted || 0;
        budget -= events.length;
      } catch (error) {
        // Requeue bounded data on provider outage; request/credential data is never inserted.
        for (const event of [...events].reverse()) await listPushTrim(queueKey, event, Math.max(5000, Math.min(100000, Number(process.env.ARIX_ANALYTICS_QUEUE_RETENTION) || 50000)));
        output.push({ projectId, accepted, error: String(error?.message || error).slice(0, 180) });
        break;
      }
    }
    if (!output.some((row) => row.projectId === projectId)) output.push({ projectId, accepted });
  }
  return sendJson(res, 200, { ok: true, flushed: output.reduce((sum, row) => sum + (row.accepted || 0), 0), remainingBudget: budget, projects: output });
}

export default createCompatibleHandler(handler);
