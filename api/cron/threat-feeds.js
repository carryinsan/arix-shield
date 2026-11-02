import { createCompatibleHandler } from '../_lib/vercel-handler.js';
import { sendJson, methodNotAllowed, safeConstantStringEqual } from '../_lib/http.js';
import { refreshThreatFeeds } from '../_lib/reputation.js';

async function handler(req, res) {
  if (req.method !== 'GET' && req.method !== 'POST') return methodNotAllowed(res, ['GET', 'POST']);
  const secret = process.env.CRON_SECRET;
  const auth = String(req.headers?.authorization || '');
  if (!secret || !safeConstantStringEqual(auth, `Bearer ${secret}`)) return sendJson(res, 401, { error: 'Unauthorized cron request.' });
  try {
    const result = await refreshThreatFeeds();
    return sendJson(res, result.ok ? 200 : 503, result);
  } catch (error) {
    console.error('[ArixShield] threat feed refresh failed:', error?.stack || error);
    return sendJson(res, 503, { error: 'Threat feed refresh failed.' });
  }
}

export default createCompatibleHandler(handler);

// Keep raw request bytes available for origin-proof verification in the shared adapter.
export const config = { api: { bodyParser: false } };
