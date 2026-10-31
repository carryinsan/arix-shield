import { createCompatibleHandler } from './_lib/vercel-handler.js';
import { sendJson, readJson, methodNotAllowed, sameOriginRequest } from './_lib/http.js';
import { requireSession } from './_lib/session.js';
import { decodeInvisibleWatermark } from './_lib/watermark.js';

async function handler(req, res) {
  if (req.method !== 'POST') return methodNotAllowed(res, ['POST']);
  if (!sameOriginRequest(req)) return sendJson(res, 403, { error: 'Cross-origin request rejected.' });
  try {
    const auth = await requireSession(req);
    if (!auth) return sendJson(res, 401, { error: 'Sign in to decode project watermarks.' });
    const body = await readJson(req, 260000);
    if (typeof body.text !== 'string' || body.text.length > 250000) return sendJson(res, 400, { error: 'Provide leaked text up to 250 KB.' });
    const result = await decodeInvisibleWatermark(body.text, auth.project.id);
    return sendJson(res, 200, result);
  } catch (error) {
    console.error('[ArixShield] /api/decode-leak request failed:', error?.stack || error);
    const status = Number(error.statusCode) || 503;
    return sendJson(res, status, { error: status === 503 ? 'Watermark decoder unavailable. Verify Upstash REST URL/token and ARIX_MASTER_SECRET.' : error.message });
  }
}

export default createCompatibleHandler(handler);
