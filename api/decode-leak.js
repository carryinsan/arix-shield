import { assertProductionStore } from './_lib/redis.js';
import { requireSession } from './_lib/session.js';
import { assertMasterSecret } from './_lib/crypto-trap.js';
import { decodeWatermark } from './_lib/watermark.js';
import { jsonResponse, readJson, errorResponse, sameOriginRequest } from './_lib/http.js';

export default async function handler(req) {
  try {
    assertProductionStore();
    assertMasterSecret();
    if (req.method !== 'POST') return jsonResponse(req, { error: 'Method not allowed.' }, 405, { Allow: 'POST' });
    if (!sameOriginRequest(req)) return jsonResponse(req, { error: 'Cross-origin decoder request rejected.' }, 403);
    const auth = await requireSession(req);
    if (auth.response) return auth.response;
    const body = await readJson(req, 110000);
    let leakedText = '';
    if (typeof body.text === 'string') leakedText = body.text;
    else if (body.text && typeof body.text === 'object') leakedText = JSON.stringify(body.text);
    if (!leakedText || leakedText.length > 100000) return jsonResponse(req, { error: 'Paste text or JSON up to 100 KB.' }, 400);
    const projectId = auth.session.account.projectId;
    const decoded = await decodeWatermark(leakedText, projectId);
    if (!decoded) return jsonResponse(req, { found: false, error: 'No valid ArixShield attribution marker was found for this project.' }, 404);
    return jsonResponse(req, { found: true, attribution: decoded });
  } catch (error) {
    return errorResponse(req, error, 'Watermark decoder is temporarily unavailable.');
  }
}
