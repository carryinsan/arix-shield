import { createHmac, timingSafeEqual } from 'node:crypto';
import { createCompatibleHandler } from './_lib/vercel-handler.js';
import { sendJson, methodNotAllowed } from './_lib/http.js';
import { getJson, setJson, deleteKeys, recordProjectEvent } from './_lib/redis.js';
import { hashCredential } from './_lib/crypto-trap.js';

export const config = { api: { bodyParser: false, sizeLimit: '512kb' } };

async function readRawBody(req, maxBytes = 512 * 1024) {
  if (typeof req.body === 'string') {
    if (Buffer.byteLength(req.body) > maxBytes) throw Object.assign(new Error('Webhook body too large.'), { statusCode: 413 });
    return Buffer.from(req.body);
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw Object.assign(new Error('Webhook body too large.'), { statusCode: 413 });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function verifySignature(raw, signature, secret) {
  if (typeof signature !== 'string' || !/^sha256=[a-f0-9]{64}$/i.test(signature)) return false;
  const expected = `sha256=${createHmac('sha256', secret).update(raw).digest('hex')}`;
  const left = Buffer.from(signature);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

async function handler(req, res) {
  if (req.method !== 'POST') return methodNotAllowed(res, ['POST']);
  const secret = process.env.ARIX_GITHUB_WEBHOOK_SECRET;
  if (!secret || Buffer.byteLength(secret) < 32) return sendJson(res, 503, { error: 'GitHub webhook is not configured.' });
  try {
    const raw = await readRawBody(req);
    if (!verifySignature(raw, req.headers?.['x-hub-signature-256'], secret)) return sendJson(res, 401, { error: 'Invalid webhook signature.' });
    const payload = JSON.parse(raw.toString('utf8'));
    const eventName = String(req.headers?.['x-github-event'] || '').slice(0, 80);
    if (eventName !== 'secret_scanning_alert' && eventName !== 'secret_scanning_scan') return sendJson(res, 202, { ok: true, ignored: true });

    const alert = payload.alert && typeof payload.alert === 'object' ? payload.alert : {};
    const candidate = typeof alert.secret === 'string' ? alert.secret : typeof payload.secret === 'string' ? payload.secret : null;
    let revoked = false;
    let projectId = null;
    if (candidate && candidate.length <= 512) {
      const digest = await hashCredential(candidate);
      const mapping = await getJson(`arix:key:${digest}`);
      if (mapping?.projectId && !mapping.revokedAt) {
        projectId = mapping.projectId;
        await setJson(`arix:key:${digest}`, { ...mapping, revokedAt: new Date().toISOString(), revokeReason: 'GITHUB_SECRET_SCANNING' });
        if (mapping.type === 'canary') await deleteKeys(`arix:canary:active:${mapping.projectId}`);
        revoked = true;
        await recordProjectEvent(projectId, {
          type: 'GITHUB_SECRET_EXPOSURE', blocked: true,
          secretType: String(alert.secret_type || 'unknown').slice(0, 80),
          repository: String(payload.repository?.full_name || '').slice(0, 160),
          alertNumber: Number(alert.number) || 0,
          timestamp: new Date().toISOString()
        }, { threat: true });
      }
    }

    // Standard GitHub App secret_scanning_alert payloads may not disclose the raw secret.
    // We never log the candidate value; a matched credential is revoked only when its hash is available.
    return sendJson(res, 202, {
      ok: true,
      event: eventName,
      alertNumber: Number(alert.number) || null,
      revoked,
      projectId,
      actionRequired: !candidate ? 'Rotate the exposed credential using your provider console; this webhook did not include the raw secret.' : (!revoked ? 'No active ArixShield credential matched the secret hash.' : null)
    });
  } catch (error) {
    const status = Number(error.statusCode) || (error instanceof SyntaxError ? 400 : 500);
    console.error('[ArixShield] GitHub webhook processing failed:', error?.message || error);
    return sendJson(res, status, { error: status === 400 ? 'Invalid webhook JSON.' : 'Webhook processing failed.' });
  }
}

export default createCompatibleHandler(handler);
