import { createCompatibleHandler } from './_lib/vercel-handler.js';
import { sendJson, methodNotAllowed } from './_lib/http.js';
import { getRedisConfigurationStatus, pingRedis } from './_lib/redis.js';
import { verifyRuntimeIntegrity } from './_lib/integrity.js';

async function handler(req, res) {
  if (req.method !== 'GET') return methodNotAllowed(res, ['GET']);

  const redis = getRedisConfigurationStatus();
  const masterSecret = typeof process.env.ARIX_MASTER_SECRET === 'string'
    && Buffer.byteLength(process.env.ARIX_MASTER_SECRET) >= 32;

  let redisPing = 'not_checked';
  let redisError = null;
  if (redis.configured) {
    try {
      const result = await pingRedis();
      redisPing = result === 'PONG' ? 'ok' : 'unexpected_response';
      if (redisPing !== 'ok') redisError = 'Upstash returned an unexpected PING result.';
    } catch (error) {
      redisPing = 'failed';
      redisError = String(error?.message || 'Upstash connection failed').slice(0, 180);
    }
  }

  const integrity = await verifyRuntimeIntegrity();
  const healthy = redis.configured && redisPing === 'ok' && masterSecret && integrity.ok;
  return sendJson(res, healthy ? 200 : 503, {
    ok: healthy,
    service: 'arixshield-api',
    runtime: 'nodejs',
    redis: { configured: redis.configured, mode: redis.mode, ping: redisPing },
    masterSecret: masterSecret ? 'configured' : 'missing_or_too_short',
    integrity: { ok: integrity.ok, production: integrity.production, issues: integrity.issues, manifestRoot: integrity.manifestRoot },
    ...(redisError ? { redisError } : {}),
    checkedAt: new Date().toISOString()
  });
}

export default createCompatibleHandler(handler);
