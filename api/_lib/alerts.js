import { createHmac } from 'node:crypto';
import { arixSafeFetch } from '../../sdk/safe-fetch.js';

/** Signed outbound incident webhook. The receiver needs no API key; it verifies X-Arix-Signature. */
export async function dispatchIncidentAlert(webhookUrl, incident) {
  if (typeof webhookUrl !== 'string' || webhookUrl.length > 2048) throw new TypeError('Incident webhook URL is invalid.');
  const url = new URL(webhookUrl);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new Error('Incident webhook must be a credential-free HTTPS URL.');
  const secret = process.env.ARIX_MASTER_SECRET;
  if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32) throw new Error('ARIX_MASTER_SECRET is required to sign incident webhooks.');
  const timestamp = String(Date.now());
  const body = JSON.stringify({ schema: 'arixshield.incident.v1', timestamp: new Date(Number(timestamp)).toISOString(), ...incident });
  const signature = createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
  const response = await arixSafeFetch(url.href, {
    method: 'POST', timeoutMs: 5000, maxRedirects: 0,
    headers: { 'content-type': 'application/json', 'x-arix-timestamp': timestamp, 'x-arix-signature': `sha256=${signature}`, 'user-agent': 'ArixShield-Incident-Alert/1.0' },
    body
  });
  if (!response.ok) throw new Error(`Incident webhook returned HTTP ${response.status}.`);
  return { delivered: true, status: response.status };
}

import {
  acquireIncidentAlertLease, releaseIncidentAlertLease, getJson, recoverIncidentAlertClaims, claimIncidentAlert,
  ackIncidentAlert, retryIncidentAlert, deadLetterIncidentAlert
} from './redis.js';

/**
 * At-least-once webhook delivery from the Redis-backed outbox. A crash after a
 * receiver accepts a webhook but before its LREM acknowledgement can duplicate
 * delivery; consumers should deduplicate by the stable incident outboxId.
 */
export async function drainIncidentAlertOutbox(projectIds, { maxPerProject = 50, maxAttempts = 8 } = {}) {
  if (!Array.isArray(projectIds)) throw new TypeError('projectIds must be an array.');
  const limit = Math.max(1, Math.min(200, Math.floor(Number(maxPerProject) || 50)));
  const attemptsLimit = Math.max(1, Math.min(20, Math.floor(Number(maxAttempts) || 8)));
  const summary = { delivered: 0, retried: 0, deadLettered: 0, discarded: 0, errors: [] };
  for (const rawProjectId of projectIds.slice(0, 500)) {
    const projectId = String(rawProjectId || '').trim();
    if (!/^[A-Za-z0-9_-]{1,100}$/.test(projectId)) continue;
    try {
      // A bounded per-project lease prevents concurrent cron invocations from
      // recovering and delivering the same in-flight entries simultaneously.
      const leaseToken = await acquireIncidentAlertLease(projectId, 300);
      if (!leaseToken) continue;
      try {
        await recoverIncidentAlertClaims(projectId, 100, attemptsLimit);
        const project = await getJson(`arix:project:${projectId}`);
        const webhookUrl = typeof project?.policy?.alertWebhookUrl === 'string' ? project.policy.alertWebhookUrl : '';
        const attemptedIds = new Set();
        for (let index = 0; index < limit; index++) {
          const raw = await claimIncidentAlert(projectId);
          if (raw == null) break;
          let payload;
          try { payload = JSON.parse(raw); }
          catch {
            await ackIncidentAlert(projectId, raw); summary.discarded++; continue;
          }
          if (!webhookUrl || !payload?.incident || !payload?.id) {
            await ackIncidentAlert(projectId, raw); summary.discarded++; continue;
          }
          const payloadId = String(payload.id);
          // RPOPLPUSH is FIFO; a just-retried item eventually reaches the head
          // again in this invocation. Defer it instead of exhausting all retries
          // immediately or repeatedly hammering a failing webhook.
          if (attemptedIds.has(payloadId)) {
            await retryIncidentAlert(projectId, raw, raw);
            break;
          }
          attemptedIds.add(payloadId);
          const incident = { ...payload.incident, outboxId: payloadId, outboxCreatedAt: payload.createdAt };
          try {
            await dispatchIncidentAlert(webhookUrl, incident);
            await ackIncidentAlert(projectId, raw); summary.delivered++;
          } catch (error) {
            const attempts = Math.max(0, Number(payload.attempts) || 0) + 1;
            if (attempts >= attemptsLimit) {
              await deadLetterIncidentAlert(projectId, raw); summary.deadLettered++;
            } else {
              const next = JSON.stringify({ ...payload, attempts, lastErrorAt: new Date().toISOString() });
              await retryIncidentAlert(projectId, raw, next); summary.retried++;
            }
            summary.errors.push({ projectId, error: String(error?.message || error).slice(0, 160) });
            // A failed delivery is retried/dead-lettered above. Continue draining
            // independent incidents rather than allowing one poison webhook to
            // starve every later alert for this project.
            continue;
          }
        }
      } finally {
        await releaseIncidentAlertLease(projectId, leaseToken).catch(() => {});
      }
    } catch (error) {
      summary.errors.push({ projectId, error: String(error?.message || error).slice(0, 160) });
    }
  }
  return summary;
}
