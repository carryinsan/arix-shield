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
