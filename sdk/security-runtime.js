import { randomUUID, createHash } from 'node:crypto';
import { verifySignedToken, verifyRequestDpopProof, createSignedToken, sha256Hex } from '../api/_lib/crypto-trap.js';
import { BoundedReplayCache, BoundedWindowQuotaStore } from '../api/_lib/bounded-replay-cache.js';

// The replay cache is process-local because this is the explicitly degraded-mode
// path. It is hard-bounded globally and per project/requester, and never evicts
// an unexpired proof. Expiry is heap-driven rather than a full Map scan.
const existingOutageReplay = globalThis.__ARIX_OUTAGE_REPLAY_CACHE__;
const outageReplay = existingOutageReplay && typeof existingOutageReplay.admit === 'function' && typeof existingOutageReplay.stats === 'function'
  ? existingOutageReplay
  : (globalThis.__ARIX_OUTAGE_REPLAY_CACHE__ = new BoundedReplayCache({ maxEntries: 32768, maxPerNamespace: 8192, maxPerPartition: 256 }));
const existingOutageBuckets = globalThis.__ARIX_OUTAGE_QUOTA_STORE__;
const outageBuckets = existingOutageBuckets && typeof existingOutageBuckets.consume === 'function'
  ? existingOutageBuckets
  : (globalThis.__ARIX_OUTAGE_QUOTA_STORE__ = new BoundedWindowQuotaStore({ maxEntries: 20000, maxPerNamespace: 4000 }));

function outageScopeHash(value) { return createHash('sha256').update(String(value ?? 'unknown')).digest('hex'); }

export function routeRequiresClearance(pathname, config = {}) {
  if (config === false || config?.enabled === false) return false;
  if (!Array.isArray(config?.paths)) return /\/(?:login|signup|checkout|otp|ai)(?:\/|$)/i.test(pathname);
  const paths = config.paths;
  return paths.some((raw) => {
    if (typeof raw !== 'string' || raw.length > 180) return false;
    const path = raw.split('?')[0];
    return path.endsWith('/**') ? pathname.startsWith(path.slice(0, -2)) : path.endsWith('/*') ? pathname.startsWith(path.slice(0, -1)) : pathname === path || pathname.startsWith(`${path}/`);
  });
}

export async function validateClearanceRequest({ headers, method, url, bodyBytes, projectId, clientIp = '', consumeSingleUse, consumeProofReplay, botProtection = {} }) {
  const ticket = headers.get ? headers.get('x-arix-clearance') : headers['x-arix-clearance'];
  const proof = headers.get ? headers.get('x-arix-pop') : headers['x-arix-pop'];
  const claims = await verifySignedToken(ticket, 'browser-clearance');
  if (!claims || claims.projectId !== projectId || !claims.singleUseNonce || claims.singleUseNonce.length < 20) return { valid: false, reason: 'CLEARANCE_INVALID' };
  // IP/ASN changes are expected during Wi-Fi, carrier and VPN handoffs.
  // The DPoP thumbprint and request proof provide session continuity instead.
  const maximumRisk = Math.max(0, Math.min(100, Number(botProtection.maxRiskScore ?? 50)));
  if (Number(claims.riskScore || 0) > maximumRisk) return { valid: false, reason: 'CLEARANCE_RISK_TOO_HIGH' };
  // JA4 is telemetry only; it must not invalidate a device-bound clearance.
  if (typeof consumeProofReplay !== 'function') return { valid: false, reason: 'DPOP_REPLAY_SERVICE_UNAVAILABLE', unavailable: true };
  const dpop = await verifyRequestDpopProof({ proof, method, url, bodyBytes, expectedThumbprint: claims.dpopThumbprint, clearanceNonce: claims.singleUseNonce, projectId, consumeReplay: consumeProofReplay });
  if (!dpop.valid) return { valid: false, reason: dpop.reason, unavailable: dpop.unavailable === true };
  if (botProtection.singleUse === true || /\/(?:signup|checkout)(?:\/|$)/i.test(new URL(url).pathname)) {
    if (typeof consumeSingleUse !== 'function') return { valid: false, reason: 'CLEARANCE_REPLAY_SERVICE_UNAVAILABLE', unavailable: true };
    try {
      const consumed = await consumeSingleUse(claims.singleUseNonce);
      if (!consumed) return { valid: false, reason: 'CLEARANCE_REPLAY' };
    } catch { return { valid: false, reason: 'CLEARANCE_REPLAY_SERVICE_UNAVAILABLE', unavailable: true }; }
  }
  return { valid: true, claims, thumbprint: dpop.thumbprint };
}



function routePatternMatches(pattern, pathname) {
  if (typeof pattern !== 'string' || pattern.length > 180) return false;
  const escaped = pattern.split('/').map((part) => {
    if (part === '**') return '.*';
    if (part === '*' || part.startsWith(':')) return '[^/]+';
    return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }).join('/');
  try { return new RegExp(`^${escaped}/?$`).test(pathname); } catch { return false; }
}

/** Validate and advance a signed, ordered workflow chain for configured routes. */
export async function validateWorkflowRequest({ config, method, pathname, headers, projectId, tenantId, actorId, consumeNonce }) {
  if (!config || config.enabled !== true) return { matched: false, valid: true };
  const workflows = Array.isArray(config.workflows) ? config.workflows.slice(0, 32) : [];
  const verb = String(method || 'GET').toUpperCase();
  let selected = null;
  for (const workflow of workflows) {
    if (!workflow || typeof workflow.id !== 'string' || !Array.isArray(workflow.steps) || workflow.steps.length < 2 || workflow.steps.length > 12) continue;
    const index = workflow.steps.findIndex((step) => String(step?.method || 'GET').toUpperCase() === verb && routePatternMatches(step?.path, pathname));
    if (index >= 0) { selected = { workflow, index }; break; }
  }
  if (!selected) return { matched: false, valid: true };
  const { workflow, index } = selected;
  const identity = String(actorId || '').trim();
  const tenant = String(tenantId || '').trim();
  const project = String(projectId || '').trim();
  if (!identity || identity === 'anonymous' || !tenant || !project) return { matched: true, valid: false, reason: 'WORKFLOW_IDENTITY_REQUIRED' };
  const actorHash = await sha256Hex(`${project}:${tenant}:${identity}`);
  const now = Date.now();
  const minStepMs = Math.max(0, Math.min(30000, Number(workflow.minStepMs ?? config.minStepMs ?? 1500)));
  const maxAgeMs = Math.max(5000, Math.min(900000, Number(workflow.maxAgeMs ?? config.maxAgeMs ?? 600000)));
  if (index > 0) {
    const supplied = headers?.get ? headers.get('x-arix-flow') : headers?.['x-arix-flow'];
    const claims = await verifySignedToken(supplied, 'arix-flow');
    const previous = workflow.steps[index - 1];
    if (!claims || claims.workflowId !== workflow.id || claims.projectId !== project || claims.tenantId !== tenant || claims.actorHash !== actorHash || claims.nextStep !== index || claims.previousStep !== index - 1 || claims.nextMethod !== verb || !routePatternMatches(claims.nextPath, pathname) || !claims.flowNonce || !Number.isFinite(Number(claims.stepStartedAt))) return { matched: true, valid: false, reason: 'WORKFLOW_BREADCRUMB_INVALID' };
    const elapsed = now - Number(claims.stepStartedAt);
    if (elapsed < minStepMs || elapsed > maxAgeMs || claims.previousMethod !== String(previous.method || 'GET').toUpperCase() || !routePatternMatches(previous.path, claims.previousPath)) return { matched: true, valid: false, reason: 'WORKFLOW_STEP_ORDER_OR_TIMING' };
    if (typeof consumeNonce !== 'function') return { matched: true, valid: false, unavailable: true, reason: 'WORKFLOW_REPLAY_SERVICE_UNAVAILABLE' };
    try {
      if (!await consumeNonce(claims.flowNonce)) return { matched: true, valid: false, reason: 'WORKFLOW_BREADCRUMB_REPLAY' };
    } catch { return { matched: true, valid: false, unavailable: true, reason: 'WORKFLOW_REPLAY_SERVICE_UNAVAILABLE' }; }
  }
  if (index >= workflow.steps.length - 1) return { matched: true, valid: true, complete: true, workflowId: workflow.id };
  const next = workflow.steps[index + 1];
  const nextMethod = String(next.method || 'GET').toUpperCase();
  const nextPath = String(next.path || '');
  const nonce = randomUUID();
  const ticket = await createSignedToken({
    workflowId: workflow.id, projectId: project, tenantId: tenant, actorHash,
    previousStep: index, nextStep: index + 1, previousMethod: verb, previousPath: pathname,
    nextMethod, nextPath, flowNonce: nonce, stepStartedAt: now, exp: now + maxAgeMs
  }, 'arix-flow');
  return { matched: true, valid: true, complete: false, workflowId: workflow.id, ticket };
}

export function quotaDimensions({ actor, subnet, tenant, method, pathname, limit }) {
  const base = Math.max(1, Math.min(10000, Math.floor(Number(limit) || 120)));
  return [
    { name: 'actor', scope: String(actor || 'anonymous').slice(0, 180), limit: base },
    // Shared network prefixes and multi-user tenants are aggregate fairness
    // envelopes, not per-person bans. Give them broad headroom so one school,
    // office NAT, mobile carrier or dashboard cannot consume another actor's
    // personal bucket at ordinary concurrency.
    { name: 'subnet', scope: String(subnet || 'unknown').slice(0, 100), limit: Math.min(100000, base * 500) },
    { name: 'tenant', scope: String(tenant || 'default').slice(0, 180), limit: Math.min(100000, base * 100) },
    { name: 'endpoint', scope: `${String(method || 'GET').toUpperCase()}:${String(pathname || '/').slice(0, 200)}`, limit: Math.min(100000, base * 100) }
  ];
}

export async function makeOutageChallenge({ method, pathname, difficulty = 12, projectId = 'default', requesterKey = 'unknown' }) {
  const nonce = randomUUID();
  const normalizedDifficulty = Math.max(8, Math.min(20, Math.floor(Number(difficulty) || 12)));
  const projectHash = outageScopeHash(projectId);
  const requesterHash = outageScopeHash(requesterKey);
  const token = await createSignedToken({ nonce, method: String(method).toUpperCase(), pathname, projectHash, requesterHash, difficulty: normalizedDifficulty, exp: Date.now() + 60000 }, 'arix-outage-pow');
  return { token, nonce, difficulty: normalizedDifficulty, expiresInSeconds: 60 };
}

/**
 * Verify a degraded-mode proof and consume it only after the local read quota
 * admits the request. The callback inside BoundedReplayCache is synchronous,
 * so quota admission and replay insertion cannot interleave within this process.
 */
export async function verifyOutageProof(headerValue, method, pathname, {
  projectId = 'default', requesterKey = 'unknown', quotaKey, limit = 120, windowMs = 60000
} = {}) {
  if (typeof headerValue !== 'string' || headerValue.length > 4300) return { valid: false, reason: 'OUTAGE_POW_MALFORMED' };
  const split = headerValue.lastIndexOf(':');
  if (split < 1) return { valid: false, reason: 'OUTAGE_POW_MALFORMED' };
  const token = headerValue.slice(0, split);
  const solution = headerValue.slice(split + 1);
  if (!/^\d{1,16}$/.test(solution)) return { valid: false, reason: 'OUTAGE_POW_SOLUTION_INVALID' };
  const claims = await verifySignedToken(token, 'arix-outage-pow');
  if (!claims || claims.method !== String(method).toUpperCase() || claims.pathname !== pathname || !claims.nonce) return { valid: false, reason: 'OUTAGE_POW_INVALID' };
  const projectHash = outageScopeHash(projectId);
  const requesterHash = outageScopeHash(requesterKey);
  // New challenges are bound to both project and trusted requester prefix.
  if (claims.projectHash !== projectHash || claims.requesterHash !== requesterHash) return { valid: false, reason: 'OUTAGE_POW_SCOPE_MISMATCH' };
  const digest = await sha256Hex(`${claims.nonce}:${solution}`);
  const bits = Math.max(8, Math.min(20, Number(claims.difficulty) || 12));
  const hexZeroes = Math.floor(bits / 4);
  const remaining = bits % 4;
  if (!digest.startsWith('0'.repeat(hexZeroes)) || (remaining && (parseInt(digest[hexZeroes], 16) >> (4 - remaining)) !== 0)) return { valid: false, reason: 'OUTAGE_POW_INVALID' };

  const replayKey = await sha256Hex(token);
  let quota = null;
  const admission = outageReplay.admit(replayKey, {
    namespace: projectHash,
    partition: requesterHash,
    ttlMs: 60000
  }, () => {
    quota = consumeLocalOutageRead({
      key: String(quotaKey || `${projectHash}:${requesterHash}`).slice(0, 512),
      namespace: projectHash,
      limit,
      windowMs
    });
    return quota.allowed;
  });

  if (!admission.accepted) {
    if (admission.reason === 'ADMISSION_DENIED' && quota?.reason === 'STORE_CAPACITY') return { valid: false, reason: 'OUTAGE_QUOTA_STORE_CAPACITY', quota };
    if (admission.reason === 'ADMISSION_DENIED') return { valid: false, reason: 'OUTAGE_LOCAL_QUOTA', quota };
    if (admission.reason === 'REPLAY') return { valid: false, reason: 'OUTAGE_POW_REPLAY' };
    if (admission.reason.endsWith('CAPACITY')) return { valid: false, reason: 'OUTAGE_REPLAY_CAPACITY' };
    return { valid: false, reason: admission.reason || 'OUTAGE_REPLAY_UNAVAILABLE' };
  }
  return { valid: true, quota };
}

export function consumeLocalOutageRead({ key, namespace = 'default', limit, windowMs = 60000 }) {
  return outageBuckets.consume({ key, namespace, limit, windowMs });
}
