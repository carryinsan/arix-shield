import { randomUUID } from 'node:crypto';
import { getString, setString, setAdd, trackWindowEvent, trackResourceVelocity, incrementWithExpiry } from './redis.js';
import { sha256Hex } from './crypto-trap.js';
import { formatIpPrefix } from './cidr.js';
import { recordProjectEvent } from './redis.js';

// Recognize database/object identifiers across UUID, Mongo ObjectId, ULID,
// CUID and opaque URL-safe ID formats so BOLA velocity and route catalogs do
// not silently ignore non-numeric resource identifiers.
const ID_SEGMENT = /^(?:\d{1,20}|[0-9a-f]{24}|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9A-HJKMNP-TV-Z]{26}|c[a-z0-9]{23,25}|[A-Za-z0-9_-]{20,128})$/i;
// Kept as a compatibility export for older integrations. Shared IP addresses are
// reputation/quota context only and are never a hard-ban identity.
export function isIpLocallyBlocked(_projectId, _ip) { return false; }

function hasStableActorIdentity(value) {
  const identity = String(value || '').trim().toLowerCase();
  return Boolean(identity) && identity !== 'anonymous' && !identity.startsWith('anonymous:');
}

export function normalizeRoute(path) {
  return String(path || '/').split('?')[0].split('/').map((part) => {
    let decoded = part;
    try { decoded = decodeURIComponent(part); } catch { /* malformed escapes remain literal */ }
    return ID_SEGMENT.test(decoded) ? ':id' : part;
  }).join('/').slice(0, 220) || '/';
}

export function extractResourceId(path) {
  const parts = String(path || '').split('?')[0].split('/').filter(Boolean);
  for (let index = parts.length - 1; index >= 0; index--) {
    let decoded = parts[index];
    try { decoded = decodeURIComponent(decoded); } catch { /* malformed escapes are not IDs */ }
    if (ID_SEGMENT.test(decoded)) return decoded.slice(0, 80);
  }
  return null;
}

function haversineKm(a, b) {
  const radians = (value) => value * Math.PI / 180;
  const dLat = radians(b.lat - a.lat);
  const dLon = radians(b.lon - a.lon);
  const value = Math.sin(dLat / 2) ** 2 + Math.cos(radians(a.lat)) * Math.cos(radians(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 6371 * 2 * Math.atan2(Math.sqrt(value), Math.sqrt(1 - value));
}

function validCoordinates(lat, lon) {
  return Number.isFinite(lat) && Number.isFinite(lon) && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
}

export async function recordThreatCorrelation(projectId, actorHash, ip, points, reason = 'SECURITY_SIGNAL') {
  const value = Math.max(0, Math.min(100, Math.floor(Number(points) || 0)));
  if (!value) return { actorScore: 0, subnetScore: 0, subnetActors: 0 };
  const actorKey = actorHash ? `arix:risk:actor:${projectId}:${actorHash}` : null;
  const prefix = formatIpPrefix(String(ip || ''));
  const subnetHash = prefix ? await sha256Hex(`${projectId}:${prefix}`) : null;
  const subnetKey = subnetHash ? `arix:risk:subnet:${projectId}:${subnetHash}` : null;
  const [actorScore, subnetScore] = await Promise.all([
    actorKey ? incrementWithExpiry(actorKey, 600, value) : Promise.resolve(0),
    subnetKey ? incrementWithExpiry(subnetKey, 600, value) : Promise.resolve(0)
  ]);
  if (subnetKey) await setString(`${subnetKey}:last`, String(reason).slice(0, 48), 600);
  return { actorScore: Math.min(1000, Number(actorScore) || 0), subnetScore: Math.min(1000, Number(subnetScore) || 0), subnetActors: 0, subnetHash };
}

async function readThreatCorrelation(projectId, actorHash, ip) {
  const prefix = formatIpPrefix(String(ip || ''));
  const subnetHash = prefix ? await sha256Hex(`${projectId}:${prefix}`) : null;
  const keys = [actorHash ? `arix:risk:actor:${projectId}:${actorHash}` : null, subnetHash ? `arix:risk:subnet:${projectId}:${subnetHash}` : null].filter(Boolean);
  const values = await Promise.all(keys.map((key) => getString(key)));
  return { actorScore: actorHash ? Math.max(0, Number(values[0]) || 0) : 0, subnetScore: subnetHash ? Math.max(0, Number(values.at(-1)) || 0) : 0 };
}

export async function isActorBackedOff(projectId, actorId, ip = '') {
  const identity = String(actorId || '').trim();
  const hasStableActor = hasStableActorIdentity(identity);
  const actorHash = hasStableActor ? await sha256Hex(`${projectId}:${identity.slice(0, 180)}`) : null;
  // A raw IP (or its hash) is deliberately not a ban key: carrier-grade NAT,
  // office gateways, VPN exits and campus networks are shared by unrelated users.
  const keys = actorHash ? [`arix:abuse:ban:${projectId}:${actorHash}`] : [];
  if (!keys.length) return { blocked: false, actorHash: null };
  const [values, correlation] = await Promise.all([Promise.all(keys.map((key) => getString(key))), readThreatCorrelation(projectId, actorHash, ip)]);
  const until = values.map(Number).filter((value) => Number.isFinite(value) && value > Date.now()).sort((a, b) => b - a)[0];
  const correlatedScore = Math.max(correlation.actorScore, correlation.subnetScore);
  if (correlation.actorScore >= 65) return { blocked: true, challenge: true, actorHash, riskScore: correlatedScore, actorScore: correlation.actorScore, subnetScore: correlation.subnetScore, retryAfterMs: 60000, reason: 'CROSS_ENDPOINT_RISK_THRESHOLD' };
  if (!until) return { blocked: false, challenge: correlation.subnetScore >= 65, actorHash, riskScore: correlatedScore, actorScore: correlation.actorScore, subnetScore: correlation.subnetScore };
  return { blocked: true, challenge: correlation.subnetScore >= 65, actorHash, riskScore: correlatedScore, actorScore: correlation.actorScore, subnetScore: correlation.subnetScore, retryAfterMs: until - Date.now() };
}

export function isReservedKnuthTrapId(value) {
  if (process.env.ARIX_RESERVED_TRAP_ID_SPACE !== 'true' || !/^\d{1,20}$/.test(String(value))) return false;
  try { return (BigInt(value) * 2654435761n) % 97n === 0n; } catch { return false; }
}

export async function banActorForHoneypot(projectId, actorId, _ip = '', durationMs = 24 * 60 * 60 * 1000) {
  const boundedDuration = Math.max(60_000, Math.min(24 * 60 * 60 * 1000, Number(durationMs) || 24 * 60 * 60 * 1000));
  const until = Date.now() + boundedDuration;
  const identity = String(actorId || '').trim();
  const hasStableActor = hasStableActorIdentity(identity);
  const actorHash = hasStableActor ? await sha256Hex(`${projectId}:${identity.slice(0, 180)}`) : null;
  if (actorHash) {
    await setString(`arix:abuse:ban:${projectId}:${actorHash}`, String(until), Math.ceil(boundedDuration / 1000));
    await setAdd(`arix:abuse:ban-actors:${projectId}`, actorHash, Math.ceil(boundedDuration / 1000));
    // Subnet correlation is accumulated only from distinct attributable actors.
    // It can raise challenge/review signals, but it never blocks the entire subnet.
    const prefix = formatIpPrefix(String(_ip || ''));
    if (prefix) {
      const subnetHash = await sha256Hex(`${projectId}:${prefix}`);
      const distinctBannedActors = await setAdd(`arix:abuse:banned-subnet-actors:${projectId}:${subnetHash}`, actorHash, 600);
      if (Number(distinctBannedActors) >= 3) await incrementWithExpiry(`arix:risk:subnet:${projectId}:${subnetHash}`, 600, 15);
    }
  }
  return { actorHash, until, scope: actorHash ? 'actor' : 'none' };
}

export async function recordRequestOutcome({ projectId, actorId, ip = '', method = 'GET', path = '/', status = 0, latencyMs = 0, country = '', city = '', asn = '', latitude, longitude, geoVelocityEnabled = false, shadowCatalogEnabled = false, resourceCapabilityVerified = false }) {
  const requestedActor = String(actorId || '').trim();
  // Never collapse anonymous users onto a shared public IP. SDKs should pass a
  // verified DPoP thumbprint for anonymous-but-device-bound requests; otherwise
  // isolate the event rather than creating a cross-user velocity identity.
  const effectiveActor = requestedActor && requestedActor.toLowerCase() !== 'anonymous' ? requestedActor : randomUUID();
  const actorHash = await sha256Hex(`${projectId}:${effectiveActor.slice(0, 180)}`);
  const now = Date.now();
  const requestId = randomUUID();
  const normalizedRoute = normalizeRoute(path);
  const numericStatus = Math.max(0, Math.min(599, Number(status) || 0));

  const [requestCount, unauthorizedCount] = await Promise.all([
    trackWindowEvent(`arix:abuse:all:${projectId}:${actorHash}`, requestId, 60000),
    numericStatus === 401 ? trackWindowEvent(`arix:abuse:401:${projectId}:${actorHash}`, requestId, 60000) : Promise.resolve(0)
  ]);
  let backoffMs = 0;
  if (unauthorizedCount >= 8 && requestCount >= 10 && unauthorizedCount / requestCount >= 0.4) {
    backoffMs = Math.min(5 * 60 * 1000, 2000 * (2 ** Math.min(7, unauthorizedCount - 8)));
    await setString(`arix:abuse:ban:${projectId}:${actorHash}`, String(now + backoffMs), Math.ceil(backoffMs / 1000));
    await setAdd(`arix:abuse:ban-actors:${projectId}`, actorHash, Math.ceil(backoffMs / 1000));
  }

  let bolaCount = 0;
  let bolaTriggered = false;
  let bolaObserved = false;
  const objectId = !resourceCapabilityVerified && [200, 403, 404].includes(numericStatus) ? extractResourceId(path) : null;
  let sequentialHits = 0;
  let reservedTrap = false;
  if (objectId) {
    const velocity = await trackResourceVelocity(`arix:abuse:resource:${projectId}:${actorHash}`, objectId, 60000);
    bolaCount = velocity.distinct;
    sequentialHits = velocity.sequential;
    // Numeric ranges are not deception tokens: a modulo-based 'trap ID' can
    // collide with a real invoice/order. Only explicitly registered canary IDs
    // are treated as traps by the response-outcome handler.
    reservedTrap = false;
    const threshold = Math.max(8, Number(process.env.ARIX_BOLA_DISTINCT_ID_THRESHOLD) || 12);
    const successEnumeration = numericStatus === 200 && (bolaCount > threshold || sequentialHits >= 2);
    const deniedEnumeration = [403, 404].includes(numericStatus) && bolaCount >= threshold;
    bolaObserved = successEnumeration;
    // A successful read-velocity heuristic is observation-only. It must never
    // lock out an accountant, dashboard fan-out, pagination, or a sealed ID.
    bolaTriggered = deniedEnumeration;
    if (deniedEnumeration) {
      const until = now + 2 * 60 * 1000;
      await setString(`arix:abuse:ban:${projectId}:${actorHash}`, String(until), 120);
      await setAdd(`arix:abuse:ban-actors:${projectId}`, actorHash, 120);
    }
  }

  const catalogEntry = `${String(method).toUpperCase().slice(0, 12)} ${normalizedRoute}`;
  // Catalog only when explicitly enabled; paths are normalized and bounded.
  if (shadowCatalogEnabled) {
    const { setAdd } = await import('./redis.js');
    await setAdd(`arix:api-catalog:${projectId}`, catalogEntry, 90 * 24 * 60 * 60);
  }

  let geoVelocity = null;
  const lat = Number(latitude);
  const lon = Number(longitude);
  if (geoVelocityEnabled && validCoordinates(lat, lon)) {
    const { getJson, setJson } = await import('./redis.js');
    const locationKey = `arix:geo-last:${projectId}:${actorHash}`;
    const previous = await getJson(locationKey);
    const current = { lat: Math.round(lat * 10) / 10, lon: Math.round(lon * 10) / 10, timestamp: now, country: String(country).slice(0, 2), city: String(city).slice(0, 64) };
    if (previous && Number.isFinite(previous.lat) && Number.isFinite(previous.lon) && Number.isFinite(previous.timestamp)) {
      const elapsedHours = Math.max(1 / 3600, (now - previous.timestamp) / 3600000);
      const distanceKm = haversineKm(previous, current);
      const speedKmh = distanceKm / elapsedHours;
      if (speedKmh > (Number(process.env.ARIX_GEO_MAX_SPEED_KMH) || 1100) && distanceKm > 500) {
        geoVelocity = { detected: true, distanceKm: Math.round(distanceKm), elapsedSeconds: Math.max(1, Math.round((now - previous.timestamp) / 1000)), estimatedSpeedKmh: Math.round(speedKmh), previousCountry: previous.country, currentCountry: current.country };
      }
    }
    await setJson(locationKey, current, 60 * 60 * 24 * 30);
  }

  if (backoffMs || bolaTriggered || bolaObserved || geoVelocity?.detected) {
    const event = {
      type: bolaObserved ? 'BOLA_SUCCESS_VELOCITY_OBSERVED' : bolaTriggered ? 'BOLA_DENIED_ENUMERATION' : backoffMs ? 'CREDENTIAL_STUFFING_BACKOFF' : 'GEO_VELOCITY_ANOMALY',
      blocked: bolaTriggered || backoffMs > 0,
      actorHash,
      route: normalizedRoute,
      method: String(method).toUpperCase().slice(0, 12),
      status: numericStatus,
      bolaDistinctIds: bolaCount,
      sequentialHits,
      reservedTrap,
      unauthorizedCount,
      requestCount,
      backoffMs,
      geoVelocity,
      timestamp: new Date(now).toISOString()
    };
    await recordProjectEvent(projectId, event, { threat: true, countRequest: false });
  }

  return { actorHash, requestCount, unauthorizedCount, unauthorizedRatio: requestCount ? unauthorizedCount / requestCount : 0, backoffMs, bolaDistinctIds: bolaCount, sequentialHits, reservedTrap, bolaObserved, bolaTriggered, capabilityVerified: resourceCapabilityVerified === true, geoVelocity };
}

export function sanitizeForensicEvent(event) {
  const route = String(event.path || '/').split('?')[0].slice(0, 220);
  const safeHeaders = {};
  const sourceHeaders = event.headers && typeof event.headers === 'object' ? event.headers : {};
  for (const name of ['accept', 'content-type', 'user-agent', 'x-request-id']) {
    if (sourceHeaders[name] !== undefined) safeHeaders[name] = String(sourceHeaders[name]).slice(0, 180);
  }
  return {
    timestamp: event.timestamp || new Date().toISOString(),
    method: String(event.method || 'GET').toUpperCase().slice(0, 12),
    route,
    status: Math.max(0, Math.min(599, Number(event.status) || 0)),
    blocked: event.blocked === true,
    ip: String(event.ip || '').slice(0, 64),
    country: String(event.country || '').slice(0, 2),
    asn: String(event.asn || '').slice(0, 24),
    safeHeaders,
    findings: Array.isArray(event.findings) ? event.findings.slice(0, 20).map((finding) => ({ id: String(finding.id || '').slice(0, 64), category: String(finding.category || '').slice(0, 48), severity: String(finding.severity || '').slice(0, 16) })) : []
  };
}
