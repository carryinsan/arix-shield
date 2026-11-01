import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { getString, setString, setAdd, trackWindowEvent, trackResourceVelocity } from './redis.js';
import { sha256Hex } from './crypto-trap.js';
import { recordProjectEvent } from './redis.js';

const ID_SEGMENT = /^(?:\d{1,20}|[0-9a-f]{8}-[0-9a-f-]{27,})$/i;
const localIpBlocks = globalThis.__ARIX_LOCAL_IP_BLOCKS__ ??= new Map();

export function isIpLocallyBlocked(projectId, ip) {
  const key = `${projectId}:${String(ip || '')}`; const until = Number(localIpBlocks.get(key) || 0);
  if (until <= Date.now()) { if (until) localIpBlocks.delete(key); return false; }
  return true;
}

function cacheLocalIpBlock(projectId, ip, until) {
  if (!isIP(String(ip || ''))) return; const key = `${projectId}:${ip}`; localIpBlocks.set(key, until);
  if (localIpBlocks.size > 10000) for (const [id, expiry] of localIpBlocks) if (expiry <= Date.now()) localIpBlocks.delete(id);
}

function normalizeRoute(path) {
  return String(path || '/').split('?')[0].split('/').map((part) => ID_SEGMENT.test(part) ? ':id' : part).join('/').slice(0, 220) || '/';
}

function extractResourceId(path) {
  const parts = String(path || '').split('?')[0].split('/').filter(Boolean);
  for (let index = parts.length - 1; index >= 0; index--) {
    if (ID_SEGMENT.test(parts[index])) return parts[index].slice(0, 80);
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

export async function isActorBackedOff(projectId, actorId, ip = '') {
  const identity = String(actorId || '').trim();
  const hasStableActor = identity.length > 0 && identity.toLowerCase() !== 'anonymous';
  const actorHash = hasStableActor ? await sha256Hex(`${projectId}:${identity.slice(0, 180)}`) : null;
  const ipHash = isIP(String(ip || '')) ? await sha256Hex(`${projectId}:${String(ip)}`) : null;
  const keys = [
    ...(actorHash ? [`arix:abuse:ban:${projectId}:${actorHash}`] : []),
    ...(ipHash ? [`arix:abuse:ban:${projectId}:${ipHash}`] : [])
  ];
  if (!keys.length) return { blocked: false, actorHash: null };
  const values = await Promise.all(keys.map((key) => getString(key)));
  const until = values.map(Number).filter((value) => Number.isFinite(value) && value > Date.now()).sort((a, b) => b - a)[0];
  if (!until) return { blocked: false, actorHash };
  return { blocked: true, actorHash, retryAfterMs: until - Date.now() };
}

export function isReservedKnuthTrapId(value) {
  if (process.env.ARIX_RESERVED_TRAP_ID_SPACE !== 'true' || !/^\d{1,20}$/.test(String(value))) return false;
  try { return (BigInt(value) * 2654435761n) % 97n === 0n; } catch { return false; }
}

export async function banActorForHoneypot(projectId, actorId, ip = '', durationMs = 24 * 60 * 60 * 1000) {
  const boundedDuration = Math.max(60_000, Math.min(24 * 60 * 60 * 1000, Number(durationMs) || 24 * 60 * 60 * 1000));
  const until = Date.now() + boundedDuration;
  const identity = String(actorId || '').trim();
  const hasStableActor = identity.length > 0 && identity.toLowerCase() !== 'anonymous';
  const actorHash = hasStableActor ? await sha256Hex(`${projectId}:${identity.slice(0, 180)}`) : null;
  if (actorHash) {
    await setString(`arix:abuse:ban:${projectId}:${actorHash}`, String(until), Math.ceil(boundedDuration / 1000));
    await setAdd(`arix:abuse:ban-actors:${projectId}`, actorHash, Math.ceil(boundedDuration / 1000));
  }
  if (isIP(String(ip || ''))) {
    const ipHash = await sha256Hex(`${projectId}:${String(ip)}`);
    await setString(`arix:abuse:ban:${projectId}:${ipHash}`, String(until), Math.ceil(boundedDuration / 1000));
    cacheLocalIpBlock(projectId, String(ip), until);
    await setAdd(`arix:abuse:ban-ips:${projectId}`, ipHash, Math.ceil(boundedDuration / 1000));
  }
  return { actorHash, until };
}

export async function recordRequestOutcome({ projectId, actorId, ip = '', method = 'GET', path = '/', status = 0, latencyMs = 0, country = '', city = '', asn = '', latitude, longitude, geoVelocityEnabled = false, shadowCatalogEnabled = false }) {
  const requestedActor = String(actorId || '').trim();
  const effectiveActor = requestedActor && requestedActor.toLowerCase() !== 'anonymous' ? requestedActor : (isIP(String(ip || '')) ? String(ip) : randomUUID());
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
  const objectId = [200, 403, 404].includes(numericStatus) ? extractResourceId(path) : null;
  let sequentialHits = 0;
  let reservedTrap = false;
  if (objectId) {
    const velocity = await trackResourceVelocity(`arix:abuse:resource:${projectId}:${actorHash}`, objectId, 60000);
    bolaCount = velocity.distinct;
    sequentialHits = velocity.sequential;
    reservedTrap = isReservedKnuthTrapId(objectId);
    const threshold = Math.max(8, Number(process.env.ARIX_BOLA_DISTINCT_ID_THRESHOLD) || 12);
    const successEnumeration = numericStatus === 200 && (bolaCount > threshold || sequentialHits >= 2);
    const deniedEnumeration = [403, 404].includes(numericStatus) && bolaCount >= threshold;
    bolaTriggered = successEnumeration || deniedEnumeration || (numericStatus === 200 && reservedTrap);
    if (bolaTriggered) {
      if (reservedTrap) await banActorForHoneypot(projectId, effectiveActor, ip, 24 * 60 * 60 * 1000);
      else {
        const until = now + 10 * 60 * 1000;
        await setString(`arix:abuse:ban:${projectId}:${actorHash}`, String(until), 600);
        await setAdd(`arix:abuse:ban-actors:${projectId}`, actorHash, 600);
      }
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

  if (backoffMs || bolaTriggered || geoVelocity?.detected) {
    const event = {
      type: reservedTrap ? 'BOLA_RESERVED_TRAP_ID' : bolaTriggered ? 'BOLA_ENUMERATION' : backoffMs ? 'CREDENTIAL_STUFFING_BACKOFF' : 'GEO_VELOCITY_ANOMALY',
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

  return { actorHash, requestCount, unauthorizedCount, unauthorizedRatio: requestCount ? unauthorizedCount / requestCount : 0, backoffMs, bolaDistinctIds: bolaCount, sequentialHits, reservedTrap, bolaTriggered, geoVelocity };
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
