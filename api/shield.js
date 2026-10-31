import { command, getJSON, setJSON, pushRing, incrementMetric, rateLimit, addActiveVisitor, assertProductionStore } from './_lib/redis.js';
import { findKeyEntry, verifyDpop, randomId, hashIdentifier, sha256, sha256Bytes, bindInfrastructure, assertMasterSecret } from './_lib/crypto-trap.js';
import { inspectRequestData, detectBotSignals, getNumericResourceId, isSequentialEnumeration } from './_lib/waf-engine.js';
import { watermarkOutboundJson, embedInvisibleWatermark, decodeWatermark } from './_lib/watermark.js';
import { jsonResponse, readJson, getRequestMetadata, getClientIp, corsHeaders, safeString } from './_lib/http.js';

const DATACENTER_ASNS = new Set(['16509', '14618', '14061', '63949', '16276', '24940', '20473', '174', '9009']);

function projectJson(req, data, status = 200, policy, extra = {}) {
  const origin = req.headers.get('origin') || '';
  const cors = Object.fromEntries(corsHeaders(origin, policy?.allowedOrigins || []).entries());
  return jsonResponse(req, data, status, { ...cors, ...extra });
}

function defaultPolicy(project) {
  const stored = project?.policy && typeof project.policy === 'object' ? project.policy : {};
  return {
    mode: stored.mode === 'DRY_RUN' ? 'DRY_RUN' : 'ENFORCE',
    rateLimitRPM: Math.max(10, Math.min(10000, Number(stored.rateLimitRPM) || 120)),
    rateAlgorithm: ['TOKEN_BUCKET', 'SLIDING_WINDOW', 'FIXED_WINDOW', 'LEAKY_BUCKET'].includes(stored.rateAlgorithm) ? stored.rateAlgorithm : 'SLIDING_WINDOW',
    blockDatacenter: stored.blockDatacenter === true,
    backendDnaLock: stored.backendDnaLock === true,
    tarpitEnabled: stored.tarpitEnabled !== false,
    canaryRows: stored.canaryRows === true,
    redactSecrets: stored.redactSecrets !== false,
    redactEmails: stored.redactEmails === true,
    blockBots: stored.blockBots === true,
    allowedOrigins: Array.isArray(project?.allowedOrigins) ? project.allowedOrigins : Array.isArray(stored.allowedOrigins) ? stored.allowedOrigins : []
  };
}

async function saveThreat(projectId, metadata, type, reason, extra = {}) {
  const event = {
    id: `thr_${randomId(8)}`,
    timestamp: new Date().toISOString(),
    type,
    reason: safeString(reason, 180),
    projectId,
    ip: metadata.ip,
    country: metadata.country,
    asn: metadata.asn,
    userAgent: metadata.userAgent,
    path: metadata.path,
    ...extra
  };
  await pushRing(`arix:threat_logs:${projectId}`, event, 500);
  if (type === 'TRAPPED_HACKER') await incrementMetric(`arix:metrics:${projectId}`, 'trappedHackers', 1);
  else if (type === 'BLOCKED_ATTACK') await incrementMetric(`arix:metrics:${projectId}`, 'blockedAttacks', 1);
  else await incrementMetric(`arix:metrics:${projectId}`, 'observedAttacks', 1);
  return event;
}

async function saveVisitor(projectId, metadata, body, latencyMs, status, popVerified, riskScore = 0) {
  const visitorId = safeString(body.visitorId || `v_${randomId(8)}`, 80);
  const event = {
    id: `vis_${randomId(7)}`,
    visitorId,
    timestamp: new Date().toISOString(),
    ip: metadata.ip,
    country: metadata.country,
    asn: metadata.asn,
    userAgent: metadata.userAgent,
    path: safeString(body.path || metadata.path, 240),
    latencyMs: Math.max(0, Math.min(60000, Math.round(latencyMs))),
    status,
    riskScore: Math.max(0, Math.min(100, riskScore)),
    dpopVerified: popVerified
  };
  await pushRing(`arix:live_visitors:${projectId}`, event, 500);
  const activeCount = await addActiveVisitor(`arix:active:${projectId}`, visitorId, Date.now(), 90000);
  await command('HSET', `arix:metrics:${projectId}`, 'activeVisitorCount', String(activeCount));
  return event;
}

function deterministicMirage(projectId, requestPath, fingerprint) {
  let seed = 2166136261;
  for (const ch of `${projectId}:${requestPath}:${fingerprint}`) seed = Math.imul(seed ^ ch.charCodeAt(0), 16777619) >>> 0;
  const id = (seed.toString(16).padStart(8, '0') + Math.imul(seed, 2246822519).toString(16).replace('-', '').slice(-8)).toLowerCase();
  return {
    status: 'success',
    environment: 'production-primary',
    data: {
      account_id: `acct_${id.slice(0, 12)}`,
      account_balance_usd: Number((120000 + (seed % 300000) / 100).toFixed(2)),
      internal_backup_s3: `s3://arix-canary-vault.invalid/snapshots/${id.slice(0, 8)}.json.gz`,
      aws_Honey_Access_Key: `AKIAARIXTRAP${id.slice(0, 12).toUpperCase()}`,
      database_host: `db-${id.slice(0, 6)}.internal.invalid`,
      internal_api_token: `ARIX_INTERNAL_${id.toUpperCase()}`,
      records: [{ id: `rec_${id.slice(2, 14)}`, state: 'completed', source: 'mirage' }]
    },
    meta: { request_id: `req_mirage_${id}`, synthetic: true }
  };
}

async function trapResponse(req, projectId, metadata, reason, policy) {
  const started = Date.now();
  const mirage = deterministicMirage(projectId, metadata.path, await hashIdentifier(getClientIp(req)));
  await saveThreat(projectId, metadata, 'TRAPPED_HACKER', reason, { deception: 'PHANTOM_SANDBOX', miragePreview: mirage.data });
  if (policy?.tarpitEnabled) {
    const delayMs = 450;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    await incrementMetric(`arix:metrics:${projectId}`, 'tarpitMsServed', delayMs);
  }
  return projectJson(req, { decision: 'MIRAGE', trapped: true, reason: safeString(reason, 140), data: mirage, latencyMs: Date.now() - started }, 200, policy, {
    'X-Arix-Decision': 'MIRAGE',
    'X-Arix-Synthetic': '1'
  });
}

function bearerOrHeader(req) {
  const headerKey = req.headers.get('x-arix-key');
  if (headerKey) return headerKey.trim();
  const authorization = req.headers.get('authorization') || '';
  return authorization.startsWith('Bearer ') ? authorization.slice(7).trim() : '';
}

async function verifyProjectContext(req, apiKey, keyEntry, project, policy, metadata, action, browserBindingId) {
  if (keyEntry.kind === 'CANARY') return { trapped: true, reason: 'CANARY_KEY_USED' };
  if (keyEntry.kind === 'LIVE' && !['pageview', 'enroll'].includes(action)) return { trapped: true, reason: 'BROWSER_KEY_USED_FOR_SERVER_API_ACCESS' };
  if (keyEntry.kind === 'SERVER' && ['pageview', 'enroll'].includes(action)) return { trapped: true, reason: 'SERVER_KEY_USED_FOR_BROWSER_TELEMETRY' };
  const pop = req.headers.get('x-arix-pop');
  if (pop) {
    if (keyEntry.kind === 'LIVE' && !browserBindingId) return { trapped: true, reason: 'BROWSER_BINDING_ID_REQUIRED' };
    const popBinding = keyEntry.kind === 'LIVE' ? await hashIdentifier(String(browserBindingId)) : 'server';
    const popKey = `arix:pop:${project.id}:${project.keyVersion || 1}:${popBinding}`;
    const expected = await command('GET', popKey);
    const proof = await verifyDpop(pop, { method: req.method, url: req.url, apiKey, expectedThumbprint: expected || undefined });
    if (!proof.valid) return { trapped: true, reason: proof.reason };
    if (!expected) {
      const inserted = await command('SET', popKey, proof.thumbprint, 'NX', 'EX', 31536000);
      if (inserted !== 'OK') {
        const saved = await command('GET', popKey);
        if (saved !== proof.thumbprint) return { trapped: true, reason: 'DPoP_ENROLLMENT_RACE_OR_KEY_MISMATCH' };
      }
    }
    const origin = req.headers.get('origin');
    if (origin && !policy.allowedOrigins.includes(origin)) return { trapped: true, reason: 'ORIGIN_NOT_ALLOWED' };
    if (keyEntry.kind !== 'LIVE') return { trapped: true, reason: 'DPoP_NOT_EXPECTED_FOR_SERVER_KEY' };
    return { valid: true, popVerified: true };
  }
  if (keyEntry.kind === 'LIVE') return { trapped: true, reason: 'MISSING_DPOP_PROOF' };
  if (policy.backendDnaLock) {
    const dna = await bindInfrastructure(project.id, req);
    if (!dna.match) return { trapped: true, reason: 'INFRASTRUCTURE_DNA_MISMATCH' };
  }
  return { valid: true, popVerified: false };
}

async function checkEnumeration(projectId, metadata, requestPath, actorId = '') {
  const id = getNumericResourceId(requestPath);
  if (!id) return false;
  const actorIdentity = safeString(actorId || metadata.ipFingerprint, 160);
  const actor = await hashIdentifier(`${projectId}:${actorIdentity}`);
  const key = `arix:bola:${projectId}:${actor}`;
  await command('ZADD', key, Date.now(), id);
  await command('ZREMRANGEBYSCORE', key, '-inf', Date.now() - 120000);
  await command('EXPIRE', key, 180);
  const values = await command('ZRANGE', key, 0, -1);
  return isSequentialEnumeration(values, 4);
}

async function recordRequest(projectId) {
  await incrementMetric(`arix:metrics:${projectId}`, 'totalRequests', 1);
}

async function evaluatePow(projectId, visitorId, headerValue) {
  if (!headerValue) {
    const token = randomId(18);
    await setJSON(`arix:pow:${projectId}:${token}`, { visitorId, expiresAt: Date.now() + 120000 }, 120);
    return { required: true, token, difficulty: 12 };
  }
  const [token, nonce] = String(headerValue).split('.', 2);
  if (!token || !nonce || token.length > 64 || nonce.length > 24 || !/^[A-Za-z0-9_-]+$/.test(token) || !/^[A-Za-z0-9_-]+$/.test(nonce)) return { valid: false };
  const challenge = await getJSON(`arix:pow:${projectId}:${token}`);
  if (!challenge || challenge.visitorId !== visitorId || challenge.expiresAt < Date.now()) return { valid: false };
  const digest = await sha256Bytes(`${token}:${nonce}`);
  if (digest[0] !== 0 || (digest[1] & 0xf0) !== 0) return { valid: false };
  const used = await command('SET', `arix:pow:used:${projectId}:${token}`, '1', 'NX', 'EX', 120);
  if (used !== 'OK') return { valid: false };
  await command('DEL', `arix:pow:${projectId}:${token}`);
  return { valid: true };
}

async function handleDemo(req, body) {
  const ipHash = await hashIdentifier(getClientIp(req));
  const rate = await rateLimit({ key: `arix:rl:demo:${ipHash}`, limit: 20, windowMs: 60000 });
  if (!rate.allowed) return jsonResponse(req, { error: 'Demo request limit reached. Try again in a minute.' }, 429);
  const scenario = String(body.scenario || 'legitimate');
  const projectId = 'demo';
  const metadata = getRequestMetadata(req);
  if (scenario === 'legitimate') {
    const visitor = await saveVisitor(projectId, metadata, { path: '/demo/catalog', visitorId: `demo_${ipHash.slice(0, 10)}` }, 4, 200, true, 0);
    await incrementMetric(`arix:metrics:${projectId}`, 'totalRequests', 1);
    return jsonResponse(req, { decision: 'ALLOW', demo: true, message: 'Demo request accepted. No customer origin was contacted.', visitor });
  }
  if (scenario === 'sqli') {
    const inspection = inspectRequestData({ path: '/api/users', method: 'GET', query: "id=1 UNION SELECT email,password FROM users" });
    await saveThreat(projectId, metadata, 'BLOCKED_ATTACK', inspection.findings.map((f) => f.id).join(', '), { demo: true, findings: inspection.findings });
    return jsonResponse(req, { decision: 'BLOCK', demo: true, status: 403, findings: inspection.findings, message: 'Lexical WAF detected a SQL injection pattern.' });
  }
  if (scenario === 'stolen') {
    const mirage = deterministicMirage(projectId, '/api/v1/accounts', ipHash);
    await saveThreat(projectId, metadata, 'TRAPPED_HACKER', 'DEMO_STOLEN_KEY_REPLAY', { demo: true, deception: 'PHANTOM_SANDBOX' });
    return jsonResponse(req, { decision: 'MIRAGE', demo: true, status: 200, mirage, message: 'A synthetic Mirage response was returned; no real account or origin data was accessed.' });
  }
  if (scenario === 'leak') {
    const sampleText = await embedInvisibleWatermark('Sample customer record', {
      projectId: 'demo', sessionId: 'sess_demo_9a81', userId: 'usr_demo_4412', ip: '203.0.113.24', source: 'landing-page-demo'
    });
    const decoded = await decodeWatermark(sampleText, 'demo');
    return jsonResponse(req, { decision: 'WATERMARKED', demo: true, sampleText, decoded, message: 'The invisible attribution marker was decoded from this demonstration record.' });
  }
  return jsonResponse(req, { error: 'Unknown demo scenario.' }, 400);
}

async function authorizeOrigin(req, policy) {
  const origin = req.headers.get('origin');
  if (!origin) return true;
  return policy.allowedOrigins.includes(origin);
}

export default async function handler(req) {
  try {
    assertProductionStore();
    assertMasterSecret();
    if (req.method === 'OPTIONS') {
      const origin = req.headers.get('origin') || '';
      let safeOrigin = '';
      try {
        const parsed = new URL(origin);
        if (['https:', 'http:'].includes(parsed.protocol)) safeOrigin = parsed.origin;
      } catch { /* invalid origins receive no allow-origin header */ }
      return new Response(null, { status: 204, headers: corsHeaders(safeOrigin, safeOrigin ? [safeOrigin] : []) });
    }
    if (req.method !== 'POST') return jsonResponse(req, { error: 'Method not allowed.' }, 405, { Allow: 'POST, OPTIONS' });
    const body = await readJson(req, 65536);
    if (body.action === 'demo') return handleDemo(req, body);

    const apiKey = bearerOrHeader(req);
    const keyEntry = await findKeyEntry(apiKey);
    if (!keyEntry) return jsonResponse(req, { error: 'A valid ArixShield project key is required.' }, 401);
    const project = await getJSON(`arix:project:${keyEntry.projectId}`);
    if (!project) return jsonResponse(req, { error: 'Project not found.' }, 401);
    const policy = defaultPolicy(project);
    const origin = req.headers.get('origin');
    if (origin && !(await authorizeOrigin(req, policy))) {
      return jsonResponse(req, { error: 'This origin is not authorized for the project.' }, 403, Object.fromEntries(corsHeaders(origin, []).entries()));
    }
    const metadata = getRequestMetadata(req);
    const started = Date.now();
    await recordRequest(project.id);
    const action = String(body.action || 'inspect');
    const context = await verifyProjectContext(req, apiKey, keyEntry, project, policy, metadata, action, body.visitorId);
    if (context.trapped) return trapResponse(req, project.id, metadata, context.reason, policy);

    const inspectionForQuota = body.inspection && typeof body.inspection === 'object' ? body.inspection : body;
    const quotaActor = action === 'pageview' ? safeString(body.visitorId || '', 80) : safeString(inspectionForQuota.actorId || '', 160);
    const quotaDimension = await hashIdentifier(`${metadata.ipFingerprint}:${quotaActor || 'ip-only'}`);
    const perProject = await rateLimit({
      key: `arix:rl:project:${project.id}:${quotaDimension}`,
      algorithm: policy.rateAlgorithm,
      limit: policy.rateLimitRPM,
      windowMs: 60000
    });
    if (!perProject.allowed) {
      const enforce = policy.mode === 'ENFORCE';
      await saveThreat(project.id, metadata, enforce ? 'BLOCKED_ATTACK' : 'OBSERVED_ATTACK', 'RATE_LIMIT_EXCEEDED', { retryAfterMs: perProject.retryAfterMs });
      return projectJson(req, { decision: enforce ? 'BLOCK' : 'DRY_RUN', reason: 'RATE_LIMIT_EXCEEDED', remaining: perProject.remaining, retryAfterMs: perProject.retryAfterMs }, enforce ? 429 : 200, policy, { 'Retry-After': String(Math.max(1, Math.ceil(perProject.retryAfterMs / 1000))) });
    }

    if (action === 'enroll') {
      if (!context.popVerified) return trapResponse(req, project.id, metadata, 'DPoP_REQUIRED_FOR_ENROLLMENT', policy);
      return projectJson(req, { decision: 'ENROLLED', projectId: project.id, dpop: 'verified' }, 200, policy);
    }
    if (action === 'pageview') {
      const visitorId = safeString(body.visitorId || `v_${randomId(8)}`, 80);
      const pow = await evaluatePow(project.id, visitorId, req.headers.get('x-arix-pow'));
      if (pow.required) return projectJson(req, { decision: 'CHALLENGE', challenge: pow.token, difficulty: pow.difficulty }, 428, policy);
      if (!pow.valid) return trapResponse(req, project.id, metadata, 'INVALID_OR_REPLAYED_PROOF_OF_WORK', policy);
      const bot = detectBotSignals({ userAgent: metadata.userAgent, headers: Object.fromEntries(req.headers.entries()), telemetry: body.telemetry || {} });
      const visitor = await saveVisitor(project.id, metadata, { ...body, visitorId }, Date.now() - started, 200, context.popVerified, bot.riskScore);
      if (bot.suspicious) await pushRing(`arix:threat_logs:${project.id}`, { id: `bot_${randomId(8)}`, type: 'BOT_SIGNAL', timestamp: new Date().toISOString(), ip: metadata.ip, path: visitor.path, signals: bot.signals, riskScore: bot.riskScore }, 500);
      return projectJson(req, { decision: 'RECORDED', visitorId: visitor.visitorId, riskScore: bot.riskScore }, 200, policy);
    }

    if (action === 'watermark') {
      if (keyEntry.kind !== 'SERVER') return trapResponse(req, project.id, metadata, 'INVALID_KEY_TYPE_FOR_WATERMARK', policy);
      const payload = await watermarkOutboundJson(body.payload, {
        projectId: project.id,
        sessionId: safeString(body.sessionId || `sess_${randomId(8)}`, 120),
        userId: safeString(body.userId || 'unknown', 120),
        ip: safeString(body.clientIp || body.attribution?.ip || metadata.ipFingerprint, 64),
        source: safeString(body.source || body.attribution?.source || 'server-middleware', 80)
      }, { canaryRows: policy.canaryRows, redactSecrets: policy.redactSecrets, redactEmails: policy.redactEmails });
      return projectJson(req, { decision: 'WATERMARKED', payload }, 200, policy);
    }

    if (action !== 'inspect') return jsonResponse(req, { error: 'Unsupported shield action.' }, 400);
    const inspection = body.inspection && typeof body.inspection === 'object' ? body.inspection : body;
    const requestPath = safeString(inspection.path || '/', 500);
    if (!requestPath.startsWith('/') || /[\r\n]/.test(requestPath)) return jsonResponse(req, { error: 'Invalid inspected path.' }, 400);
    const inspectedMethod = safeString(inspection.method || 'GET', 12).toUpperCase();
    if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'].includes(inspectedMethod)) return jsonResponse(req, { error: 'Unsupported inspected HTTP method.' }, 400);
    const waf = inspectRequestData({
      path: requestPath,
      method: inspectedMethod,
      query: safeString(inspection.query || '', 4000),
      headers: inspection.headers && typeof inspection.headers === 'object' ? inspection.headers : {},
      body: inspection.body ?? null
    });
    const bot = detectBotSignals({ userAgent: metadata.userAgent, headers: Object.fromEntries(req.headers.entries()), telemetry: body.telemetry || {} });
    const enumeration = await checkEnumeration(project.id, metadata, requestPath, inspection.actorId);
    if (enumeration) waf.findings.push({ id: 'BOLA_SEQUENTIAL_ID_ENUMERATION', severity: 'high' });
    if (bot.suspicious) waf.findings.push({ id: 'AUTOMATION_CLIENT_SIGNAL', severity: 'medium' });
    const datacenter = /^AS?(\d+)$/.exec(metadata.asn.replace(/\s/g, ''))?.[1];
    const humanOnlyPath = /\/(?:login|signup|checkout|register)(?:\/|$)/i.test(requestPath) && ['POST', 'PUT'].includes(inspectedMethod);
    const dcBlocked = policy.blockDatacenter && humanOnlyPath && datacenter && DATACENTER_ASNS.has(datacenter);
    if (dcBlocked) waf.findings.push({ id: 'DATACENTER_ASN_ON_HUMAN_ENDPOINT', severity: 'high' });
    const hasHigh = waf.findings.some((f) => f.severity === 'high');
    if (waf.findings.length) {
      await saveThreat(project.id, metadata, policy.mode === 'ENFORCE' && waf.findings.some((f) => f.severity === 'high') ? 'BLOCKED_ATTACK' : 'OBSERVED_ATTACK', waf.findings.map((f) => f.id).join(', '), { findings: waf.findings, riskScore: waf.riskScore });
    }
    const enforce = policy.mode === 'ENFORCE';
    const blocked = enforce && (hasHigh || (bot.suspicious && policy.blockBots));
    const response = {
      decision: blocked ? 'BLOCK' : waf.findings.length ? 'DRY_RUN' : 'ALLOW',
      status: blocked ? 403 : 200,
      findings: waf.findings,
      riskScore: Math.max(waf.riskScore, bot.riskScore),
      dpopVerified: context.popVerified,
      mode: policy.mode
    };
    return projectJson(req, response, blocked ? 403 : 200, policy, { 'X-Arix-Decision': response.decision });
  } catch (error) {
    const status = Number(error?.status) || 500;
    const message = status >= 500 ? 'Shield service is temporarily unavailable.' : String(error.message || 'Request rejected.');
    if (status >= 500) console.error('[ArixShield Shield]', error);
    return jsonResponse(req, { error: message }, status);
  }
}
