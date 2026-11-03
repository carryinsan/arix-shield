import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { readFile } from 'node:fs/promises';
import { createPrivateKey, randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import { performance } from 'node:perf_hooks';
import { createOriginProof } from '../api/_lib/origin-lock.js';
import { cidrContains, parseCidr } from '../api/_lib/cidr.js';
import { verifyDeploymentHardening, parseRlsTableEnvironment } from '../api/_lib/deployment-attestation.js';

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade'
]);
const SINGLETON_HEADERS = new Set([
  'host', 'content-length', 'transfer-encoding', 'authorization',
  'content-type', 'x-arix-origin-proof', 'x-arix-client-ip'
]);
const FORWARDED_HEADERS = new Set([
  'forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-port',
  'x-forwarded-proto', 'x-real-ip', 'x-client-ip'
]);

function json(res, status, value, extra = {}) {
  if (res.headersSent || res.destroyed || res.writableEnded) return;
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(body.length),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    connection: 'close',
    ...extra
  });
  res.end(body);
}

function boundedInteger(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  if (!Number.isSafeInteger(number) || number < min || number > max) throw new TypeError(`Invalid bounded integer setting (${min}..${max}).`);
  return number;
}

function singletonHeaderViolations(rawHeaders) {
  const seen = new Set();
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const name = String(rawHeaders[i]).toLowerCase();
    if (!SINGLETON_HEADERS.has(name)) continue;
    if (seen.has(name)) return name;
    seen.add(name);
  }
  return null;
}

function trustedClientIp(req, trustedProxyCidrs, clientIpHeader) {
  const peer = String(req.socket?.remoteAddress || '').replace(/^::ffff:/i, '');
  if (!isIP(peer)) return null;
  if (!trustedProxyCidrs.length || !trustedProxyCidrs.some((cidr) => cidrContains(cidr, peer))) return peer;
  const supplied = req.headers[String(clientIpHeader).toLowerCase()];
  if (typeof supplied !== 'string' || supplied.length > 64 || supplied.includes(',')) return null;
  const candidate = supplied.trim().replace(/^\[|\]$/g, '');
  return isIP(candidate) ? candidate : null;
}

function sanitizeHeaders(req, upstream, clientIp, proof, bodyLength) {
  const connectionTokens = new Set(String(req.headers.connection || '').split(',').map((value) => value.trim().toLowerCase()).filter(Boolean));
  const headers = Object.create(null);
  for (const [rawName, rawValue] of Object.entries(req.headers)) {
    const name = rawName.toLowerCase();
    if (HOP_BY_HOP.has(name) || connectionTokens.has(name) || FORWARDED_HEADERS.has(name) || name.startsWith('x-forwarded-') || name.startsWith('x-vercel-') || name.startsWith('x-arix-')) continue;
    if (name === 'host' || name === 'content-length') continue;
    if (rawValue === undefined) continue;
    headers[name] = rawValue;
  }
  headers.host = upstream.host;
  headers['content-length'] = String(bodyLength);
  headers['x-arix-client-ip'] = clientIp;
  headers['x-arix-origin-proof'] = proof;
  headers['connection'] = 'close';
  return headers;
}

function readBoundedBody(req, state, maxBodyBytes, maxBufferedBytes, timeoutMs) {
  const declared = req.headers['content-length'];
  if (declared !== undefined) {
    if (typeof declared !== 'string' || !/^\d{1,12}$/.test(declared)) return Promise.reject(Object.assign(new Error('Invalid content length.'), { status: 400, closeRequest: true }));
    if (Number(declared) > maxBodyBytes) return Promise.reject(Object.assign(new Error('Request body too large.'), { status: 413, closeRequest: true }));
  }

  // Node's requestTimeout is not a reliable absolute deadline for a body that
  // continues to make tiny amounts of progress. This monotonic deadline covers
  // the entire body read, not just periods of inactivity.
  const deadline = performance.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let reserved = 0;
    let settled = false;
    let timer;

    const cleanup = () => {
      if (timer) clearTimeout(timer);
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('aborted', onAborted);
      req.off('error', onError);
    };
    const fail = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      req.pause();
      if (reserved) state.bufferedBytes = Math.max(0, state.bufferedBytes - reserved);
      reserved = 0;
      reject(error);
    };
    const onData = (chunkValue) => {
      if (performance.now() >= deadline) {
        fail(Object.assign(new Error('Request body deadline exceeded.'), { status: 408, closeRequest: true }));
        return;
      }
      const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue);
      if (size + chunk.length > maxBodyBytes) {
        fail(Object.assign(new Error('Request body too large.'), { status: 413, closeRequest: true }));
        return;
      }
      if (state.bufferedBytes + chunk.length > maxBufferedBytes) {
        fail(Object.assign(new Error('Edge buffer capacity exceeded.'), { status: 503, closeRequest: true }));
        return;
      }
      size += chunk.length;
      state.bufferedBytes += chunk.length;
      reserved += chunk.length;
      chunks.push(chunk);
    };
    const onEnd = () => {
      if (performance.now() >= deadline) {
        fail(Object.assign(new Error('Request body deadline exceeded.'), { status: 408, closeRequest: true }));
        return;
      }
      if (settled) return;
      settled = true;
      cleanup();
      resolve(Buffer.concat(chunks, size));
    };
    const onAborted = () => fail(Object.assign(new Error('Request body was aborted.'), { status: 400, closeRequest: true }));
    const onError = () => fail(Object.assign(new Error('Request body could not be read.'), { status: 400, closeRequest: true }));

    req.on('data', onData);
    req.once('end', onEnd);
    req.once('aborted', onAborted);
    req.once('error', onError);
    timer = setTimeout(() => fail(Object.assign(new Error('Request body deadline exceeded.'), { status: 408, closeRequest: true })), timeoutMs);
  });
}

function forwardRequest({ req, res, upstreamUrl, upstreamTls, body, clientIp, privateKey, timeoutMs }) {
  return new Promise((resolve) => {
    const requestTarget = req.url;
    const timestamp = Date.now();
    const nonce = randomBytes(16).toString('base64url');
    const proof = createOriginProof({ privateKey, timestamp, nonce, method: req.method, url: requestTarget, clientIp, body });
    const headers = sanitizeHeaders(req, upstreamUrl, clientIp, proof, body.length);
    const transport = upstreamUrl.protocol === 'https:' ? https : http;
    const requestOptions = {
      protocol: upstreamUrl.protocol,
      hostname: upstreamUrl.hostname,
      port: upstreamUrl.port || (upstreamUrl.protocol === 'https:' ? 443 : 80),
      method: req.method,
      path: requestTarget,
      headers,
      agent: upstreamUrl.protocol === 'https:' ? upstreamTls.agent : undefined,
      rejectUnauthorized: true,
      servername: upstreamUrl.hostname,
      ca: upstreamTls.ca,
      cert: upstreamTls.cert,
      key: upstreamTls.key,
      minVersion: 'TLSv1.2'
    };
    let settled = false;
    let absoluteTimer;
    const finish = () => {
      if (settled) return;
      settled = true;
      if (absoluteTimer) clearTimeout(absoluteTimer);
      resolve();
    };
    const proxyReq = transport.request(requestOptions, (proxyRes) => {
      const responseHeaders = Object.create(null);
      const connectionTokens = new Set(String(proxyRes.headers.connection || '').split(',').map((value) => value.trim().toLowerCase()).filter(Boolean));
      for (const [name, value] of Object.entries(proxyRes.headers)) {
        const lower = name.toLowerCase();
        if (HOP_BY_HOP.has(lower) || connectionTokens.has(lower)) continue;
        if (value !== undefined) responseHeaders[name] = value;
      }
      const upstreamStatus = proxyRes.statusCode || 502;
      if (upstreamStatus >= 400 && upstreamStatus < 500) responseHeaders.connection = 'close';
      res.writeHead(upstreamStatus, responseHeaders);
      proxyRes.pipe(res);
      proxyRes.once('end', finish);
      proxyRes.once('aborted', () => { if (!res.destroyed) res.destroy(); finish(); });
      proxyRes.once('error', () => { if (!res.headersSent) json(res, 502, { error: 'Upstream response failed.' }); else res.destroy(); finish(); });
    });
    // setTimeout is an idle-socket timeout; this separate deadline also bounds a
    // slow-drip response that periodically sends bytes without ever completing.
    absoluteTimer = setTimeout(() => proxyReq.destroy(new Error('Upstream absolute deadline exceeded.')), timeoutMs);
    proxyReq.setTimeout(timeoutMs, () => proxyReq.destroy(new Error('Upstream idle timeout.')));
    proxyReq.once('error', () => { json(res, 502, { error: 'Upstream unavailable.' }); finish(); });
    res.once('close', () => { if (!res.writableEnded) proxyReq.destroy(new Error('Downstream client disconnected.')); });
    if (body.length) proxyReq.write(body);
    proxyReq.end();
  });
}

/**
 * Creates a bounded reverse proxy that signs every forwarded request for the
 * origin-lock middleware. The service intentionally does not claim upstream
 * DDoS scrubbing; deploy it behind a provider with volumetric protection.
 */
export function createEdgeGatewayServer({
  upstreamUrl,
  privateKey,
  trustedProxyCidrs = [],
  clientIpHeader = 'x-forwarded-for',
  maxBodyBytes = 1_048_576,
  maxConcurrentRequests = 256,
  maxConnections = 512,
  maxBufferedBytes = 32 * 1024 * 1024,
  requestTimeoutMs = 15_000,
  upstreamTimeoutMs = 15_000,
  allowInsecureUpstream = false,
  upstreamCa = null,
  upstreamCert = null,
  upstreamKey = null,
  listenerTls = null,
  allowedSniHosts = [],
  requireClientCertificate = false,
  listenerClientCa = null,
  shedThreshold = 0.8,
  shedHeadersTimeoutMs = 2000,
  shedKeepAliveTimeoutMs = 1000,
  normalHeadersTimeoutMs = 10_000,
  normalKeepAliveTimeoutMs = 5000
} = {}) {
  const target = upstreamUrl instanceof URL ? upstreamUrl : new URL(String(upstreamUrl || ''));
  if (!['https:', 'http:'].includes(target.protocol) || target.username || target.password || target.hash || target.pathname !== '/' || target.search) throw new TypeError('EDGE_UPSTREAM_URL must be an HTTP(S) URL without credentials or a fragment.');
  if (target.protocol !== 'https:' && !(allowInsecureUpstream && ['127.0.0.1', '::1', 'localhost'].includes(target.hostname))) throw new TypeError('The origin upstream must use HTTPS. Plain HTTP is allowed only for loopback tests.');
  const signingKey = privateKey?.type === 'private' ? privateKey : createPrivateKey(privateKey);
  if (signingKey.asymmetricKeyType !== 'ed25519') throw new TypeError('The edge origin-signing key must be Ed25519.');
  const cidrs = trustedProxyCidrs.map((entry) => {
    const parsed = parseCidr(String(entry));
    if (!parsed) throw new TypeError(`Invalid trusted proxy CIDR: ${entry}`);
    return parsed;
  });
  if (!/^[a-z0-9-]{1,64}$/i.test(clientIpHeader)) throw new TypeError('Invalid client IP header name.');
  const limits = {
    maxBodyBytes: boundedInteger(maxBodyBytes, 1_048_576, 1024, 10 * 1024 * 1024),
    maxConcurrentRequests: boundedInteger(maxConcurrentRequests, 256, 1, 4096),
    maxConnections: boundedInteger(maxConnections, 512, 1, 8192),
    maxBufferedBytes: boundedInteger(maxBufferedBytes, 32 * 1024 * 1024, 1024 * 1024, 512 * 1024 * 1024),
    requestTimeoutMs: boundedInteger(requestTimeoutMs, 15_000, 1000, 120_000),
    upstreamTimeoutMs: boundedInteger(upstreamTimeoutMs, 15_000, 1000, 120_000)
  };
  const normalizedSniHosts = [...new Set((Array.isArray(allowedSniHosts) ? allowedSniHosts : String(allowedSniHosts || '').split(','))
    .map((value) => String(value).trim().toLowerCase().replace(/\.$/, ''))
    .filter(Boolean))];
  if (normalizedSniHosts.some((host) => host.length > 253 || !/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host))) throw new TypeError('EDGE_ALLOWED_SNI_HOSTS contains an invalid hostname.');
  if (listenerTls && process.env.NODE_ENV === 'production' && normalizedSniHosts.length === 0) throw new TypeError('Production TLS listener requires explicit EDGE_ALLOWED_SNI_HOSTS.');
  if (requireClientCertificate && (!listenerTls || !listenerClientCa)) throw new TypeError('Client-certificate mTLS requires a TLS listener and trusted client CA.');
  const threshold = Number(shedThreshold);
  if (!Number.isFinite(threshold) || threshold < 0.5 || threshold > 0.95) throw new RangeError('shedThreshold must be between 0.5 and 0.95.');
  const timeoutLimits = {
    highHeaders: boundedInteger(shedHeadersTimeoutMs, 2000, 1000, 10_000),
    highKeepAlive: boundedInteger(shedKeepAliveTimeoutMs, 1000, 500, 5000),
    normalHeaders: boundedInteger(normalHeadersTimeoutMs, 10_000, 2000, 30_000),
    normalKeepAlive: boundedInteger(normalKeepAliveTimeoutMs, 5000, 1000, 30_000)
  };
  const state = { activeRequests: 0, activeConnections: 0, bufferedBytes: 0, shedding: false };
  let server;
  const updateShedding = () => {
    if (!server) return;
    const pressure = Math.max(state.activeRequests, state.activeConnections);
    const enterAt = Math.max(1, Math.ceil(limits.maxConcurrentRequests * threshold));
    const exitAt = Math.max(0, Math.floor(limits.maxConcurrentRequests * Math.max(0.3, threshold - 0.15)));
    if (!state.shedding && pressure >= enterAt) state.shedding = true;
    else if (state.shedding && pressure <= exitAt) state.shedding = false;
    server.headersTimeout = state.shedding ? timeoutLimits.highHeaders : timeoutLimits.normalHeaders;
    server.keepAliveTimeout = state.shedding ? timeoutLimits.highKeepAlive : timeoutLimits.normalKeepAlive;
  };
  const upstreamTls = {
    ca: upstreamCa || undefined,
    cert: upstreamCert || undefined,
    key: upstreamKey || undefined,
    agent: target.protocol === 'https:' ? new https.Agent({ keepAlive: true, maxSockets: limits.maxConcurrentRequests, maxFreeSockets: 32, timeout: limits.upstreamTimeoutMs, rejectUnauthorized: true, minVersion: 'TLSv1.2', ca: upstreamCa || undefined }) : undefined
  };
  const serverOptions = { insecureHTTPParser: false, maxHeaderSize: 16 * 1024, requestTimeout: limits.requestTimeoutMs, headersTimeout: Math.min(limits.requestTimeoutMs, 10_000), keepAliveTimeout: 5_000, connectionsCheckingInterval: 3000 };
  const requestListener = async (req, res) => {
    if (req.method === 'GET' && req.url === '/_arix_edge_health') return json(res, 200, { ok: true });
    if (state.activeRequests >= limits.maxConcurrentRequests) return json(res, 503, { error: 'Gateway capacity exceeded.' }, { 'retry-after': '1' });
    state.activeRequests++;
    updateShedding();
    let bodyBytes = 0;
    try {
      if (!['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(req.method)) return json(res, 405, { error: 'Method not allowed.' }, { allow: 'GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS' });
      if (singletonHeaderViolations(req.rawHeaders)) return json(res, 400, { error: 'Ambiguous duplicate request header.' });
      if (req.headers['transfer-encoding'] && req.headers['content-length']) return json(res, 400, { error: 'Ambiguous request framing.' });
      if (req.headers.upgrade || req.headers.expect) return json(res, 417, { error: 'Protocol upgrade and expectation requests are not supported.' });
      if (typeof req.url !== 'string' || !req.url.startsWith('/') || req.url.startsWith('//') || req.url.length > 8192 || /[\r\n\u0000-\u001f\u007f#]/.test(req.url)) return json(res, 400, { error: 'Invalid request target.' });
      const resolved = new URL(req.url, target);
      if (resolved.origin !== target.origin || resolved.username || resolved.password) return json(res, 400, { error: 'Invalid request target.' });
      const clientIp = trustedClientIp(req, cidrs, clientIpHeader);
      if (!clientIp) return json(res, 400, { error: 'Trusted client address is unavailable.' });
      const body = await readBoundedBody(req, state, limits.maxBodyBytes, limits.maxBufferedBytes, limits.requestTimeoutMs);
      bodyBytes = body.length;
      await forwardRequest({ req, res, upstreamUrl: target, upstreamTls, body, clientIp, privateKey: signingKey, timeoutMs: limits.upstreamTimeoutMs });
    } catch (error) {
      if (error?.closeRequest && !res.headersSent) {
        res.shouldKeepAlive = false;
        res.once('finish', () => {
          // Finish queues the complete error response before the graceful close.
          if (!req.socket.destroyed) req.socket.end();
        });
      }
      if (!res.headersSent) json(res, Number.isInteger(error?.status) ? error.status : 400, { error: error?.status === 408 ? 'Request body deadline exceeded.' : error?.status === 413 ? 'Request body too large.' : error?.status === 503 ? 'Gateway capacity exceeded.' : 'Request could not be processed.' });
      else res.destroy();
    } finally {
      state.bufferedBytes = Math.max(0, state.bufferedBytes - bodyBytes);
      state.activeRequests = Math.max(0, state.activeRequests - 1);
      updateShedding();
    }
  };
  const baseTlsOptions = listenerTls ? { ...listenerTls, minVersion: 'TLSv1.2' } : null;
  if (baseTlsOptions && requireClientCertificate) {
    baseTlsOptions.ca = listenerClientCa;
    baseTlsOptions.requestCert = true;
    baseTlsOptions.rejectUnauthorized = true;
  }
  if (baseTlsOptions && normalizedSniHosts.length) {
    const defaultContext = tls.createSecureContext(baseTlsOptions);
    baseTlsOptions.SNICallback = (servername, callback) => {
      const hostName = String(servername || '').toLowerCase().replace(/\.$/, '');
      if (!hostName || !normalizedSniHosts.includes(hostName)) {
        const error = new Error('TLS SNI hostname is not allowed.');
        if (typeof callback === 'function') callback(error);
        return;
      }
      if (typeof callback === 'function') callback(null, defaultContext);
    };
  }
  server = listenerTls
    ? https.createServer({ ...serverOptions, ...baseTlsOptions }, requestListener)
    : http.createServer(serverOptions, requestListener);
  server.maxHeadersCount = 100;
  server.maxRequestsPerSocket = 100;
  server.maxConnections = limits.maxConnections;
  server.on('connection', (socket) => {
    state.activeConnections++;
    updateShedding();
    socket.once('close', () => { state.activeConnections = Math.max(0, state.activeConnections - 1); updateShedding(); });
  });
  server.on('secureConnection', (socket) => {
    if (normalizedSniHosts.length && !normalizedSniHosts.includes(String(socket.servername || '').toLowerCase().replace(/\.$/, ''))) socket.destroy();
    if (requireClientCertificate && socket.authorized !== true) socket.destroy();
  });
  server.on('clientError', (_error, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
  });
  server.on('dropRequest', (_req, socket) => { if (socket.writable) socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); });
  server.on('close', () => upstreamTls.agent?.destroy());
  return server;
}

export async function startEdgeGateway(env = process.env) {
  if (env.ARIX_REQUIRE_HARDENED_RUNTIME === 'true') {
    await verifyDeploymentHardening({ tables: [], required: true });
  }
  const upstreamUrl = env.EDGE_UPSTREAM_URL;
  const keyFile = env.EDGE_ORIGIN_PRIVATE_KEY_FILE;
  if (!upstreamUrl || !keyFile) throw new Error('EDGE_UPSTREAM_URL and EDGE_ORIGIN_PRIVATE_KEY_FILE are required.');
  const [privateKeyPem, cert, key, ca] = await Promise.all([
    readFile(keyFile, 'utf8'),
    env.EDGE_UPSTREAM_MTLS_CERT_FILE ? readFile(env.EDGE_UPSTREAM_MTLS_CERT_FILE) : null,
    env.EDGE_UPSTREAM_MTLS_KEY_FILE ? readFile(env.EDGE_UPSTREAM_MTLS_KEY_FILE) : null,
    env.EDGE_UPSTREAM_CA_FILE ? readFile(env.EDGE_UPSTREAM_CA_FILE) : null
  ]);
  if (Boolean(cert) !== Boolean(key)) throw new Error('Both EDGE_UPSTREAM_MTLS_CERT_FILE and EDGE_UPSTREAM_MTLS_KEY_FILE must be supplied together.');
  const tlsCertFile = env.EDGE_TLS_CERT_FILE;
  const tlsKeyFile = env.EDGE_TLS_KEY_FILE;
  const listenerClientCaFile = env.EDGE_TLS_CLIENT_CA_FILE;
  const requireClientCertificate = env.EDGE_REQUIRE_CLIENT_CERT === 'true' || env.EDGE_REQUIRE_CLIENT_CERTIFICATE === 'true';
  if (Boolean(tlsCertFile) !== Boolean(tlsKeyFile)) throw new Error('Both EDGE_TLS_CERT_FILE and EDGE_TLS_KEY_FILE must be supplied together.');
  if (!tlsCertFile && env.NODE_ENV === 'production' && env.EDGE_TRUSTED_TLS_TERMINATOR !== 'true') throw new Error('Production edge gateway requires TLS files or a confirmed private TLS terminator (EDGE_TRUSTED_TLS_TERMINATOR=true).');
  if (requireClientCertificate && (!tlsCertFile || !listenerClientCaFile)) throw new Error('EDGE_REQUIRE_CLIENT_CERT=true requires EDGE_TLS_CERT_FILE, EDGE_TLS_KEY_FILE, and EDGE_TLS_CLIENT_CA_FILE.');
  if (listenerClientCaFile && !tlsCertFile) throw new Error('EDGE_TLS_CLIENT_CA_FILE requires an HTTPS listener certificate and key.');
  let listenerTls = null;
  if (tlsCertFile) {
    const [tlsCert, tlsKey] = await Promise.all([readFile(tlsCertFile), readFile(tlsKeyFile)]);
    listenerTls = { cert: tlsCert, key: tlsKey };
  }
  const listenerClientCa = listenerClientCaFile ? await readFile(listenerClientCaFile) : null;
  const allowedSniHosts = String(env.EDGE_ALLOWED_SNI_HOSTS || '').split(',').map((item) => item.trim()).filter(Boolean);
  const server = createEdgeGatewayServer({
    upstreamUrl,
    privateKey: privateKeyPem,
    trustedProxyCidrs: String(env.EDGE_TRUSTED_PROXY_CIDRS || '').split(',').map((item) => item.trim()).filter(Boolean),
    clientIpHeader: env.EDGE_CLIENT_IP_HEADER || 'x-forwarded-for',
    maxBodyBytes: boundedInteger(env.EDGE_MAX_BODY_BYTES, 1_048_576, 1024, 10 * 1024 * 1024),
    maxConcurrentRequests: boundedInteger(env.EDGE_MAX_CONCURRENT_REQUESTS, 256, 1, 4096),
    maxConnections: boundedInteger(env.EDGE_MAX_CONNECTIONS, 512, 1, 8192),
    maxBufferedBytes: boundedInteger(env.EDGE_MAX_BUFFERED_BYTES, 32 * 1024 * 1024, 1024 * 1024, 512 * 1024 * 1024),
    requestTimeoutMs: boundedInteger(env.EDGE_REQUEST_TIMEOUT_MS, 15_000, 1000, 120_000),
    upstreamTimeoutMs: boundedInteger(env.EDGE_UPSTREAM_TIMEOUT_MS, 15_000, 1000, 120_000),
    upstreamCa: ca,
    upstreamCert: cert,
    upstreamKey: key,
    listenerTls,
    allowedSniHosts,
    requireClientCertificate,
    listenerClientCa,
    shedThreshold: Number(env.EDGE_SHED_THRESHOLD || 0.8),
    shedHeadersTimeoutMs: boundedInteger(env.EDGE_SHED_HEADERS_TIMEOUT_MS, 2000, 1000, 10_000),
    shedKeepAliveTimeoutMs: boundedInteger(env.EDGE_SHED_KEEPALIVE_TIMEOUT_MS, 1000, 500, 5000)
  });
  const port = boundedInteger(env.PORT, 8080, 1, 65535);
  const host = env.EDGE_LISTEN_HOST || '0.0.0.0';
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  return server;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startEdgeGateway().then((server) => {
    const address = server.address();
    process.stdout.write(`[ArixShield edge] listening on ${typeof address === 'object' ? `${address.address}:${address.port}` : address}\n`);
    const shutdown = () => server.close(() => process.exit(0));
    process.once('SIGTERM', shutdown);
    process.once('SIGINT', shutdown);
  }).catch((error) => {
    process.stderr.write(`[ArixShield edge] startup failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
