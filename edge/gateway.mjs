import http from 'node:http';
import https from 'node:https';
import { readFile } from 'node:fs/promises';
import { createPrivateKey, randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import { createOriginProof } from '../api/_lib/origin-lock.js';
import { cidrContains, parseCidr } from '../api/_lib/cidr.js';

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

async function readBoundedBody(req, state, maxBodyBytes, maxBufferedBytes) {
  const declared = req.headers['content-length'];
  if (declared !== undefined) {
    if (typeof declared !== 'string' || !/^\d{1,12}$/.test(declared)) throw Object.assign(new Error('Invalid content length.'), { status: 400 });
    if (Number(declared) > maxBodyBytes) throw Object.assign(new Error('Request body too large.'), { status: 413 });
  }
  const chunks = [];
  let size = 0;
  let reserved = 0;
  try {
    for await (const chunkValue of req) {
      const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue);
      size += chunk.length;
      state.bufferedBytes += chunk.length;
      reserved += chunk.length;
      if (size > maxBodyBytes) throw Object.assign(new Error('Request body too large.'), { status: 413 });
      if (state.bufferedBytes > maxBufferedBytes) throw Object.assign(new Error('Edge buffer capacity exceeded.'), { status: 503 });
      chunks.push(chunk);
    }
    return Buffer.concat(chunks, size);
  } catch (error) {
    state.bufferedBytes = Math.max(0, state.bufferedBytes - reserved);
    throw error;
  }
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
      res.writeHead(proxyRes.statusCode || 502, responseHeaders);
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
  maxBufferedBytes = 32 * 1024 * 1024,
  requestTimeoutMs = 15_000,
  upstreamTimeoutMs = 15_000,
  allowInsecureUpstream = false,
  upstreamCa = null,
  upstreamCert = null,
  upstreamKey = null,
  listenerTls = null
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
    maxBufferedBytes: boundedInteger(maxBufferedBytes, 32 * 1024 * 1024, 1024 * 1024, 512 * 1024 * 1024),
    requestTimeoutMs: boundedInteger(requestTimeoutMs, 15_000, 1000, 120_000),
    upstreamTimeoutMs: boundedInteger(upstreamTimeoutMs, 15_000, 1000, 120_000)
  };
  const state = { activeRequests: 0, bufferedBytes: 0 };
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
      const body = await readBoundedBody(req, state, limits.maxBodyBytes, limits.maxBufferedBytes);
      bodyBytes = body.length;
      await forwardRequest({ req, res, upstreamUrl: target, upstreamTls, body, clientIp, privateKey: signingKey, timeoutMs: limits.upstreamTimeoutMs });
    } catch (error) {
      if (!res.headersSent) json(res, Number.isInteger(error?.status) ? error.status : 400, { error: error?.status === 413 ? 'Request body too large.' : error?.status === 503 ? 'Gateway capacity exceeded.' : 'Request could not be processed.' });
      else res.destroy();
    } finally {
      state.bufferedBytes = Math.max(0, state.bufferedBytes - bodyBytes);
      state.activeRequests = Math.max(0, state.activeRequests - 1);
    }
  };
  const server = listenerTls
    ? https.createServer({ ...serverOptions, ...listenerTls, minVersion: 'TLSv1.2' }, requestListener)
    : http.createServer(serverOptions, requestListener);
  server.maxHeadersCount = 100;
  server.maxRequestsPerSocket = 100;
  server.on('clientError', (_error, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
  });
  server.on('dropRequest', (_req, socket) => { if (socket.writable) socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); });
  server.on('close', () => upstreamTls.agent?.destroy());
  return server;
}

export async function startEdgeGateway(env = process.env) {
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
  if (Boolean(tlsCertFile) !== Boolean(tlsKeyFile)) throw new Error('Both EDGE_TLS_CERT_FILE and EDGE_TLS_KEY_FILE must be supplied together.');
  if (!tlsCertFile && env.NODE_ENV === 'production' && env.EDGE_TRUSTED_TLS_TERMINATOR !== 'true') throw new Error('Production edge gateway requires TLS files or a confirmed private TLS terminator (EDGE_TRUSTED_TLS_TERMINATOR=true).');
  let listenerTls = null;
  if (tlsCertFile) {
    const [tlsCert, tlsKey] = await Promise.all([readFile(tlsCertFile), readFile(tlsKeyFile)]);
    listenerTls = { cert: tlsCert, key: tlsKey };
  }
  const server = createEdgeGatewayServer({
    upstreamUrl,
    privateKey: privateKeyPem,
    trustedProxyCidrs: String(env.EDGE_TRUSTED_PROXY_CIDRS || '').split(',').map((item) => item.trim()).filter(Boolean),
    clientIpHeader: env.EDGE_CLIENT_IP_HEADER || 'x-forwarded-for',
    maxBodyBytes: boundedInteger(env.EDGE_MAX_BODY_BYTES, 1_048_576, 1024, 10 * 1024 * 1024),
    maxConcurrentRequests: boundedInteger(env.EDGE_MAX_CONCURRENT_REQUESTS, 256, 1, 4096),
    maxBufferedBytes: boundedInteger(env.EDGE_MAX_BUFFERED_BYTES, 32 * 1024 * 1024, 1024 * 1024, 512 * 1024 * 1024),
    requestTimeoutMs: boundedInteger(env.EDGE_REQUEST_TIMEOUT_MS, 15_000, 1000, 120_000),
    upstreamTimeoutMs: boundedInteger(env.EDGE_UPSTREAM_TIMEOUT_MS, 15_000, 1000, 120_000),
    upstreamCa: ca,
    upstreamCert: cert,
    upstreamKey: key,
    listenerTls
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
