import { createPublicKey } from 'node:crypto';
import { verifyOriginProof } from './origin-lock.js';
import { setString } from './redis.js';

const MAX_ADAPTER_BODY_BYTES = 524288;
let cachedOriginKeySource = null;
let cachedOriginPublicKey = null;

function originLockConfigured() {
  return process.env.ARIX_ORIGIN_LOCK_REQUIRED === 'true' || Boolean(process.env.ARIX_ORIGIN_PUBLIC_KEY);
}

function loadOriginPublicKey() {
  const source = process.env.ARIX_ORIGIN_PUBLIC_KEY || '';
  if (!source || source.length > 16_384) return null;
  if (source !== cachedOriginKeySource) {
    cachedOriginKeySource = source;
    try { cachedOriginPublicKey = createPublicKey(source); } catch { cachedOriginPublicKey = null; }
  }
  return cachedOriginPublicKey?.asymmetricKeyType === 'ed25519' ? cachedOriginPublicKey : null;
}

async function readRawNodeBody(request, maxBytes) {
  if (Buffer.isBuffer(request.rawBody)) return request.rawBody;
  if (request.rawBody instanceof Uint8Array) return Buffer.from(request.rawBody);
  if (request.body !== undefined && request.body !== null) {
    if (typeof request.body === 'string') return Buffer.from(request.body);
    throw new Error('RAW_BODY_UNAVAILABLE');
  }
  const declared = Number(request.headers?.['content-length'] || 0);
  if (!Number.isFinite(declared) || declared < 0 || declared > maxBytes) throw new RangeError('REQUEST_BODY_LIMIT');
  const chunks = [];
  let size = 0;
  for await (const chunkValue of request) {
    const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue);
    size += chunk.length;
    if (size > maxBytes) throw new RangeError('REQUEST_BODY_LIMIT');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size);
}

async function verifyConfiguredOrigin(request, maxBytes) {
  if (!originLockConfigured()) return { valid: true, disabled: true };
  const publicKey = loadOriginPublicKey();
  if (!publicKey) return { valid: false, unavailable: true, reason: 'ORIGIN_PUBLIC_KEY_MISSING_OR_INVALID' };
  let rawBody;
  try { rawBody = await readRawNodeBody(request, maxBytes); }
  catch (error) { return { valid: false, unavailable: false, reason: error instanceof RangeError ? 'ORIGIN_BODY_LIMIT' : 'ORIGIN_RAW_BODY_UNAVAILABLE', status: error instanceof RangeError ? 413 : 503 }; }
  request.rawBody = rawBody;
  request.body = rawBody.length ? rawBody.toString('utf8') : undefined;
  const configuredAge = Number(process.env.ARIX_ORIGIN_MAX_AGE_MS ?? 30_000);
  const maxAgeMs = Number.isSafeInteger(configuredAge) ? Math.max(1_000, Math.min(120_000, configuredAge)) : 30_000;
  return verifyOriginProof(request, {
    publicKey, maxAgeMs,
    consumeNonce: async (nonce, expiresAt) => {
      const ttl = Math.max(1, Math.min(180, Math.ceil((Number(expiresAt) - Date.now()) / 1000) + 1));
      const saved = await setString(`arix:origin-proof:${nonce}`, '1', ttl, true);
      return saved === 'OK' || saved === true;
    }
  });
}

function rejectOrigin(response, result, requestId) {
  if (response.headersSent) return;
  response.statusCode = result.unavailable ? 503 : (result.status || 403);
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.setHeader('Cache-Control', 'no-store, max-age=0');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Arix-Request-Id', requestId);
  response.end(JSON.stringify({ error: result.unavailable ? 'Origin proof verification is unavailable.' : 'Direct origin access denied.', code: 'ORIGIN_LOCK_FAILED' }));
}

export function makeResponseShim() {
  const headers = new Headers();
  let body = '';
  const response = {
    statusCode: 200,
    headersSent: false,
    setHeader(name, value) {
      if (Array.isArray(value) && String(name).toLowerCase() === 'set-cookie') {
        headers.delete('set-cookie');
        for (const item of value) headers.append('set-cookie', String(item));
      } else if (Array.isArray(value)) headers.set(name, value.join(', '));
      else headers.set(name, String(value));
    },
    getHeader(name) { return headers.get(name); },
    end(value = '') {
      if (this.headersSent) return;
      this.headersSent = true;
      body = value == null ? '' : (typeof value === 'string' ? value : String(value));
    }
  };
  return {
    response,
    toWebResponse() {
      const noBody = [204, 205, 304].includes(response.statusCode);
      return new Response(noBody ? null : body, {
        status: response.statusCode,
        headers
      });
    }
  };
}

async function boundedTextBody(request, maxBytes = MAX_ADAPTER_BODY_BYTES) {
  if (!request.body) return { text: '', bytes: Buffer.alloc(0), size: 0, tooLarge: false };
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        try { await reader.cancel(); } catch { /* Request body is already rejected. */ }
        return { text: '', bytes: Buffer.alloc(0), size, tooLarge: true };
      }
      chunks.push(value);
    }
  } finally {
    try { reader.releaseLock(); } catch { /* The stream may already be closed. */ }
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { text: new TextDecoder().decode(bytes), bytes: Buffer.from(bytes), size, tooLarge: false };
}

function makeRequestId() {
  try { return globalThis.crypto.randomUUID(); }
  catch { return `req_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`; }
}

function sendAdapterError(response, error, requestId) {
  console.error(`[ArixShield] Unhandled API handler error ${requestId}:`, error?.stack || error);
  if (response.headersSent) return;
  response.statusCode = 500;
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.setHeader('Cache-Control', 'no-store, max-age=0');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Arix-Request-Id', requestId);
  response.end(JSON.stringify({ error: 'Internal server error.', requestId }));
}

function isNodeResponse(value) {
  return Boolean(value && typeof value.setHeader === 'function' && typeof value.end === 'function');
}

function isFetchRequest(value) {
  return Boolean(value && typeof value.method === 'string' && value.headers && typeof value.headers.get === 'function' && typeof value.url === 'string');
}

/**
 * Supports both Vercel's Node (IncomingMessage, ServerResponse) contract and
 * the Web Request/Response contract. This keeps API behavior consistent when
 * projects are moved between Vercel Node function adapters.
 */
export function createCompatibleHandler(handler, { maxBodyBytes = MAX_ADAPTER_BODY_BYTES } = {}) {
  if (typeof handler !== 'function') throw new TypeError('ArixShield handler must be a function.');
  const bodyLimit = Math.max(1024, Math.min(MAX_ADAPTER_BODY_BYTES, Math.floor(Number(maxBodyBytes) || MAX_ADAPTER_BODY_BYTES)));

  return async function arixVercelHandler(request, response) {
    const requestId = makeRequestId();

    if (isNodeResponse(response)) {
      try {
        if (originLockConfigured()) {
          if (!request || typeof request.method !== 'string' || !request.headers || !request.url) {
            rejectOrigin(response, { valid: false, status: 503, reason: 'ORIGIN_REQUEST_UNAVAILABLE' }, requestId);
            return;
          }
          const origin = await verifyConfiguredOrigin(request, bodyLimit);
          if (!origin.valid) { rejectOrigin(response, origin, requestId); return; }
        }
        return await handler(request, response);
      } catch (error) {
        sendAdapterError(response, error, requestId);
        return;
      }
    }

    const shim = makeResponseShim();
    try {
      let nodeRequest = request;
      if (isFetchRequest(request)) {
        const url = new URL(request.url);
        const headers = Object.fromEntries(request.headers.entries());
        if (!headers.host) headers.host = url.host;
        if (!headers['x-forwarded-proto']) headers['x-forwarded-proto'] = url.protocol.slice(0, -1);
        const body = await boundedTextBody(request, bodyLimit);
        if (body.tooLarge) {
          shim.response.statusCode = 413;
          shim.response.setHeader('Content-Type', 'application/json; charset=utf-8');
          shim.response.setHeader('Cache-Control', 'no-store, max-age=0');
          shim.response.end(JSON.stringify({ error: 'Request body too large.', requestId }));
          return shim.toWebResponse();
        } else if (body.size > 0) {
          headers['content-length'] = String(body.size);
          nodeRequest = { method: request.method, url: `${url.pathname}${url.search}`, headers, body: body.text, rawBody: body.bytes };
        }
        if (nodeRequest === request) nodeRequest = { method: request.method, url: `${url.pathname}${url.search}`, headers, body: undefined, rawBody: body.bytes };
      } else if (!request || typeof request.method !== 'string' || !request.headers) {
        shim.response.statusCode = 400;
        shim.response.setHeader('Content-Type', 'application/json; charset=utf-8');
        shim.response.end(JSON.stringify({ error: 'Invalid request supplied to API handler.', requestId }));
        return shim.toWebResponse();
      }

      if (originLockConfigured()) {
        const origin = await verifyConfiguredOrigin(nodeRequest, bodyLimit);
        if (!origin.valid) { rejectOrigin(shim.response, origin, requestId); return shim.toWebResponse(); }
      }
      await handler(nodeRequest, shim.response);
      return shim.toWebResponse();
    } catch (error) {
      sendAdapterError(shim.response, error, requestId);
      return shim.toWebResponse();
    }
  };
}
