const MAX_ADAPTER_BODY_BYTES = 262144;

function makeResponseShim() {
  const headers = new Headers();
  let body = '';
  const response = {
    statusCode: 200,
    headersSent: false,
    setHeader(name, value) {
      if (Array.isArray(value)) headers.set(name, value.join(', '));
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
  if (!request.body) return { text: '', size: 0, tooLarge: false };
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
        return { text: '', size, tooLarge: true };
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
  return { text: new TextDecoder().decode(bytes), size, tooLarge: false };
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
      try { return await handler(request, response); }
      catch (error) {
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
        if (body.tooLarge) headers['content-length'] = String(bodyLimit + 1);
        else if (body.size > 0) {
          headers['content-length'] = String(body.size);
          nodeRequest = { method: request.method, url: `${url.pathname}${url.search}`, headers, body: body.text };
        }
        if (nodeRequest === request) nodeRequest = { method: request.method, url: `${url.pathname}${url.search}`, headers, body: undefined };
      } else if (!request || typeof request.method !== 'string' || !request.headers) {
        shim.response.statusCode = 400;
        shim.response.setHeader('Content-Type', 'application/json; charset=utf-8');
        shim.response.end(JSON.stringify({ error: 'Invalid request supplied to API handler.', requestId }));
        return shim.toWebResponse();
      }

      await handler(nodeRequest, shim.response);
      return shim.toWebResponse();
    } catch (error) {
      sendAdapterError(shim.response, error, requestId);
      return shim.toWebResponse();
    }
  };
}
