import { arixSafeFetch } from './safe-fetch.js';

const STATE_KEY = Symbol.for('arixshield.process-egress-firewall.v1');
const MAX_REQUEST_BODY_BYTES = 1024 * 1024;
const installations = new WeakMap();

async function readBoundedRequestBody(request, maximum) {
  if (!request.body) return undefined;
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      size += chunk.length;
      if (size > maximum) {
        await reader.cancel('ArixShield egress request body limit exceeded.').catch(() => {});
        throw new Error('Outbound request body exceeds the ArixShield egress limit.');
      }
      chunks.push(chunk);
    }
    return chunks.length ? Buffer.concat(chunks, size) : undefined;
  } finally {
    reader.releaseLock();
  }
}

/**
 * Installs an explicit, process-scoped global fetch guard. It validates methods,
 * bounds request/response bytes and delegates HTTPS/DNS pinning and redirect policy
 * to arixSafeFetch. It does not intercept node:http(s), raw sockets, native addons,
 * child processes, custom Undici dispatchers or kernel traffic.
 */
export function installProcessEgressFirewall({
  enabled = true,
  target = globalThis,
  fetchImpl = arixSafeFetch,
  safeFetch = fetchImpl,
  timeoutMs = 10_000,
  maxRedirects = 3,
  allowedPorts = [443],
  maxRequestBytes = MAX_REQUEST_BODY_BYTES,
  maxResponseBytes = 8 * 1024 * 1024,
  lockGlobalFetch = true
} = {}) {
  if (enabled !== true) return Object.freeze({ installed: false, mode: 'disabled', active: false, intercepts: [], doesNotIntercept: [] });
  if (!target || (typeof target !== 'object' && typeof target !== 'function')) throw new TypeError('A target global object is required.');
  if (typeof target.fetch !== 'function') throw new Error('The target runtime does not provide fetch.');
  if (typeof safeFetch !== 'function') throw new TypeError('safeFetch/fetchImpl must be a function.');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30_000) throw new RangeError('timeoutMs must be between 1000 and 30000.');
  if (!Number.isInteger(maxRedirects) || maxRedirects < 0 || maxRedirects > 5) throw new RangeError('maxRedirects must be between 0 and 5.');
  if (!Number.isInteger(maxRequestBytes) || maxRequestBytes < 1 || maxRequestBytes > MAX_REQUEST_BODY_BYTES) throw new RangeError('maxRequestBytes must be between 1 and 1048576.');
  if (!Number.isInteger(maxResponseBytes) || maxResponseBytes < 1024 || maxResponseBytes > 8 * 1024 * 1024) throw new RangeError('maxResponseBytes must be an integer from 1024 to 8388608.');
  if (!Array.isArray(allowedPorts) || !allowedPorts.length || allowedPorts.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) throw new RangeError('allowedPorts must contain valid TCP ports.');

  const existing = installations.get(target);
  if (existing?.active) return existing;
  const originalFetch = target.fetch;
  const guardedFetch = async function arixShieldEgressFetch(input, init = undefined) {
    const requestedMethod = String(init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
    if (!/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(requestedMethod)) throw new Error('Outbound method is not allowed by ArixShield.');
    let request;
    try { request = new Request(input, init); }
    catch { throw new TypeError('ArixShield egress guard requires a valid Fetch Request or URL.'); }
    const method = request.method.toUpperCase();
    const body = await readBoundedRequestBody(request.clone(), maxRequestBytes);
    if ((method === 'GET' || method === 'HEAD') && body?.length) throw new Error('GET and HEAD requests cannot carry a body.');
    // Preserve a caller-supplied string body for transports/tests that rely on
    // Fetch-compatible string semantics; Request inputs remain bounded Buffers.
    const fetchBody = !(input instanceof Request) && typeof init?.body === 'string' ? init.body : body;
    return safeFetch(request.url, {
      method,
      headers: request.headers,
      body: fetchBody,
      signal: request.signal,
      timeoutMs,
      maxRedirects,
      maxRequestBytes,
      maxResponseBytes,
      allowedPorts
    });
  };
  Object.defineProperty(guardedFetch, 'name', { value: 'fetch', configurable: true });

  try {
    Object.defineProperty(target, 'fetch', {
      configurable: true,
      enumerable: Object.prototype.propertyIsEnumerable.call(target, 'fetch'),
      writable: !lockGlobalFetch,
      value: guardedFetch
    });
  } catch (error) {
    throw new Error(`Unable to install ArixShield process fetch guard: ${String(error?.message || error).slice(0, 120)}`);
  }
  if (target.fetch !== guardedFetch) throw new Error('ArixShield process fetch guard could not be installed.');

  let active = true;
  const installation = {
    get active() { return active; },
    installed: true,
    mode: 'global-fetch-dns-pinned',
    intercepts: ['globalThis.fetch'],
    doesNotIntercept: ['node:http', 'node:https', 'node:net', 'native-addons', 'child-processes', 'custom-undici-dispatchers', 'os-network-stack'],
    uninstall() {
      if (!active) return false;
      active = false;
      if (target.fetch === guardedFetch) {
        try {
          Object.defineProperty(target, 'fetch', {
            configurable: true,
            enumerable: Object.prototype.propertyIsEnumerable.call(target, 'fetch'),
            writable: true,
            value: originalFetch
          });
        } catch { /* A locked target remains guarded until the process exits. */ }
      }
      installations.delete(target);
      try { if (target[STATE_KEY] === installation) delete target[STATE_KEY]; } catch { /* Best effort status cleanup. */ }
      return true;
    },
    restore() { return this.uninstall(); }
  };
  Object.freeze(installation);
  installations.set(target, installation);
  try { Object.defineProperty(target, STATE_KEY, { value: installation, enumerable: false, writable: false, configurable: true }); }
  catch { /* The WeakMap remains the authoritative status store. */ }
  return installation;
}

export function processEgressFirewallStatus(target = globalThis) {
  return installations.get(target) || target?.[STATE_KEY] || Object.freeze({ installed: false, mode: 'disabled', active: false, intercepts: [], doesNotIntercept: [] });
}
