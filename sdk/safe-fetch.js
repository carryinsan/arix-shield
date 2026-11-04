import https from 'node:https';
import { resolve4, resolve6 } from 'node:dns/promises';
import { isIP } from 'node:net';
import { cidrContains } from '../api/_lib/cidr.js';

const BLOCKED_NETWORKS = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
  '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
  '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64',
  '2001::/23', '2001:2::/48', '2001:10::/28', '2001:20::/28', '2001:30::/28',
  '2001:db8::/32', '2002::/16', '3fff::/20', 'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8'
];
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MIN_RESPONSE_BYTES = 1024;

export function assertPublicIp(address) {
  const family = isIP(address);
  // IPv6 only has a globally routable unicast space within 2000::/3.
  // Requiring this positive boundary prevents newly allocated/special-purpose
  // non-global ranges from silently passing an incomplete deny-list.
  const outsideGlobalV6 = family === 6 && !cidrContains('2000::/3', address);
  if (!family || outsideGlobalV6 || BLOCKED_NETWORKS.some((network) => cidrContains(network, address))) {
    throw new Error('Outbound request blocked: destination is not a globally routable IP address.');
  }
  return address;
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new Error('Outbound request aborted.');
}

function createDeadline(timeoutMs, parentSignal) {
  if (parentSignal !== undefined && (parentSignal === null || typeof parentSignal.addEventListener !== 'function' || typeof parentSignal.aborted !== 'boolean')) {
    throw new TypeError('signal must be an AbortSignal.');
  }
  const controller = new AbortController();
  let timedOut = false;
  const abortFromParent = () => controller.abort(parentSignal.reason instanceof Error ? parentSignal.reason : new Error('Outbound request aborted.'));
  if (parentSignal?.aborted) abortFromParent();
  else parentSignal?.addEventListener('abort', abortFromParent, { once: true });
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort(new Error('Outbound request timed out.'));
  }, timeoutMs);
  timer.unref?.();
  return {
    signal: controller.signal,
    get timedOut() { return timedOut; },
    dispose() {
      clearTimeout(timer);
      parentSignal?.removeEventListener('abort', abortFromParent);
    }
  };
}

async function resolvePublicAddresses(hostname, signal) {
  throwIfAborted(signal);
  const literal = hostname.replace(/^\[|\]$/g, '');
  if (isIP(literal)) return [{ address: assertPublicIp(literal), family: isIP(literal) }];
  if (!hostname || hostname.length > 253 || hostname.endsWith('.') || /[\u0000-\u0020\u007f]/.test(hostname)) throw new Error('Outbound request blocked: invalid hostname.');

  let timeoutId;
  let abortHandler;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error('Outbound DNS resolution timed out.')), 3000);
    timeoutId.unref?.();
  });
  const aborted = new Promise((_, reject) => {
    if (signal?.aborted) reject(signal.reason instanceof Error ? signal.reason : new Error('Outbound request aborted.'));
    else {
      abortHandler = () => reject(signal.reason instanceof Error ? signal.reason : new Error('Outbound request aborted.'));
      signal?.addEventListener('abort', abortHandler, { once: true });
    }
  });
  let results;
  try {
    results = await Promise.race([Promise.allSettled([resolve4(hostname), resolve6(hostname)]), timeout, aborted]);
  } finally {
    clearTimeout(timeoutId);
    if (abortHandler) signal?.removeEventListener('abort', abortHandler);
  }
  throwIfAborted(signal);
  const [v4, v6] = results;
  const addresses = [];
  // A mixed public/private answer is rejected as a whole; the caller cannot
  // choose the public record while a private answer remains in the DNS set.
  if (v4.status === 'fulfilled') for (const address of v4.value) addresses.push({ address: assertPublicIp(address), family: 4 });
  if (v6.status === 'fulfilled') for (const address of v6.value) addresses.push({ address: assertPublicIp(address), family: 6 });
  if (!addresses.length) throw new Error('Outbound request blocked: hostname did not resolve to a public address.');
  return [...new Map(addresses.map((item) => [item.address, item])).values()];
}

function toBuffer(body) {
  if (body == null) return undefined;
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === 'string') return Buffer.from(body);
  if (body instanceof Uint8Array) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  if (body instanceof ArrayBuffer) return Buffer.from(body);
  throw new TypeError('arixSafeFetch only accepts bounded string or binary bodies.');
}

/** Read an HTTPS response while enforcing the caller's byte ceiling. */
export function readBoundedResponseBody(response, request, maxResponseBytes) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let size = 0;
    const chunks = [];
    const fail = (error) => {
      if (settled) return;
      settled = true;
      try { response.destroy?.(); } catch { /* best effort stream teardown */ }
      try { request?.destroy?.(error); } catch { /* best effort socket teardown */ }
      reject(error);
    };

    const declaredLength = response?.headers?.['content-length'];
    if (typeof declaredLength === 'string' && /^\d+$/.test(declaredLength) && Number(declaredLength) > maxResponseBytes) {
      fail(new Error(`Outbound response exceeds configured ${maxResponseBytes}-byte limit.`));
      return;
    }
    response.on('data', (chunk) => {
      if (settled) return;
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += bytes.length;
      if (size > maxResponseBytes) {
        fail(new Error(`Outbound response exceeds configured ${maxResponseBytes}-byte limit.`));
        return;
      }
      chunks.push(bytes);
    });
    response.on('aborted', () => fail(new Error('Outbound response was aborted before completion.')));
    response.on('error', fail);
    response.on('end', () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks, size));
    });
  });
}

function requestPinned(url, options, address, signal) {
  return new Promise((resolve, reject) => {
    const headers = new Headers(options.headers || {});
    headers.delete('host');
    headers.delete('content-length');
    headers.delete('transfer-encoding');
    const body = toBuffer(options.body);
    if (body) headers.set('content-length', String(body.length));
    const nodeHeaders = Object.fromEntries(headers.entries());
    const literalHost = url.hostname.replace(/^\[|\]$/g, '');
    const request = https.request(url, {
      method: String(options.method || 'GET').toUpperCase(),
      headers: nodeHeaders,
      ...(isIP(literalHost) ? {} : { servername: literalHost }),
      rejectUnauthorized: true,
      lookup: (_hostname, lookupOptions, callback) => {
        if (lookupOptions?.all) callback(null, [address]);
        else callback(null, address.address, address.family);
      },
      timeout: Math.max(1000, Math.min(30000, Number(options.timeoutMs) || 10000)),
      maxHeaderSize: 16 * 1024,
      signal
    }, async (response) => {
      try {
        const responseBody = await readBoundedResponseBody(response, request, options.maxResponseBytes);
        resolve({ status: response.statusCode || 502, statusText: response.statusMessage || '', headers: response.headers, body: responseBody });
      } catch (error) { reject(error); }
    });
    request.on('timeout', () => request.destroy(new Error('Outbound request timed out.')));
    request.on('error', reject);
    if (body) request.write(body);
    request.end();
  });
}

/**
 * DNS-pinned HTTPS fetch with private-address denial, an absolute end-to-end
 * deadline, bounded request/response sizes, and same-origin-only redirects.
 * Cross-origin redirects are deliberately rejected: even a redirect that has
 * had standard auth headers stripped can exfiltrate caller-specific headers or
 * a 307/308 request body. Make a separate explicitly reviewed request instead.
 */
export async function arixSafeFetch(input, options = {}) {
  let current;
  try { current = new URL(input); } catch { throw new TypeError('arixSafeFetch requires a valid absolute URL.'); }
  const rawRedirects = Number(options.maxRedirects ?? 3);
  if (!Number.isInteger(rawRedirects) || rawRedirects < 0 || rawRedirects > 5) throw new RangeError('maxRedirects must be an integer from 0 to 5.');
  const maxRedirects = rawRedirects;
  const rawTimeout = Number(options.timeoutMs ?? 10000);
  if (!Number.isFinite(rawTimeout) || rawTimeout <= 0) throw new RangeError('timeoutMs must be a positive finite number.');
  const timeoutMs = Math.max(1000, Math.min(30000, Math.floor(rawTimeout)));
  const rawResponseLimit = Number(options.maxResponseBytes ?? MAX_RESPONSE_BYTES);
  if (!Number.isSafeInteger(rawResponseLimit) || rawResponseLimit < MIN_RESPONSE_BYTES || rawResponseLimit > MAX_RESPONSE_BYTES) {
    throw new RangeError(`maxResponseBytes must be an integer from ${MIN_RESPONSE_BYTES} to ${MAX_RESPONSE_BYTES}.`);
  }
  const maxResponseBytes = rawResponseLimit;
  const allowedPorts = new Set((Array.isArray(options.allowedPorts) ? options.allowedPorts : [443]).map(Number));
  if (!allowedPorts.size || [...allowedPorts].some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) throw new RangeError('allowedPorts must contain valid TCP port numbers.');
  let currentMethod = String(options.method || 'GET').toUpperCase();
  if (!/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(currentMethod)) throw new Error('Outbound method is not allowed.');
  let currentBody = toBuffer(options.body);
  if (currentBody && currentBody.length > 1024 * 1024) throw new Error('Outbound request body exceeds 1 MiB limit.');
  let headersForHop = new Headers(options.headers || {});
  const deadline = createDeadline(timeoutMs, options.signal);

  try {
    for (let hop = 0; hop <= maxRedirects; hop++) {
      throwIfAborted(deadline.signal);
      const requestPort = current.port === '' ? 443 : Number(current.port);
      if (current.protocol !== 'https:' || current.username || current.password || !allowedPorts.has(requestPort)) {
        throw new Error('Outbound request blocked: only credential-free HTTPS URLs on approved ports are allowed.');
      }
      const addresses = await resolvePublicAddresses(current.hostname, deadline.signal);
      throwIfAborted(deadline.signal);
      const selected = addresses[0];
      const result = await requestPinned(current, { ...options, headers: headersForHop, method: currentMethod, body: currentBody, timeoutMs, maxResponseBytes }, selected, deadline.signal);
      const location = result.headers.location;
      if ([301, 302, 303, 307, 308].includes(result.status) && location) {
        if (hop >= maxRedirects) throw new Error('Outbound redirect limit exceeded.');
        const next = new URL(location, current);
        if (next.origin !== current.origin) throw new Error('Outbound cross-origin redirect blocked.');
        if (result.status === 303 && currentMethod !== 'HEAD' || [301, 302].includes(result.status) && currentMethod === 'POST') {
          currentMethod = 'GET';
          currentBody = undefined;
          headersForHop.delete('content-type');
          headersForHop.delete('content-encoding');
          headersForHop.delete('content-language');
          headersForHop.delete('content-location');
          headersForHop.delete('content-md5');
        }
        current = next;
        continue;
      }
      const responseHeaders = new Headers();
      for (const [name, value] of Object.entries(result.headers || {})) {
        if (Array.isArray(value)) responseHeaders.set(name, value.join(', '));
        else if (value !== undefined) responseHeaders.set(name, String(value));
      }
      const responseBody = [204, 205, 304].includes(result.status) ? null : result.body;
      return new Response(responseBody, { status: result.status, statusText: result.statusText, headers: responseHeaders });
    }
    throw new Error('Outbound redirect limit exceeded.');
  } finally {
    deadline.dispose();
  }
}
