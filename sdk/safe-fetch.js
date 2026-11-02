import https from 'node:https';
import { resolve4, resolve6 } from 'node:dns/promises';
import { isIP } from 'node:net';
import { cidrContains } from '../api/_lib/cidr.js';

const BLOCKED_NETWORKS = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
  '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
  '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64',
  '2001::/23', '2001:db8::/32', '2002::/16', 'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8'
];
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

function assertPublicIp(address) {
  if (!isIP(address) || BLOCKED_NETWORKS.some((network) => cidrContains(network, address))) {
    throw new Error('Outbound request blocked: destination is not a globally routable IP address.');
  }
  return address;
}

async function resolvePublicAddresses(hostname) {
  const literal = hostname.replace(/^\[|\]$/g, '');
  if (isIP(literal)) return [{ address: assertPublicIp(literal), family: isIP(literal) }];
  if (!hostname || hostname.length > 253 || hostname.endsWith('.')) throw new Error('Outbound request blocked: invalid hostname.');
  let timeoutId;
  const timeout = new Promise((_, reject) => { timeoutId = setTimeout(() => reject(new Error('Outbound DNS resolution timed out.')), 3000); });
  let results;
  try { results = await Promise.race([Promise.allSettled([resolve4(hostname), resolve6(hostname)]), timeout]); }
  finally { clearTimeout(timeoutId); }
  const [v4, v6] = results;
  const addresses = [];
  if (v4.status === 'fulfilled') for (const address of v4.value) addresses.push({ address: assertPublicIp(address), family: 4 });
  if (v6.status === 'fulfilled') for (const address of v6.value) addresses.push({ address: assertPublicIp(address), family: 6 });
  if (!addresses.length) throw new Error('Outbound request blocked: hostname did not resolve to a public address.');
  const unique = [...new Map(addresses.map((item) => [item.address, item])).values()];
  return unique;
}

function toBuffer(body) {
  if (body == null) return undefined;
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === 'string') return Buffer.from(body);
  if (body instanceof Uint8Array) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  if (body instanceof ArrayBuffer) return Buffer.from(body);
  throw new TypeError('arixSafeFetch only accepts bounded string or binary bodies.');
}

function requestPinned(url, options, address) {
  return new Promise((resolve, reject) => {
    const headers = new Headers(options.headers || {});
    headers.delete('host');
    headers.delete('content-length');
    headers.delete('transfer-encoding');
    const body = toBuffer(options.body);
    if (body) headers.set('content-length', String(body.length));
    const nodeHeaders = Object.fromEntries(headers.entries());
    const request = https.request(url, {
      method: String(options.method || 'GET').toUpperCase(),
      headers: nodeHeaders,
      servername: url.hostname,
      rejectUnauthorized: true,
      lookup: (_hostname, lookupOptions, callback) => {
        const entry = address;
        if (lookupOptions?.all) callback(null, [entry]);
        else callback(null, entry.address, entry.family);
      },
      timeout: Math.max(1000, Math.min(30000, Number(options.timeoutMs) || 10000)),
      maxHeaderSize: 16 * 1024
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) {
          request.destroy(new Error('Outbound response exceeds 8 MiB limit.'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => resolve({ status: response.statusCode || 502, statusText: response.statusMessage || '', headers: response.headers, body: Buffer.concat(chunks) }));
      response.on('error', reject);
    });
    request.on('timeout', () => request.destroy(new Error('Outbound request timed out.')));
    request.on('error', reject);
    if (body) request.write(body);
    request.end();
  });
}

/**
 * DNS-pinned HTTPS fetch with private-address denial and redirect revalidation.
 * It intentionally does not inherit ambient proxy agents or follow redirects
 * automatically. The URL is resolved and pinned for each individual hop.
 */
export async function arixSafeFetch(input, options = {}) {
  let current;
  try { current = new URL(input); } catch { throw new TypeError('arixSafeFetch requires a valid absolute URL.'); }
  const maxRedirects = Math.max(0, Math.min(5, Number(options.maxRedirects ?? 3)));
  const allowedPorts = new Set((Array.isArray(options.allowedPorts) ? options.allowedPorts : [443]).map(Number));
  let currentMethod = String(options.method || 'GET').toUpperCase();
  if (!/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(currentMethod)) throw new Error('Outbound method is not allowed.');
  let currentBody = toBuffer(options.body);
  if (currentBody && currentBody.length > 1024 * 1024) throw new Error('Outbound request body exceeds 1 MiB limit.');
  let headersForHop = new Headers(options.headers || {});
  for (let hop = 0; hop <= maxRedirects; hop++) {
    if (current.protocol !== 'https:' || current.username || current.password || !allowedPorts.has(Number(current.port || 443))) {
      throw new Error('Outbound request blocked: only credential-free HTTPS URLs on approved ports are allowed.');
    }
    const addresses = await resolvePublicAddresses(current.hostname);
    const selected = addresses[0];
    const result = await requestPinned(current, { ...options, headers: headersForHop, method: currentMethod, body: currentBody }, selected);
    const location = result.headers.location;
    if ([301, 302, 303, 307, 308].includes(result.status) && location) {
      if (hop >= maxRedirects) throw new Error('Outbound redirect limit exceeded.');
      const next = new URL(location, current);
      if (result.status === 303 || ([301, 302].includes(result.status) && currentMethod === 'POST')) {
        currentMethod = 'GET'; currentBody = undefined;
      }
      if (next.origin !== current.origin) {
        headersForHop = new Headers(headersForHop);
        headersForHop.delete('authorization'); headersForHop.delete('cookie'); headersForHop.delete('proxy-authorization');
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
}
