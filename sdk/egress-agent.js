import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import { isIP } from 'node:net';
import { arixSafeFetch, assertPublicIp } from './safe-fetch.js';

function normalizeHost(value) {
  const host = String(value || '').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!host || host.length > 253 || /[\u0000-\u0020\u007f/@?#]/.test(host)) throw new TypeError('Egress allowlist host is invalid.');
  return host;
}
function normalizeHostSet(values) {
  if (!Array.isArray(values) || values.length > 256) throw new TypeError('allowedHosts must be an array with at most 256 entries.');
  return new Set(values.map(normalizeHost));
}
function makeLookup(allowedHosts, allowPublicHttps, protocol) {
  return function safeLookup(hostname, options, callback) {
    if (typeof options === 'function') { callback = options; options = {}; }
    const lookupOptions = typeof options === 'number' ? { family: options } : (options || {});
    const host = normalizeHost(hostname);
    if (allowedHosts.has(host)) return dns.lookup(hostname, lookupOptions, callback);
    if (protocol !== 'https:' || !allowPublicHttps) {
      const error = Object.assign(new Error('ArixShield egress firewall blocked a non-allowlisted destination.'), { code: 'EHOSTUNREACH' });
      return queueMicrotask(() => callback(error));
    }
    dns.lookup(hostname, { all: true, verbatim: true }, (error, records) => {
      if (error) return callback(error);
      try {
        if (!Array.isArray(records) || records.length === 0) throw new Error('DNS returned no address records.');
        const safe = records.map((record) => ({ address: assertPublicIp(record.address), family: record.family }));
        const family = Number(lookupOptions.family || 0);
        const filtered = family ? safe.filter((record) => record.family === family) : safe;
        if (!filtered.length) throw new Error('DNS has no address for the requested IP family.');
        if (lookupOptions.all) callback(null, filtered);
        else callback(null, filtered[0].address, filtered[0].family);
      } catch (blocked) {
        callback(Object.assign(new Error(`ArixShield egress firewall blocked DNS for ${host}: ${blocked.message}`), { code: 'EHOSTUNREACH' }));
      }
    });
  };
}
function installAgent(protocol, allowedHosts, allowPublicHttps) {
  const AgentClass = protocol === 'https:' ? https.Agent : http.Agent;
  const agent = new AgentClass({ keepAlive: true, maxSockets: 64, maxFreeSockets: 16, timeout: 15_000, lookup: makeLookup(allowedHosts, allowPublicHttps, protocol) });
  const originalCreateConnection = agent.createConnection.bind(agent);
  agent.createConnection = (options, callback) => {
    const rawHost = normalizeHost(options?.hostname || options?.host);
    if (!allowedHosts.has(rawHost)) {
      if (protocol !== 'https:' || !allowPublicHttps) throw Object.assign(new Error('ArixShield egress firewall blocked an outbound socket.'), { code: 'EHOSTUNREACH' });
      if (isIP(rawHost)) assertPublicIp(rawHost);
    }
    // Do not let a per-request `lookup` option bypass the agent's DNS check.
    // The agent performs its own lookup at connect time for every socket.
    return originalCreateConnection({ ...options, lookup: makeLookup(allowedHosts, allowPublicHttps, protocol) }, callback);
  };
  return agent;
}

/**
 * Opt-in enforcement for Node http/https clients that honor globalAgent.
 * This does not intercept Undici/fetch, native addons, raw sockets or OS traffic.
 */
export function installSafeGlobalAgents({ allowedHosts = [], allowPublicHttps = true } = {}) {
  const hosts = normalizeHostSet(allowedHosts);
  if (typeof allowPublicHttps !== 'boolean') throw new TypeError('allowPublicHttps must be boolean.');
  const previousHttp = http.globalAgent;
  const previousHttps = https.globalAgent;
  const nextHttp = installAgent('http:', hosts, false);
  const nextHttps = installAgent('https:', hosts, allowPublicHttps);
  http.globalAgent = nextHttp;
  https.globalAgent = nextHttps;
  let restored = false;
  return Object.freeze({
    httpAgent: nextHttp,
    httpsAgent: nextHttps,
    restore() {
      if (restored) return;
      restored = true;
      if (http.globalAgent === nextHttp) http.globalAgent = previousHttp;
      if (https.globalAgent === nextHttps) https.globalAgent = previousHttps;
      nextHttp.destroy(); nextHttps.destroy();
    }
  });
}

/** Explicitly opt in to DNS-pinned HTTPS for global fetch calls. */
export function installSafeGlobalFetch({ allowedOrigins = [] } = {}) {
  if (!Array.isArray(allowedOrigins) || allowedOrigins.length > 128) throw new TypeError('allowedOrigins must be an array with at most 128 origins.');
  const allowlist = new Set(allowedOrigins.map((raw) => {
    const url = new URL(String(raw));
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new TypeError('Allowed fetch destinations must be credential-free URL origins.');
    return url.origin;
  }));
  const previousFetch = globalThis.fetch;
  if (typeof previousFetch !== 'function') throw new Error('This Node.js runtime does not provide global fetch.');
  const wrapped = async function arixSafeGlobalFetch(input, init = {}) {
    let url;
    let request = null;
    if (typeof Request !== 'undefined' && input instanceof Request) { request = input; url = new URL(request.url); }
    else url = new URL(input instanceof URL ? input.href : String(input));
    if (allowlist.has(url.origin)) return previousFetch(input, { ...init, redirect: 'manual' });
    const method = String(init.method || request?.method || 'GET').toUpperCase();
    let body = init.body;
    if (body === undefined && request && !['GET', 'HEAD'].includes(method)) {
      const bytes = new Uint8Array(await request.clone().arrayBuffer());
      if (bytes.byteLength > 1024 * 1024) throw new Error('ArixShield global fetch request body exceeds 1 MiB.');
      body = bytes;
    }
    const headers = new Headers(init.headers || request?.headers || {});
    return arixSafeFetch(url.href, {
      method,
      headers,
      body: ['GET', 'HEAD'].includes(method) ? undefined : body,
      signal: init.signal || request?.signal,
      timeoutMs: init.timeoutMs || 10_000,
      maxRedirects: init.redirect === 'manual' ? 0 : 3
    });
  };
  globalThis.fetch = wrapped;
  let restored = false;
  return Object.freeze({
    restore() { if (restored) return; restored = true; if (globalThis.fetch === wrapped) globalThis.fetch = previousFetch; }
  });
}
