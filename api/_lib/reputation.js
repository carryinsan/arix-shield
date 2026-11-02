import { buildPrefixTrie, prefixTrieHas, cidrContains, parseCidr } from './cidr.js';
import { getJson, setJson } from './redis.js';
import { isIP } from 'node:net';
import { reverse, resolve4, resolve6 } from 'node:dns/promises';

const FEED_TTL_SECONDS = 60 * 60 * 48;
const FEED_RETENTION_SECONDS = FEED_TTL_SECONDS + 7 * 24 * 60 * 60;
const CACHE_TTL_MS = 5 * 60 * 1000;
const cache = globalThis.__ARIX_REPUTATION_CACHE__ ??= { at: 0, trie: null, sources: [], byFeed: new Map(), stale: [] };
const TRUSTED_SUFFIXES = Object.freeze({ google: ['.googlebot.com', '.google.com'], bing: ['.search.msn.com'] });

function parseTextCidrs(text, maxEntries = 100000) {
  const result = [];
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const candidate = line.split(/[\s;#]/, 1)[0];
    if (candidate && candidate.length <= 80 && parseCidr(candidate)) result.push(candidate);
    if (result.length >= maxEntries) break;
  }
  return [...new Set(result)];
}

function parseSpamhaus(text) {
  const trimmed = String(text).trim();
  try {
    const value = JSON.parse(trimmed);
    const rows = Array.isArray(value) ? value : Array.isArray(value?.data) ? value.data : Array.isArray(value?.cidrs) ? value.cidrs : [];
    const entries = rows.map((row) => typeof row === 'string' ? row : row?.cidr).filter((item) => typeof item === 'string');
    if (entries.length) return entries;
  } catch { /* JSON feed may include a trailing metadata row. */ }
  const entries = [];
  for (const line of trimmed.split(/\r?\n/)) {
    try {
      const row = JSON.parse(line);
      if (typeof row?.cidr === 'string') entries.push(row.cidr);
    } catch {
      const match = line.match(/^\s*([0-9a-f:.]+\/\d{1,3})\b/i);
      if (match) entries.push(match[1]);
    }
  }
  return [...new Set(entries)];
}

async function boundedFetch(url, { maxBytes = 5000000, headers = {} } = {}) {
  const response = await fetch(url, { headers: { 'User-Agent': 'ArixShield-ThreatFeed/1.0 (+https://arixshield.io)', ...headers }, signal: AbortSignal.timeout(12000), redirect: 'error' });
  if (!response.ok) throw new Error(`Feed returned HTTP ${response.status}`);
  const declared = Number(response.headers.get('content-length') || 0);
  if (declared > maxBytes) throw new Error('Feed exceeds the configured size limit.');
  if (!response.body?.getReader) {
    const text = await response.text();
    if (Buffer.byteLength(text) > maxBytes) throw new Error('Feed exceeds the configured size limit.');
    return text;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) { await reader.cancel(); throw new Error('Feed exceeds the configured size limit.'); }
      chunks.push(Buffer.from(value));
    }
  } finally { reader.releaseLock?.(); }
  return Buffer.concat(chunks, total).toString('utf8');
}

export async function refreshThreatFeeds() {
  const definitions = [
    { name: 'spamhaus-drop-v4', url: 'https://www.spamhaus.org/drop/drop_v4.json', parser: parseSpamhaus },
    { name: 'spamhaus-drop-v6', url: 'https://www.spamhaus.org/drop/drop_v6.json', parser: parseSpamhaus },
    { name: 'firehol-level1', url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', parser: parseTextCidrs },
    { name: 'tor-exit', url: 'https://check.torproject.org/api/bulk', parser: parseTextCidrs }
  ];
  if (process.env.ARIX_ABUSEIPDB_API_KEY) definitions.push({
    name: 'abuseipdb-blacklist', url: 'https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=10000',
    headers: { Key: process.env.ARIX_ABUSEIPDB_API_KEY, Accept: 'application/json' },
    parser: (text) => { const value = JSON.parse(text); return (Array.isArray(value?.data) ? value.data : []).map((row) => row?.ipAddress).filter((ip) => typeof ip === 'string'); }
  });
  const results = await Promise.all(definitions.map(async (feed) => {
    try {
      const text = await boundedFetch(feed.url, { headers: feed.headers || {} });
      const cidrs = [...new Set(feed.parser(text).filter((item) => typeof item === 'string' && item.length <= 80 && parseCidr(item)))].slice(0, 100000);
      if (!cidrs.length) throw new Error('Feed parsed to zero network entries.');
      const payload = { name: feed.name, source: feed.url, sourceCount: cidrs.length, cidrs, fetchedAt: new Date().toISOString(), expiresAt: Date.now() + FEED_TTL_SECONDS * 1000 };
      await setJson(`arix:threat-feed:${feed.name}`, payload, FEED_RETENTION_SECONDS);
      return { name: feed.name, ok: true, count: cidrs.length };
    } catch (error) { return { name: feed.name, ok: false, error: String(error?.message || error).slice(0, 180) }; }
  }));
  cache.at = 0;
  const successCount = results.filter((result) => result.ok).length;
  return { ok: successCount > 0, updated: successCount, feeds: results, checkedAt: new Date().toISOString() };
}

async function loadTrie() {
  if (cache.trie && Date.now() - cache.at < CACHE_TTL_MS) return cache;
  const names = ['spamhaus-drop-v4', 'spamhaus-drop-v6', 'firehol-level1', 'tor-exit', 'abuseipdb-blacklist'];
  const feeds = await Promise.all(names.map((name) => getJson(`arix:threat-feed:${name}`)));
  const valid = feeds.filter((feed) => feed && Array.isArray(feed.cidrs) && feed.cidrs.length > 0
    && (!Number.isFinite(Number(feed.expiresAt)) || Number(feed.expiresAt) > Date.now() - 7 * 24 * 60 * 60 * 1000));
  const cidrs = valid.flatMap((feed) => feed.cidrs).slice(0, 300000);
  cache.trie = buildPrefixTrie(cidrs);
  cache.byFeed = new Map(valid.map((feed) => [String(feed.name || ''), { trie: buildPrefixTrie(feed.cidrs.slice(0, 150000)), fetchedAt: Number.isFinite(Date.parse(feed.fetchedAt)) ? Date.parse(feed.fetchedAt) : 0, sourceCount: feed.cidrs.length }]));
  cache.sources = valid.map(({ name, sourceCount, fetchedAt }) => ({ name, sourceCount, fetchedAt }));
  const expectedFeeds = ['spamhaus-drop-v4', 'spamhaus-drop-v6', 'firehol-level1', 'tor-exit'];
  const oldFeeds = valid.filter((feed) => !Number.isFinite(Date.parse(feed.fetchedAt)) || Date.now() - Date.parse(feed.fetchedAt) > 24 * 60 * 60 * 1000).map((feed) => String(feed.name || 'unknown'));
  const missingFeeds = expectedFeeds.filter((name) => !valid.some((feed) => feed.name === name));
  cache.stale = [...new Set([...oldFeeds, ...missingFeeds])];
  cache.at = Date.now();
  return cache;
}


/** Synchronous worker-cache lookup used for bounded pre-body shedding. It never fetches feeds. */
export function isIpInLoadedThreatFeed(ip) {
  const address = String(ip || '').trim();
  return isIP(address) !== 0 && Boolean(cache.trie?.count) && prefixTrieHas(cache.trie, address);
}

export async function getThreatFeedStatus() {
  const loaded = await loadTrie();
  return { loaded: Boolean(loaded.trie?.count), feedCount: loaded.trie?.count || 0, sources: loaded.sources || [], staleFeeds: loaded.stale || [], warning: (loaded.stale || []).length > 0 };
}

export async function checkIpReputation(ip) {
  const address = String(ip || '').split(',')[0].trim();
  if (!address || isIP(address) === 0) return { checked: false, listed: false, threatConfidence: 0, action: 'allow', reason: 'INVALID_OR_MISSING_IP' };
  const loaded = await loadTrie();
  if (!loaded.trie?.count) return { checked: false, listed: false, threatConfidence: 0, action: 'allow', reason: 'THREAT_FEEDS_NOT_LOADED', feedCount: 0, staleFeeds: loaded.stale || [] };
  const signals = [];
  let threatConfidence = 0;
  for (const [name, weight] of [['spamhaus-drop-v4', 85], ['spamhaus-drop-v6', 85]]) {
    const feed = loaded.byFeed?.get(name);
    if (!feed || !prefixTrieHas(feed.trie, address)) continue;
    const stale = feed.fetchedAt <= 0 || Date.now() - feed.fetchedAt > 24 * 60 * 60 * 1000;
    const effectiveWeight = stale ? Math.floor(weight / 2) : weight;
    signals.push({ source: name, weight: effectiveWeight, stale });
    threatConfidence = Math.min(100, threatConfidence + effectiveWeight);
  }
  const medium = ['firehol-level1', 'tor-exit'].map((name) => ({ name, feed: loaded.byFeed?.get(name) })).filter(({ feed }) => feed && prefixTrieHas(feed.trie, address));
  if (medium.length) {
    const stale = medium.every(({ feed }) => feed.fetchedAt <= 0 || Date.now() - feed.fetchedAt > 24 * 60 * 60 * 1000);
    const weight = stale ? 22 : 45;
    threatConfidence = Math.min(100, threatConfidence + weight);
    for (const item of medium) signals.push({ source: item.name, weight: 0, stale });
  }
  // FireHOL and Tor are correlated medium-confidence lists: together they still
  // contribute one +45 signal and require an independent signal to hard-block.
  const highConfidence = signals.some((signal) => signal.source.startsWith('spamhaus') && !signal.stale);
  const action = highConfidence || threatConfidence >= 85 ? 'block' : threatConfidence >= 40 ? 'challenge' : 'allow';
  return { checked: true, listed: signals.length > 0, threatConfidence, action, signals, feedCount: loaded.trie.count, sources: loaded.sources, staleFeeds: loaded.stale || [] };
}

function hostnameMatches(host, suffixes) {
  const value = String(host).toLowerCase().replace(/\.$/, '');
  return suffixes.some((suffix) => value.endsWith(suffix) && value.length > suffix.length);
}

export async function verifyForwardConfirmedCrawler(ip, userAgent = '') {
  if (isIP(String(ip || '')) === 0) return { verified: false, provider: null, reason: 'INVALID_IP' };
  const agent = String(userAgent).toLowerCase();
  const candidate = agent.includes('googlebot') ? 'google' : agent.includes('bingbot') ? 'bing' : null;
  if (!candidate) return { verified: false, provider: null, reason: 'NOT_A_SUPPORTED_CRAWLER' };
  try {
    let timer;
    const ptrs = await Promise.race([
      reverse(ip),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('DNS timeout')), 1600); })
    ]).finally(() => clearTimeout(timer));
    for (const ptr of ptrs.slice(0, 5)) {
      if (!hostnameMatches(ptr, TRUSTED_SUFFIXES[candidate])) continue;
      const [v4, v6] = await Promise.allSettled([resolve4(ptr), resolve6(ptr)]);
      const addresses = [...(v4.status === 'fulfilled' ? v4.value : []), ...(v6.status === 'fulfilled' ? v6.value : [])];
      if (addresses.includes(ip)) return { verified: true, provider: candidate, hostname: ptr };
    }
    return { verified: false, provider: candidate, reason: 'FORWARD_CONFIRMATION_FAILED' };
  } catch { return { verified: false, provider: candidate, reason: 'DNS_VERIFICATION_UNAVAILABLE' }; }
}

/** Explicit, operator-maintained source allowlist. Values are provider CIDR arrays in
 * ARIX_TRUSTED_PROVIDER_CIDRS_JSON; no provider is trusted by a user-agent alone. */
export function verifyConfiguredProviderIp(ip, provider) {
  if (isIP(String(ip || '')) === 0 || typeof provider !== 'string') return { verified: false, provider: null, reason: 'INVALID_INPUT' };
  let configured;
  try { configured = JSON.parse(process.env.ARIX_TRUSTED_PROVIDER_CIDRS_JSON || '{}'); }
  catch { return { verified: false, provider: null, reason: 'INVALID_ALLOWLIST_CONFIGURATION' }; }
  const name = provider.toLowerCase();
  const cidrs = configured && Array.isArray(configured[name]) ? configured[name].slice(0, 2000) : [];
  const verified = cidrs.some((cidr) => typeof cidr === 'string' && cidrContains(cidr, ip));
  return { verified, provider: verified ? name : null, reason: verified ? undefined : 'SOURCE_IP_NOT_ALLOWLISTED' };
}
