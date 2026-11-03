import http from 'node:http';
import https from 'node:https';
import { readFile, mkdir, open } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { createHash, createHmac, hkdfSync, randomUUID, timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const ZERO_HASH = '0'.repeat(64);
const KEY_SALT = Buffer.from('ArixShield replicated state peer salt v1');
const KEY_INFO = Buffer.from('replicated-state-peer-auth-hmac-sha256');
const MUTATING = new Set(['SET','SETEX','PSETEX','DEL','GETDEL','INCR','INCRBY','LPUSH','LTRIM','RPOPLPUSH','LREM','SADD','SREM','HSET','ZADD','ZREMRANGEBYSCORE','EXPIRE','PEXPIRE']);

function equalSecret(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  return left.length > 0 && left.length === right.length && timingSafeEqual(left, right);
}
function normalizePeerUrl(raw) {
  const url = new URL(String(raw));
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || !['', '/'].includes(url.pathname)) throw new TypeError('Peer URL must be a credential-free HTTP(S) origin.');
  if (url.protocol !== 'https:' && !['localhost','127.0.0.1','::1'].includes(url.hostname)) throw new TypeError('Remote state peers must use HTTPS.');
  return url.origin;
}
function peerKey(master) {
  if (typeof master !== 'string' || Buffer.byteLength(master) < 32) throw new Error('ARIX_MASTER_SECRET >= 32 bytes is required by the replicated state service.');
  return Buffer.from(hkdfSync('sha256', Buffer.from(master), KEY_SALT, KEY_INFO, 32));
}
function signPeer(key, timestamp, body) { return createHmac('sha256', key).update(`${timestamp}.${body}`).digest('hex'); }
function hashEntry(entry) { return createHash('sha256').update(JSON.stringify({ seq: entry.seq, prevHash: entry.prevHash, command: entry.command, timestamp: entry.timestamp, id: entry.id })).digest('hex'); }
function encodeJson(value) { return Buffer.from(JSON.stringify(value)); }
function json(res, status, payload) {
  if (res.headersSent || res.destroyed || res.writableEnded) return;
  const body = encodeJson(payload);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': String(body.length), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', connection: 'close' });
  res.end(body);
}
async function readJson(req, maxBytes = 1_048_576) {
  const chunks = []; let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) throw Object.assign(new Error('Request exceeds the configured body limit.'), { status: 413 });
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw Object.assign(new Error('Request JSON is invalid.'), { status: 400 }); }
}
function normalizeCommand(input) {
  if (!Array.isArray(input) || input.length < 1 || input.length > 2048) throw new TypeError('Redis command must be a non-empty array.');
  const parts = input.map((value) => String(value));
  if (parts.some((part) => part.length > 1024 * 1024 || /[\u0000]/.test(part))) throw new TypeError('Redis command argument is invalid or oversized.');
  return parts;
}

function createEngine() {
  const data = new Map();
  function get(key, now = Date.now()) {
    const item = data.get(key);
    if (item?.expiresAt && item.expiresAt <= now) { data.delete(key); return null; }
    return item || null;
  }
  function set(key, type, value, expiresAt = null) { data.set(key, { type, value, expiresAt }); }
  function listItem(key, now) { const item = get(key, now); if (!item) return []; if (item.type !== 'list') throw new Error('WRONGTYPE Operation against a key holding the wrong kind of value'); return item.value; }
  function setItem(key, now) { const item = get(key, now); if (!item) return new Set(); if (item.type !== 'set') throw new Error('WRONGTYPE Operation against a key holding the wrong kind of value'); return item.value; }
  function hashItem(key, now) { const item = get(key, now); if (!item) return new Map(); if (item.type !== 'hash') throw new Error('WRONGTYPE Operation against a key holding the wrong kind of value'); return item.value; }
  function zsetItem(key, now) { const item = get(key, now); if (!item) return new Map(); if (item.type !== 'zset') throw new Error('WRONGTYPE Operation against a key holding the wrong kind of value'); return item.value; }
  function apply(parts, now = Date.now()) {
    const [raw, ...args] = parts; const name = String(raw).toUpperCase(); const key = String(args[0] ?? ''); const item = get(key, now);
    switch (name) {
      case 'PING': return 'PONG';
      case 'GET': return item?.type === 'string' ? item.value : null;
      case 'MGET': return args.map((k) => { const value = get(String(k), now); return value?.type === 'string' ? value.value : null; });
      case 'SET': case 'SETEX': case 'PSETEX': {
        const value = String(args[name === 'SET' ? 1 : 2] ?? '');
        const ttlIndex = name === 'SET' ? args.findIndex((v) => ['EX','PX'].includes(String(v).toUpperCase())) : 0;
        const unit = name === 'PSETEX' || String(args[ttlIndex] || '').toUpperCase() === 'PX' ? 1 : 1000;
        const ttlValue = name === 'SET' ? (ttlIndex >= 0 ? Number(args[ttlIndex + 1]) : null) : Number(args[1]);
        const nx = name === 'SET' && args.some((v) => String(v).toUpperCase() === 'NX');
        const xx = name === 'SET' && args.some((v) => String(v).toUpperCase() === 'XX');
        if ((nx && item) || (xx && !item)) return null;
        if (ttlValue !== null && (!Number.isSafeInteger(ttlValue) || ttlValue < 1 || ttlValue > 31_536_000_000)) throw new Error('Invalid expiry.');
        set(key, 'string', value, ttlValue === null ? null : now + ttlValue * unit);
        return 'OK';
      }
      case 'GETDEL': { const value = item?.type === 'string' ? item.value : null; data.delete(key); return value; }
      case 'DEL': { let count = 0; for (const k of args) if (data.delete(String(k))) count++; return count; }
      case 'INCR': case 'INCRBY': {
        const amount = name === 'INCR' ? 1 : Number(args[1]);
        const previous = item?.type === 'string' ? Number(item.value) : (item ? NaN : 0);
        const next = previous + amount;
        if (!Number.isSafeInteger(amount) || !Number.isSafeInteger(previous) || !Number.isSafeInteger(next)) throw new Error('ERR value is not an integer or out of range');
        set(key, 'string', String(next), item?.expiresAt || null); return next;
      }
      case 'EXPIRE': case 'PEXPIRE': {
        if (!item) return 0; const amount = Number(args[1]);
        if (!Number.isSafeInteger(amount) || amount < 0) throw new Error('Invalid expiry.');
        item.expiresAt = now + amount * (name === 'EXPIRE' ? 1000 : 1); return 1;
      }
      case 'LPUSH': { const list = listItem(key, now); for (const value of args.slice(1)) list.unshift(String(value)); set(key, 'list', list, item?.expiresAt || null); return list.length; }
      case 'LRANGE': { const list = listItem(key, now); const start = Number(args[1]); const end = Number(args[2]); const from = start < 0 ? Math.max(0, list.length + start) : Math.min(list.length, start); const to = end < 0 ? list.length + end + 1 : end + 1; return list.slice(from, Math.max(from, to)); }
      case 'LLEN': return listItem(key, now).length;
      case 'LTRIM': {
        const list = listItem(key, now); const start = Number(args[1]); const end = Number(args[2]);
        const from = start < 0 ? Math.max(0, list.length + start) : Math.min(list.length, start);
        const to = end < 0 ? list.length + end + 1 : end + 1; const next = list.slice(from, Math.max(from, to));
        set(key, 'list', next, item?.expiresAt || null); return 'OK';
      }
      case 'RPOPLPUSH': {
        const source = String(args[0]); const destination = String(args[1]);
        const sourceItem = get(source, now); if (sourceItem && sourceItem.type !== 'list') throw new Error('WRONGTYPE');
        const sourceList = sourceItem?.value || []; if (!sourceList.length) return null;
        const value = sourceList.pop(); set(source, 'list', sourceList, sourceItem?.expiresAt || null);
        const destItem = get(destination, now); if (destItem && destItem.type !== 'list') throw new Error('WRONGTYPE');
        const dest = destItem?.value || []; dest.unshift(value); set(destination, 'list', dest, destItem?.expiresAt || null); return value;
      }
      case 'LREM': {
        const count = Number(args[1]); const value = String(args[2]); const list = listItem(key, now); const out = []; let removed = 0;
        const candidates = count >= 0 ? list : [...list].reverse(); const limit = Math.abs(count);
        for (const itemValue of candidates) {
          if (itemValue === value && (count === 0 || removed < limit)) removed++; else out.push(itemValue);
        }
        if (count < 0) out.reverse(); set(key, 'list', out, item?.expiresAt || null); return removed;
      }
      case 'SADD': { const setValue = setItem(key, now); let added = 0; for (const member of args.slice(1)) { const before = setValue.size; setValue.add(String(member)); if (setValue.size > before) added++; } set(key, 'set', setValue, item?.expiresAt || null); return added; }
      case 'SREM': { const value = setItem(key, now); let removed = 0; for (const member of args.slice(1)) if (value.delete(String(member))) removed++; set(key, 'set', value, item?.expiresAt || null); return removed; }
      case 'SMEMBERS': return [...setItem(key, now)];
      case 'SCARD': return setItem(key, now).size;
      case 'HSET': { const hash = hashItem(key, now); let added = 0; for (let i = 1; i + 1 < args.length; i += 2) { const field = String(args[i]); if (!hash.has(field)) added++; hash.set(field, String(args[i + 1])); } set(key, 'hash', hash, item?.expiresAt || null); return added; }
      case 'HMGET': { const hash = hashItem(key, now); return args.slice(1).map((field) => hash.get(String(field)) ?? null); }
      case 'ZADD': { const zset = zsetItem(key, now); let added = 0; for (let i = 1; i + 1 < args.length; i += 2) { const member = String(args[i + 1]); if (!zset.has(member)) added++; zset.set(member, Number(args[i])); } set(key, 'zset', zset, item?.expiresAt || null); return added; }
      case 'ZREMRANGEBYSCORE': { const zset = zsetItem(key, now); const min = Number(args[1]); const max = Number(args[2]); let removed = 0; for (const [member, score] of zset) if (score >= min && score <= max) { zset.delete(member); removed++; } set(key, 'zset', zset, item?.expiresAt || null); return removed; }
      case 'ZCARD': return zsetItem(key, now).size;
      default: throw new Error(`ERR unsupported command ${name}; this service intentionally supports only the documented command subset and does not emulate Redis Lua/EVAL.`);
    }
  }
  return { data, apply, get };
}

export function createReplicatedStateServer({
  dataDir,
  peers = [],
  nodeId = 'arix-state-node',
  restToken = process.env.UPSTASH_REDIS_REST_TOKEN,
  masterSecret = process.env.ARIX_MASTER_SECRET,
  fetchImpl = globalThis.fetch,
  maxBodyBytes = 1_048_576,
  role = 'primary'
} = {}) {
  if (typeof dataDir !== 'string' || !dataDir || dataDir.length > 1024) throw new TypeError('A persistent dataDir is required.');
  if (typeof restToken !== 'string' || restToken.length < 16 || restToken.length > 8192) throw new Error('UPSTASH_REDIS_REST_TOKEN is required as the state REST bearer token.');
  if (!['primary','replica'].includes(role)) throw new TypeError('role must be primary or replica.');
  const peerUrls = peers.map(normalizePeerUrl);
  if (new Set(peerUrls).size !== peerUrls.length || peerUrls.length > 4) throw new TypeError('State peers must be unique (maximum four peers).');
  if (role === 'replica' && peerUrls.length) throw new TypeError('Replica nodes must not initiate replication to other peers.');
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1024 || maxBodyBytes > 16 * 1024 * 1024) throw new TypeError('maxBodyBytes must be between 1 KiB and 16 MiB.');
  const authKey = peerKey(masterSecret);
  const engine = createEngine();
  const state = { seq: 0, hash: ZERO_HASH, prepared: new Map(), unfinalized: new Map(), readOnly: false, writeTail: Promise.resolve() };
  const walPath = join(dataDir, 'state.wal');
  const quorum = Math.floor((peerUrls.length + 1) / 2) + 1;
  const serialize = (value) => JSON.stringify(value);
  const queue = (operation) => {
    const next = state.writeTail.then(operation, operation);
    state.writeTail = next.catch(() => {});
    return next;
  };
  async function append(record) {
    await mkdir(dirname(walPath), { recursive: true, mode: 0o700 });
    const handle = await open(walPath, 'a', 0o600);
    try { await handle.writeFile(`${serialize(record)}\n`, 'utf8'); await handle.sync(); }
    finally { await handle.close(); }
  }
  function applyEntry(entry) {
    if (entry.seq !== state.seq + 1 || entry.prevHash !== state.hash || hashEntry(entry) !== entry.hash) throw new Error('Replicated state WAL chain is inconsistent.');
    engine.apply(entry.command, entry.timestamp);
    state.seq = entry.seq; state.hash = entry.hash;
  }
  async function recover() {
    await mkdir(dataDir, { recursive: true, mode: 0o700 });
    let raw;
    try { raw = await readFile(walPath, 'utf8'); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
    const prepared = new Map();
    const unfinalized = new Map();
    const lines = raw.split('\n');
    if (lines.at(-1) === '') lines.pop();
    for (let index = 0; index < lines.length; index++) {
      let record;
      try { record = JSON.parse(lines[index]); } catch { throw new Error(`WAL corruption at line ${index + 1}.`); }
      if (record.type === 'prepare') prepared.set(record.entry.seq, record.entry);
      else if (record.type === 'abort') prepared.delete(record.seq);
      else if (record.type === 'commit') {
        const entry = record.entry; const pending = prepared.get(entry.seq);
        if (!pending || pending.hash !== entry.hash) throw new Error(`WAL commit has no matching prepare at line ${index + 1}.`);
        applyEntry(entry); prepared.delete(entry.seq); unfinalized.set(entry.seq, entry);
      } else if (record.type === 'finalize') {
        const pending = unfinalized.get(record.seq);
        if (!pending || pending.hash !== record.hash) throw new Error(`WAL finalize has no matching commit at line ${index + 1}.`);
        unfinalized.delete(record.seq);
      } else throw new Error(`Unknown WAL record at line ${index + 1}.`);
    }
    if (prepared.size || unfinalized.size) {
      // A crash may leave a prepare or commit without a recorded completion
      // marker. Do not guess whether a quorum reached the same state.
      for (const [seq, entry] of prepared) state.prepared.set(seq, entry);
      for (const [seq, entry] of unfinalized) state.unfinalized.set(seq, entry);
      state.readOnly = true;
    }
  }
  async function signedPeerRequest(url, action, entry) {
    const body = JSON.stringify({ action, entry }); const timestamp = String(Date.now());
    const signature = signPeer(authKey, timestamp, body);
    const response = await fetchImpl(`${url}/__arix/replicate`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-arix-state-time': timestamp, 'x-arix-state-auth': signature },
      body, signal: AbortSignal.timeout(2500), redirect: 'error'
    });
    if (!response.ok) throw new Error(`Peer rejected ${action} (${response.status}).`);
    const result = await response.json();
    if (result?.ok !== true) throw new Error('Peer returned an invalid replication acknowledgement.');
    return true;
  }
  async function handlePeer(req, res) {
    if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed.' }, { allow: 'POST' });
    const timestamp = Number(req.headers['x-arix-state-time']); const signature = req.headers['x-arix-state-auth'];
    const body = await readJson(req, maxBodyBytes);
    const canonicalBody = JSON.stringify(body);
    if (!Number.isSafeInteger(timestamp) || Math.abs(Date.now() - timestamp) > 30_000 || typeof signature !== 'string') return json(res, 401, { error: 'Peer authentication failed.' });
    const expected = signPeer(authKey, String(timestamp), canonicalBody);
    if (!equalSecret(signature, expected)) return json(res, 401, { error: 'Peer authentication failed.' });
    if (role !== 'replica') return json(res, 403, { error: 'Only replica nodes accept peer writes.' });
    const { action, entry } = body;
    if (!entry || !Number.isSafeInteger(entry.seq) || entry.seq < 1 || !/^[a-f0-9]{64}$/.test(entry.hash || '') || hashEntry(entry) !== entry.hash || !Array.isArray(entry.command)) return json(res, 400, { error: 'Invalid replication entry.' });
    try { const normalized = normalizeCommand(entry.command); if (!MUTATING.has(normalized[0].toUpperCase())) return json(res, 400, { error: 'Replication entry is not a supported mutating command.' }); }
    catch { return json(res, 400, { error: 'Invalid replication command.' }); }
    return queue(async () => {
      if (action === 'prepare') {
        if (entry.seq === state.seq && entry.hash === state.hash) return json(res, 200, { ok: true, duplicate: true });
        if (entry.seq !== state.seq + 1 || entry.prevHash !== state.hash || state.readOnly || state.unfinalized.size) return json(res, 409, { error: 'Replication sequence conflict.' });
        const current = state.prepared.get(entry.seq);
        if (current && current.hash !== entry.hash) return json(res, 409, { error: 'Conflicting prepared entry.' });
        await append({ type: 'prepare', entry }); state.prepared.set(entry.seq, entry);
        return json(res, 200, { ok: true });
      }
      if (action === 'abort') {
        await append({ type: 'abort', seq: entry.seq }); state.prepared.delete(entry.seq);
        state.readOnly = state.prepared.size > 0 || state.unfinalized.size > 0;
        return json(res, 200, { ok: true });
      }
      if (action === 'commit') {
        const pending = state.prepared.get(entry.seq);
        if (!pending || pending.hash !== entry.hash) {
          if (entry.seq === state.seq && entry.hash === state.hash) return json(res, 200, { ok: true, duplicate: true });
          return json(res, 409, { error: 'Commit has no matching prepare.' });
        }
        await append({ type: 'commit', entry }); applyEntry(entry); state.prepared.delete(entry.seq); state.unfinalized.set(entry.seq, entry);
        return json(res, 200, { ok: true });
      }
      if (action === 'finalize') {
        const pending = state.unfinalized.get(entry.seq);
        if (!pending || pending.hash !== entry.hash) return json(res, 409, { error: 'Finalize has no matching committed entry.' });
        await append({ type: 'finalize', seq: entry.seq, hash: entry.hash });
        state.unfinalized.delete(entry.seq);
        state.readOnly = state.prepared.size > 0 || state.unfinalized.size > 0;
        return json(res, 200, { ok: true });
      }
      return json(res, 400, { error: 'Unknown replication action.' });
    });
  }
  async function mutate(command) {
    if (state.readOnly || state.unfinalized.size) throw Object.assign(new Error('State node is read-only after an incomplete quorum operation; operator recovery is required.'), { status: 503 });
    const entry = { seq: state.seq + 1, prevHash: state.hash, command, timestamp: Date.now(), id: randomUUID() };
    entry.hash = hashEntry(entry);
    await append({ type: 'prepare', entry }); state.prepared.set(entry.seq, entry);
    let prepareAcks = 1;
    const prepareResults = await Promise.allSettled(peerUrls.map((peer) => signedPeerRequest(peer, 'prepare', entry)));
    prepareAcks += prepareResults.filter((result) => result.status === 'fulfilled').length;
    if (prepareAcks < quorum) {
      await append({ type: 'abort', seq: entry.seq }); state.prepared.delete(entry.seq);
      await Promise.allSettled(peerUrls.map((peer) => signedPeerRequest(peer, 'abort', entry)));
      throw Object.assign(new Error(`State quorum unavailable (${prepareAcks}/${quorum} prepare acknowledgements).`), { status: 503 });
    }
    await append({ type: 'commit', entry });
    const result = engine.apply(command, entry.timestamp);
    state.seq = entry.seq; state.hash = entry.hash; state.prepared.delete(entry.seq); state.unfinalized.set(entry.seq, entry);
    let commitAcks = 1;
    const commitResults = await Promise.allSettled(peerUrls.map((peer) => signedPeerRequest(peer, 'commit', entry)));
    commitAcks += commitResults.filter((item) => item.status === 'fulfilled').length;
    if (commitAcks < quorum) {
      state.readOnly = true;
      throw Object.assign(new Error(`State commit replication degraded (${commitAcks}/${quorum}); node is frozen for operator reconciliation.`), { status: 503 });
    }
    const finalizeResults = await Promise.allSettled(peerUrls.map((peer) => signedPeerRequest(peer, 'finalize', entry)));
    const finalizeAcks = 1 + finalizeResults.filter((item) => item.status === 'fulfilled').length;
    if (finalizeAcks < quorum) {
      state.readOnly = true;
      throw Object.assign(new Error(`State finalize replication degraded (${finalizeAcks}/${quorum}); node is frozen for operator reconciliation.`), { status: 503 });
    }
    try { await append({ type: 'finalize', seq: entry.seq, hash: entry.hash }); state.unfinalized.delete(entry.seq); }
    catch (error) { state.readOnly = true; throw error; }
    return result;
  }
  async function execute(command) {
    const parts = normalizeCommand(command);
    const name = parts[0].toUpperCase();
    if (!MUTATING.has(name)) return engine.apply(parts);
    if (role !== 'primary') throw Object.assign(new Error('Replica nodes are read-only for REST clients.'), { status: 503 });
    return queue(() => mutate(parts));
  }
  async function handleRequest(req, res) {
    if (req.method === 'GET' && req.url === '/health') return json(res, 200, { ok: true, role, seq: state.seq, hash: state.hash, readOnly: state.readOnly, prepared: state.prepared.size, unfinalized: state.unfinalized.size, quorum, peers: peerUrls.length });
    if (req.url === '/__arix/replicate') {
      try { return await handlePeer(req, res); }
      catch (error) { return json(res, error.status || 400, { error: String(error.message || error).slice(0, 180) }); }
    }
    if (!['POST'].includes(req.method) || !['/','/pipeline'].includes(req.url)) return json(res, 404, { error: 'Not found.' });
    const auth = String(req.headers.authorization || '');
    if (!auth.startsWith('Bearer ') || !equalSecret(auth.slice(7), restToken)) return json(res, 401, { error: 'Unauthorized.' });
    let payload;
    try { payload = await readJson(req, maxBodyBytes); }
    catch (error) { return json(res, error.status || 400, { error: error.message }); }
    if (req.url === '/pipeline') {
      if (!Array.isArray(payload) || payload.length > 500) return json(res, 400, { error: 'Pipeline must be an array of at most 500 commands.' });
      const rows = [];
      for (const command of payload) {
        try { rows.push({ result: await execute(command) }); }
        catch (error) { rows.push({ error: String(error.message || error).slice(0, 200) }); }
      }
      return json(res, 200, rows);
    }
    try { return json(res, 200, { result: await execute(payload) }); }
    catch (error) { return json(res, error.status || 400, { error: String(error.message || error).slice(0, 200) }); }
  }
  const server = http.createServer({ maxHeaderSize: 16 * 1024, headersTimeout: 10_000, requestTimeout: 15_000, keepAliveTimeout: 1000, maxRequestsPerSocket: 50 }, handleRequest);
  Object.defineProperties(server, {
    ready: { value: recover() },
    stateRequestHandler: { value: handleRequest },
    stateSnapshot: { value: () => ({ seq: state.seq, hash: state.hash, role, readOnly: state.readOnly, prepared: state.prepared.size, unfinalized: state.unfinalized.size, quorum, peers: peerUrls.length }) }
  });
  return server;
}

export async function startReplicatedStateServer(env = process.env) {
  const dataDir = env.ARIX_STATE_DATA_DIR || '/var/lib/arixshield-state';
  const peers = String(env.ARIX_STATE_PEERS || '').split(',').map((url) => url.trim()).filter(Boolean);
  const role = env.ARIX_STATE_ROLE || 'primary';
  const server = createReplicatedStateServer({ dataDir, peers, nodeId: env.ARIX_STATE_NODE_ID || 'arix-state-node', role });
  await server.ready;
  const certFile = env.ARIX_STATE_TLS_CERT_FILE; const keyFile = env.ARIX_STATE_TLS_KEY_FILE;
  if (Boolean(certFile) !== Boolean(keyFile)) throw new Error('Both ARIX_STATE_TLS_CERT_FILE and ARIX_STATE_TLS_KEY_FILE are required together.');
  if (certFile) {
    const [cert, key] = await Promise.all([readFile(certFile), readFile(keyFile)]);
    const secureServer = https.createServer({ cert, key, minVersion: 'TLSv1.2', maxHeaderSize: 16 * 1024, headersTimeout: 10_000, requestTimeout: 15_000, keepAliveTimeout: 1000 }, server.stateRequestHandler);
    Object.defineProperties(secureServer, { stateSnapshot: { value: server.stateSnapshot }, ready: { value: server.ready } });
    const port = Number(env.ARIX_STATE_PORT || 8090); const host = env.ARIX_STATE_LISTEN_HOST || '0.0.0.0';
    await new Promise((resolve, reject) => { secureServer.once('error', reject); secureServer.listen(port, host, resolve); });
    return secureServer;
  }
  if (env.NODE_ENV === 'production' && env.ARIX_STATE_TRUSTED_TLS_TERMINATOR !== 'true') throw new Error('Production state service requires TLS files or a confirmed private TLS terminator.');
  const port = Number(env.ARIX_STATE_PORT || 8090); const host = env.ARIX_STATE_LISTEN_HOST || '127.0.0.1';
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startReplicatedStateServer().then((server) => {
    const address = server.address(); process.stdout.write(`[ArixShield state] listening on ${typeof address === 'object' ? `${address.address}:${address.port}` : address}\n`);
    const shutdown = () => server.close(() => process.exit(0)); process.once('SIGTERM', shutdown); process.once('SIGINT', shutdown);
  }).catch((error) => { process.stderr.write(`[ArixShield state] startup failed: ${error.message}\n`); process.exitCode = 1; });
}
