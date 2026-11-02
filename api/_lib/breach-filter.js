import { createHash } from 'node:crypto';

const MAGIC = 'ARIX-XOR16-V1';
const MAX_WORDS = 2_000_000;

export function normalizeBreachCandidate(value) {
  return String(value ?? '').normalize('NFKC').toLowerCase()
    .replace(/[@]/g, 'a').replace(/[0]/g, 'o').replace(/[1!|]/g, 'i')
    .replace(/[3]/g, 'e').replace(/[4]/g, 'a').replace(/[5$]/g, 's')
    .replace(/[7]/g, 't').replace(/[^a-z0-9]/g, '').slice(0, 256);
}

function hash64(value, seed) {
  const digest = createHash('sha256').update(`${seed}\0${value}`, 'utf8').digest();
  return digest.readBigUInt64LE(0);
}

function mix64(value) {
  let x = BigInt.asUintN(64, value);
  x ^= x >> 30n; x = BigInt.asUintN(64, x * 0xbf58476d1ce4e5b9n);
  x ^= x >> 27n; x = BigInt.asUintN(64, x * 0x94d049bb133111ebn);
  return BigInt.asUintN(64, x ^ (x >> 31n));
}

function positions(hash, blockLength) {
  // Modulo is intentional: block sizes are not required to be powers of two.
  const a = Number(hash % BigInt(blockLength));
  const b = blockLength + Number(mix64(hash) % BigInt(blockLength));
  const c = 2 * blockLength + Number(mix64(hash ^ 0x9e3779b97f4a7c15n) % BigInt(blockLength));
  return [a, b, c];
}

function fingerprint(hash) {
  const value = Number((mix64(hash) >> 32n) & 0xffffn);
  return value || 1;
}

/** Build a deterministic 16-bit, 3-part XOR filter. Inputs are normalized and deduplicated. */
export function compileXorFilter(words, { seed = 'arixshield-breach-v1', maxWords = MAX_WORDS, retries = 16 } = {}) {
  if (!Array.isArray(words) && !(words && typeof words[Symbol.iterator] === 'function')) throw new TypeError('words must be iterable');
  if (!Number.isInteger(maxWords) || maxWords < 1 || maxWords > MAX_WORDS || !Number.isInteger(retries) || retries < 1 || retries > 64 || String(seed).length > 128) throw new RangeError('Invalid XOR filter build limits or seed');
  const unique = new Set();
  for (const word of words) {
    const normalized = normalizeBreachCandidate(word);
    if (normalized) unique.add(normalized);
    if (unique.size > maxWords) throw new RangeError(`word list exceeds maxWords (${maxWords})`);
  }
  const values = [...unique];
  if (!values.length) return { magic: MAGIC, seed, count: 0, blockLength: 0, fingerprints: '' };
  const blockLength = Math.max(3, Math.ceil(values.length * 1.30 / 3));
  for (let attempt = 0; attempt < retries; attempt++) {
    const attemptSeed = attempt ? `${seed}:${attempt}` : seed;
    const hashes = values.map((value) => hash64(value, attemptSeed));
    const slots = hashes.map((hash) => positions(hash, blockLength));
    const size = blockLength * 3;
    const degree = new Uint32Array(size);
    const xors = new Uint32Array(size);
    for (let i = 0; i < slots.length; i++) for (const slot of slots[i]) { degree[slot]++; xors[slot] ^= i; }
    const queue = [];
    for (let slot = 0; slot < size; slot++) if (degree[slot] === 1) queue.push(slot);
    const stack = [];
    for (let head = 0; head < queue.length; head++) {
      const slot = queue[head];
      if (degree[slot] !== 1) continue;
      const index = xors[slot];
      stack.push([index, slot]);
      for (const other of slots[index]) {
        if (degree[other] === 0) continue;
        degree[other]--;
        xors[other] ^= index;
        if (degree[other] === 1) queue.push(other);
      }
    }
    if (stack.length !== values.length) continue;
    const array = new Uint16Array(size);
    for (let i = stack.length - 1; i >= 0; i--) {
      const [index, selected] = stack[i];
      let value = fingerprint(hashes[index]);
      for (const slot of slots[index]) if (slot !== selected) value ^= array[slot];
      array[selected] = value;
    }
    const bytes = Buffer.alloc(array.length * 2);
    for (let index = 0; index < array.length; index++) bytes.writeUInt16LE(array[index], index * 2);
    return { magic: MAGIC, seed: attemptSeed, count: values.length, blockLength, fingerprints: bytes.toString('base64') };
  }
  throw new Error('XOR_FILTER_BUILD_FAILED: retry with a different seed or larger load factor');
}

export function createXorFilter(filter) {
  if (!filter || filter.magic !== MAGIC || typeof filter.seed !== 'string' || !Number.isInteger(filter.count) || filter.count < 0) throw new TypeError('Invalid Arix XOR filter');
  if (filter.count === 0) return Object.freeze({ has: () => false, count: 0, falsePositiveRateUpperBound: 1 / 65536 });
  if (!Number.isInteger(filter.blockLength) || filter.blockLength < 1 || typeof filter.fingerprints !== 'string') throw new TypeError('Invalid Arix XOR filter dimensions');
  const bytes = Buffer.from(filter.fingerprints, 'base64');
  if (bytes.toString('base64') !== filter.fingerprints || bytes.length !== filter.blockLength * 3 * 2) throw new TypeError('Invalid Arix XOR filter payload length');
  const seed = filter.seed;
  return Object.freeze({
    count: filter.count,
    falsePositiveRateUpperBound: 1 / 65536,
    has(value) {
      const normalized = normalizeBreachCandidate(value);
      if (!normalized) return false;
      const hash = hash64(normalized, seed);
      const [a, b, c] = positions(hash, filter.blockLength);
      return (bytes.readUInt16LE(a * 2) ^ bytes.readUInt16LE(b * 2) ^ bytes.readUInt16LE(c * 2)) === fingerprint(hash);
    }
  });
}

export function estimateMarkovEntropyBits(value, corpus = []) {
  if (!Array.isArray(corpus)) throw new TypeError('corpus must be an array');
  const input = normalizeBreachCandidate(value);
  if (!input) return 0;
  const uni = new Map(); const bi = new Map(); const tri = new Map();
  let total = 0;
  for (const word of corpus.slice(0, 100_000)) {
    const s = normalizeBreachCandidate(word);
    for (let i = 0; i < s.length; i++) {
      const c = s[i]; uni.set(c, (uni.get(c) || 0) + 1); total++;
      if (i >= 1) { const k = s.slice(i - 1, i + 1); bi.set(k, (bi.get(k) || 0) + 1); }
      if (i >= 2) { const k = s.slice(i - 2, i + 1); tri.set(k, (tri.get(k) || 0) + 1); }
    }
  }
  if (!total) {
    // Conservative fallback: sequence diversity estimate, not a cracking-cost guarantee.
    const alphabet = new Set(input).size;
    return input.length * Math.log2(Math.max(1, alphabet));
  }
  let bits = 0;
  for (let i = 0; i < input.length; i++) {
    const c = input[i];
    const context = i >= 2 ? input.slice(i - 2, i + 1) : i >= 1 ? input.slice(i - 1, i + 1) : c;
    const count = i >= 2 ? tri.get(context) : i >= 1 ? bi.get(context) : uni.get(c);
    const denominator = i >= 2 ? (bi.get(input.slice(i - 2, i)) || 0) : i >= 1 ? (uni.get(input[i - 1]) || 0) : total;
    const probability = (count || 0.25) / (denominator + 0.25 * 36);
    bits += Math.max(0, -Math.log2(Math.min(1, probability)));
  }
  return bits;
}

export const DEFAULT_BREACH_WORDS = Object.freeze([
  'password','password1','password123','password1234','passw0rd','qwerty','qwerty123','qwertyuiop','123456','123456789','1234567890','111111','000000','iloveyou','letmein','welcome','admin','administrator','changeme','monkey','dragon','football','baseball','sunshine','princess','shadow','master','login','abc123','trustnoone','secret','password2026','welcome2026','admin123','p@ssw0rd','p@ssw0rd123','P@ssw0rd123','1q2w3e4r','1q2w3e4r5t','1qaz2wsx','zaq12wsx','qazwsxedc','asdfghjkl','zxcvbnm','iloveyou1','whatever','computer','internet','testing','test1234','pass1234','root','toor','changeme1','letmein1','welcome1','qwerty1','qwerty12','football1','monkey1','dragon1','sunshine1','princess1','starwars','pokemon','matrix','shadow1','master1','freedom','hello123','hellohello','welcomehome','password!','pass@123','india123','gujarat123','arixshield','arixadmin','arix123456','qwerty123456','1q2w3e4r5t6y','qwertyuiop123','asdf1234','qwerty!','iloveyou123','summer2026','winter2026','spring2026','autumn2026'
]);

export const DEFAULT_BREACH_FILTER = compileXorFilter(DEFAULT_BREACH_WORDS);
export const defaultBreachFilter = createXorFilter(DEFAULT_BREACH_FILTER);
