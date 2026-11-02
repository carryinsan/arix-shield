import { isIP } from 'node:net';

function ipv4ToBigInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return null;
  return parts.reduce((value, part) => (value << 8n) | BigInt(Number(part)), 0n);
}

function ipv6ToBigInt(ip) {
  let value = ip.toLowerCase().split('%')[0];
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    const ipv4 = ipv4ToBigInt(value.slice(lastColon + 1));
    if (ipv4 === null) return null;
    value = `${value.slice(0, lastColon)}:${((ipv4 >> 16n) & 0xffffn).toString(16)}:${(ipv4 & 0xffffn).toString(16)}`;
  }
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const words = [...left, ...Array(missing).fill('0'), ...right];
  if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/.test(word))) return null;
  return words.reduce((result, word) => (result << 16n) | BigInt(parseInt(word, 16)), 0n);
}

export function parseIp(ip) {
  if (typeof ip !== 'string') return null;
  const normalized = ip.trim().replace(/^\[|\]$/g, '').split('%')[0];
  const family = isIP(normalized);
  if (family === 4) return { family, bits: 32, value: ipv4ToBigInt(normalized), normalized };
  if (family === 6) return { family, bits: 128, value: ipv6ToBigInt(normalized), normalized };
  return null;
}

export function parseCidr(input) {
  if (typeof input !== 'string' || input.length > 100) return null;
  const [address, rawPrefix, extra] = input.trim().split('/');
  if (extra !== undefined) return null;
  const ip = parseIp(address);
  if (!ip) return null;
  const prefix = rawPrefix === undefined ? ip.bits : Number(rawPrefix);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > ip.bits) return null;
  return { family: ip.family, bits: ip.bits, prefix, value: ip.value, source: `${ip.normalized}/${prefix}` };
}

export function cidrContains(cidr, ipAddress) {
  const network = typeof cidr === 'string' ? parseCidr(cidr) : cidr;
  const ip = parseIp(ipAddress);
  if (!network || !ip || network.family !== ip.family) return false;
  if (network.prefix === 0) return true;
  const shift = BigInt(network.bits - network.prefix);
  return (network.value >> shift) === (ip.value >> shift);
}

export function buildPrefixTrie(cidrs = []) {
  const roots = { 4: { zero: null, one: null, terminal: false }, 6: { zero: null, one: null, terminal: false } };
  let valid = 0;
  for (const raw of cidrs) {
    const network = parseCidr(raw);
    if (!network) continue;
    let node = roots[network.family];
    for (let bit = 0; bit < network.prefix; bit++) {
      const direction = Number((network.value >> BigInt(network.bits - bit - 1)) & 1n) ? 'one' : 'zero';
      node[direction] ??= { zero: null, one: null, terminal: false };
      node = node[direction];
    }
    node.terminal = true;
    valid++;
  }
  return { roots, count: valid };
}

export function prefixTrieHas(trie, ipAddress) {
  const ip = parseIp(ipAddress);
  if (!trie || !ip) return false;
  let node = trie.roots[ip.family];
  if (!node) return false;
  if (node.terminal) return true;
  for (let bit = 0; bit < ip.bits; bit++) {
    const direction = Number((ip.value >> BigInt(ip.bits - bit - 1)) & 1n) ? 'one' : 'zero';
    node = node?.[direction];
    if (!node) return false;
    if (node.terminal) return true;
  }
  return false;
}

export function formatIpPrefix(ipAddress, prefixLength = null) {
  const ip = parseIp(ipAddress);
  if (!ip) return null;
  const prefix = prefixLength === null ? (ip.family === 4 ? 24 : 48) : Number(prefixLength);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > ip.bits) return null;
  const shift = BigInt(ip.bits - prefix);
  const network = shift === 0n ? ip.value : (ip.value >> shift) << shift;
  let address;
  if (ip.family === 4) {
    address = [24n, 16n, 8n, 0n].map((bits) => Number((network >> bits) & 255n)).join('.');
  } else {
    const groups = [];
    for (let index = 7; index >= 0; index--) groups.push(Number((network >> BigInt(index * 16)) & 0xffffn).toString(16));
    address = groups.join(':');
  }
  return `${address}/${prefix}`;
}
