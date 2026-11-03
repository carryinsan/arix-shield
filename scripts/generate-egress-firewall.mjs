import { writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { parseCidr } from '../api/_lib/cidr.js';

const V4_BLOCKED = ['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.0.0.0/24','192.0.2.0/24','192.88.99.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4'];
const V6_BLOCKED = ['::/128','::1/128','::ffff:0:0/96','64:ff9b::/96','64:ff9b:1::/48','100::/64','2001::/23','2001:2::/48','2001:10::/28','2001:20::/28','2001:30::/28','2001:db8::/32','2002::/16','3fff::/20','fc00::/7','fe80::/10','fec0::/10','ff00::/8'];

function parseArgs(argv) {
  const values = { uid: '65532', allow: [], output: '' };
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === '--uid') values.uid = argv[++index] || '';
    else if (arg === '--allow-cidr') values.allow.push(argv[++index] || '');
    else if (arg === '--output') values.output = argv[++index] || '';
    else if (arg === '--help') values.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!/^\d{1,10}$/.test(values.uid) || Number(values.uid) > 4294967294) throw new Error('--uid must be a valid numeric Linux UID.');
  for (const cidr of values.allow) if (!parseCidr(cidr)) throw new Error(`Invalid --allow-cidr value: ${cidr}`);
  return values;
}

export function generateEgressFirewallRules({ uid = '65532', allow = [] } = {}) {
  if (!/^\d{1,10}$/.test(String(uid)) || Number(uid) > 4294967294) throw new TypeError('uid must be numeric.');
  if (!Array.isArray(allow) || allow.length > 128) throw new TypeError('allow must be an array of at most 128 CIDRs.');
  const parsedAllow = allow.map((entry) => { const parsed = parseCidr(String(entry)); if (!parsed) throw new TypeError(`Invalid allow CIDR: ${entry}`); return parsed; });
  const v4Allow = parsedAllow.filter((entry) => entry.family === 4).map((entry) => entry.source);
  const v6Allow = parsedAllow.filter((entry) => entry.family === 6).map((entry) => entry.source);
  const allowRules = [
    ...(v4Allow.length ? [`    meta skuid ${uid} ip daddr { ${v4Allow.join(', ')} } accept`] : []),
    ...(v6Allow.length ? [`    meta skuid ${uid} ip6 daddr { ${v6Allow.join(', ')} } accept`] : [])
  ];
  return [
    '# ArixShield generated egress-deny fragment. Review before applying.',
    '# This policy is scoped to the selected process UID and does not replace ingress/DDoS controls.',
    'table inet arixshield_egress {',
    '  chain output {',
    '    type filter hook output priority filter; policy accept;',
    ...allowRules,
    `    meta skuid ${uid} ip daddr { ${V4_BLOCKED.join(', ')} } drop`,
    `    meta skuid ${uid} ip6 daddr { ${V6_BLOCKED.join(', ')} } drop`,
    '  }',
    '}',
    ''
  ].join('\n');
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    process.stdout.write('Usage: node scripts/generate-egress-firewall.mjs [--uid 65532] [--allow-cidr 10.0.0.5/32] [--output rules.nft]\n');
    return;
  }
  const rules = generateEgressFirewallRules(options);
  if (options.output) await writeFile(options.output, rules, { mode: 0o600, flag: 'wx' });
  else process.stdout.write(rules);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => { process.stderr.write(`[egress-firewall] ${error.message}\n`); process.exitCode = 1; });
}
