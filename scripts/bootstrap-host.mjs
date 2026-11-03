#!/usr/bin/env node
import { writeFile, mkdtemp, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { resolve, dirname, join } from 'node:path';
import { mkdir } from 'node:fs/promises';
import { parseCidr } from '../api/_lib/cidr.js';

const args = new Set(process.argv.slice(2));
const apply = args.has('--apply-firewall');
const edgePort = Number(process.env.ARIX_BOOTSTRAP_EDGE_PORT || 443);
const sshPort = Number(process.env.ARIX_BOOTSTRAP_SSH_PORT || 22);
const edgeCidrs = String(process.env.ARIX_BOOTSTRAP_EDGE_CIDRS || '').split(',').map((s) => s.trim()).filter(Boolean);
const sshCidrs = String(process.env.ARIX_BOOTSTRAP_SSH_CIDRS || '').split(',').map((s) => s.trim()).filter(Boolean);

function validCidr(value) {
  return value.length <= 64 && Boolean(parseCidr(value));
}
function run(command, commandArgs) {
  const result = spawnSync(command, commandArgs, { encoding: 'utf8' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} failed: ${(result.stderr || result.stdout || '').trim().slice(0, 500)}`);
  return result.stdout;
}

if (process.platform !== 'linux') throw new Error('Host provisioning supports Linux only.');
if (typeof process.getuid !== 'function' || process.getuid() !== 0) throw new Error('Run this command as root through a reviewed administrative session.');
if (!Number.isInteger(edgePort) || edgePort < 1 || edgePort > 65535 || !Number.isInteger(sshPort) || sshPort < 1 || sshPort > 65535) throw new Error('Invalid edge/SSH port configuration.');
if (!edgeCidrs.length || !sshCidrs.length || [...edgeCidrs, ...sshCidrs].some((cidr) => !validCidr(cidr))) {
  throw new Error('Set explicit ARIX_BOOTSTRAP_EDGE_CIDRS and ARIX_BOOTSTRAP_SSH_CIDRS first. This safety check prevents accidental remote lockout.');
}
run('nft', ['--version']);
const ruleSet = [
  'table inet arixshield_guard {',
  '  chain input {',
  '    type filter hook input priority -50; policy accept;',
  '    iifname "lo" accept',
  '    ct state established,related accept',
  ...sshCidrs.map((cidr) => `${cidr.includes(':') ? 'ip6' : 'ip'} saddr ${cidr} tcp dport ${sshPort} accept`),
  ...edgeCidrs.map((cidr) => `${cidr.includes(':') ? 'ip6' : 'ip'} saddr ${cidr} tcp dport ${edgePort} accept`),
  `tcp dport { ${sshPort}, ${edgePort} } drop`,
  '  }',
  '}',
  ''
].join('\n');
const output = resolve('/etc/nftables.d/arixshield-guard.nft');
if (edgePort === sshPort) throw new Error('The edge HTTPS port and SSH administration port must be different.');
if (!apply) {
  process.stdout.write(`PREVIEW ONLY: no host policy changed.\nWould write ${output}:\n${ruleSet}\nRe-run with --apply-firewall after reviewing CIDRs and confirming out-of-band console access.\n`);
  process.exit(0);
}
const systemdUnit = resolve('/etc/systemd/system/arixshield-guard.service');
const nftBinary = run('sh', ['-lc', 'command -v nft']).trim();
if (!nftBinary || !/^[A-Za-z0-9_./-]+$/.test(nftBinary)) throw new Error('Could not resolve a safe nft binary path.');
run('systemctl', ['--version']);
await mkdir(dirname(output), { recursive: true, mode: 0o700 });
const temporaryDirectory = await mkdtemp('/run/arixshield-host-bootstrap-');
const checkFile = join(temporaryDirectory, 'rules.nft');
try {
  // `destroy` is idempotent on nftables versions that support it. The delete
  // and replacement happen in one nftables batch, including on service restart.
  const applyContents = `destroy table inet arixshield_guard\n${ruleSet}`;
  await writeFile(checkFile, applyContents, { mode: 0o600, flag: 'wx' });
  run('nft', ['--check', '-f', checkFile]);
  run('nft', ['-f', checkFile]);
  await writeFile(output, applyContents, { mode: 0o600 });
  const unit = [
    '[Unit]',
    'Description=ArixShield dedicated ingress allowlist guard',
    'Wants=network-pre.target',
    'Before=network-pre.target',
    'After=local-fs.target nftables.service',
    '',
    '[Service]',
    'Type=oneshot',
    'RemainAfterExit=yes',
    `ExecStartPre=${nftBinary} --check -f ${output}`,
    `ExecStart=${nftBinary} -f ${output}`,
    '',
    '[Install]',
    'WantedBy=multi-user.target',
    ''
  ].join('\n');
  await writeFile(systemdUnit, unit, { mode: 0o644 });
  run('systemctl', ['daemon-reload']);
  run('systemctl', ['enable', '--now', 'arixshield-guard.service']);
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true });
}
process.stdout.write(`Applied and enabled the dedicated ArixShield ingress guard at boot; rules saved to ${output}, unit saved to ${systemdUnit}. Existing nftables tables were not flushed. The guard restricts only the configured SSH/edge TCP ports and does not create an outbound egress policy.\n`);
