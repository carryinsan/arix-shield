import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function runPreload(enabled, modulePath = './sdk/register-egress-firewall.js') {
  const source = `
    const before = globalThis.fetch;
    const loaded = await import('${modulePath}');
    const status = loaded.egressFirewallStatus ?? (await import('./sdk/process-egress-firewall.js')).processEgressFirewallStatus();
    const active = status.active === true;
    const changed = globalThis.fetch !== before;
    if (active !== ${enabled} || changed !== ${enabled}) process.exit(7);
    if (active) status.uninstall();
    if (globalThis.fetch !== before) process.exit(8);
    process.stdout.write('ok');
  `;
  return spawnSync(process.execPath, ['--input-type=module', '-e', source], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, ARIX_PROCESS_EGRESS_FIREWALL: enabled ? 'true' : 'false' }
  });
}

test('egress preload is inert unless ARIX_PROCESS_EGRESS_FIREWALL=true', () => {
  const result = runPreload(false);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(result.stdout, 'ok');
});

test('egress preload installs and restores only when explicitly enabled', () => {
  const result = runPreload(true);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(result.stdout, 'ok');
});


test('Node SDK import installs the global fetch guard only when explicitly enabled', () => {
  for (const enabled of [false, true]) {
    const result = runPreload(enabled, './sdk/node.js');
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(result.stdout, 'ok');
  }
});
