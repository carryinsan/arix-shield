import { readFile } from 'node:fs/promises';

function parseStatus(statusText) {
  const fields = new Map();
  for (const line of String(statusText).split(/\r?\n/)) {
    const separator = line.indexOf(':');
    if (separator > 0) fields.set(line.slice(0, separator), line.slice(separator + 1).trim());
  }
  return fields;
}

/**
 * Inspect Linux process hardening controls without changing host state. A
 * successful result is evidence only for this process at inspection time; it
 * is not an attestation of the full container, kernel, network, or database.
 */
export async function inspectLinuxHostHardening({ statusPath = '/proc/self/status', uid = process.getuid?.(), readStatus = readFile } = {}) {
  if (process.platform !== 'linux') return Object.freeze({ supported: false, ok: false, issues: ['HOST_ATTESTATION_LINUX_ONLY'] });
  let status;
  try { status = parseStatus(await readStatus(statusPath, 'utf8')); }
  catch { return Object.freeze({ supported: true, ok: false, issues: ['HOST_STATUS_UNREADABLE'] }); }

  const issues = [];
  if (!Number.isInteger(uid) || uid === 0) issues.push('HOST_PROCESS_MUST_NOT_RUN_AS_ROOT');
  if (status.get('NoNewPrivs') !== '1') issues.push('HOST_NO_NEW_PRIVILEGES_NOT_SET');
  const effectiveCapabilities = status.get('CapEff');
  if (!effectiveCapabilities || !/^0+$/.test(effectiveCapabilities)) issues.push('HOST_EFFECTIVE_CAPABILITIES_NOT_ZERO');
  return Object.freeze({
    supported: true,
    ok: issues.length === 0,
    uid: Number.isInteger(uid) ? uid : null,
    noNewPrivileges: status.get('NoNewPrivs') === '1',
    effectiveCapabilitiesZero: Boolean(effectiveCapabilities && /^0+$/.test(effectiveCapabilities)),
    issues: Object.freeze(issues)
  });
}

/** Pure compatibility helper for inspecting a supplied Linux proc-status snapshot. */
export function inspectLinuxHardeningStatus({ platform = process.platform, uid = process.getuid?.(), statusText = '' } = {}) {
  const issues = [];
  if (platform !== 'linux' || !Number.isInteger(uid)) return { ok: false, issues: ['LINUX_HARDENING_ATTESTATION_UNAVAILABLE'] };
  if (uid === 0) issues.push('LINUX_RUNTIME_IS_ROOT');
  const noNewPrivs = /^NoNewPrivs:\s+(\d+)\s*$/m.exec(String(statusText))?.[1];
  const effectiveCaps = /^CapEff:\s+([a-f0-9]+)\s*$/im.exec(String(statusText))?.[1];
  if (noNewPrivs !== '1') issues.push('LINUX_NO_NEW_PRIVS_NOT_SET');
  if (!effectiveCaps || !/^0+$/.test(effectiveCaps)) issues.push('LINUX_EFFECTIVE_CAPABILITIES_NOT_EMPTY');
  return { ok: issues.length === 0, issues };
}
