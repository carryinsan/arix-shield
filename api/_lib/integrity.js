import { readFile, readdir } from 'node:fs/promises';
import { createHash, createHmac, timingSafeEqual, createPrivateKey } from 'node:crypto';
import { join, relative, sep } from 'node:path';

let cachedPromise;
const root = process.cwd();
const digest = (value) => createHash('sha256').update(value).digest('hex');
const signedFields = (manifest) => JSON.stringify({ schema: manifest.schema, algorithm: manifest.algorithm, fileCount: manifest.fileCount, rootDigest: manifest.rootDigest, files: manifest.files });

async function verify() {
  const deploymentProduction = process.env.VERCEL_ENV === 'production' || process.env.NODE_ENV === 'production';
  const production = deploymentProduction;
  const issues = [];
  let manifest;
  try { manifest = JSON.parse(await readFile(join(root, 'docs', 'INTEGRITY-MANIFEST.json'), 'utf8')); }
  catch { issues.push('INTEGRITY_MANIFEST_MISSING_OR_INVALID'); }
  const secret = process.env.ARIX_MASTER_SECRET;
  const secretReady = typeof secret === 'string' && Buffer.byteLength(secret) >= 32;
  if (!secretReady && production) issues.push('ARIX_MASTER_SECRET_MISSING_OR_TOO_SHORT');
  if (deploymentProduction && process.env.NODE_ENV !== 'production') issues.push('NODE_ENV_NOT_PRODUCTION');
  if (production && process.env.VERCEL !== '1' && process.env.ARIX_FORCE_HTTPS !== 'true') issues.push('HTTPS_DEPLOYMENT_NOT_ATTESTED');

  if (manifest && Array.isArray(manifest.files)) {
    const listed = manifest.files.filter((entry) => typeof entry?.path === 'string' && /^api\/_lib\/[A-Za-z0-9._/-]+\.js$/.test(entry.path));
    const allPaths = manifest.files.map((entry) => entry?.path);
    if (!listed.length) issues.push('INTEGRITY_MANIFEST_HAS_NO_API_LIBRARIES');
    if (manifest.fileCount !== manifest.files.length || new Set(allPaths).size !== allPaths.length) issues.push('INTEGRITY_MANIFEST_FILE_COUNT_OR_DUPLICATE_PATH_ERROR');
    for (const entry of listed) {
      const segments = entry.path.split('/');
      if (segments.some((part) => !part || part === '.' || part === '..') || !/^[a-f0-9]{64}$/.test(entry.sha256 || '')) {
        issues.push(`INTEGRITY_MANIFEST_ENTRY_INVALID:${String(entry.path).slice(0, 100)}`);
        continue;
      }
      try {
        const actual = digest(await readFile(join(root, ...segments)));
        if (actual !== entry.sha256) issues.push(`FILE_DRIFT:${entry.path}`);
      } catch { issues.push(`FILE_MISSING:${entry.path}`); }
    }
    const expectedLibraryPaths = [];
    async function collectLibraryFiles(directory, relativeDirectory = 'api/_lib') {
      for (const item of await readdir(directory, { withFileTypes: true })) {
        if (item.isSymbolicLink()) { issues.push(`INTEGRITY_LIBRARY_SYMLINK_REJECTED:${relativeDirectory}/${item.name}`); continue; }
        if (item.isDirectory()) await collectLibraryFiles(join(directory, item.name), `${relativeDirectory}/${item.name}`);
        else if (item.isFile() && item.name.endsWith('.js')) expectedLibraryPaths.push(`${relativeDirectory}/${item.name}`);
      }
    }
    try { await collectLibraryFiles(join(root, 'api', '_lib')); }
    catch { issues.push('INTEGRITY_API_LIBRARY_DIRECTORY_UNREADABLE'); }
    const listedPaths = new Set(listed.map((entry) => entry.path));
    for (const path of expectedLibraryPaths) if (!listedPaths.has(path)) issues.push(`INTEGRITY_LIBRARY_NOT_MANIFESTED:${path}`);
    for (const path of listedPaths) if (!expectedLibraryPaths.includes(path)) issues.push(`INTEGRITY_MANIFEST_EXTRA_LIBRARY:${path}`);
    const rootDigest = digest(JSON.stringify(manifest.files));
    if (rootDigest !== manifest.rootDigest) issues.push('INTEGRITY_ROOT_DIGEST_MISMATCH');
    if (production) {
      const signature = manifest.signature;
      if (!secretReady || signature?.algorithm !== 'HMAC-SHA256' || !/^[a-f0-9]{64}$/.test(signature?.value || '')) issues.push('INTEGRITY_MANIFEST_UNSIGNED');
      else {
        const expected = createHmac('sha256', secret).update(signedFields(manifest)).digest();
        const actual = Buffer.from(signature.value, 'hex');
        if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) issues.push('INTEGRITY_SIGNATURE_INVALID');
      }
    }
  }

  if (production) {
    try {
      const raw = process.env.ARIX_CLEARANCE_PRIVATE_JWK;
      const jwk = raw && raw.length <= 16000 ? JSON.parse(raw) : null;
      if (!jwk || jwk.kty !== 'RSA' || !jwk.n || !jwk.e || !jwk.d) throw new Error('invalid');
      const configuredKid = process.env.ARIX_CLEARANCE_KID;
      if (configuredKid && jwk.kid && configuredKid !== jwk.kid) throw new Error('kid mismatch');
      const effectiveKid = String(configuredKid || jwk.kid || '');
      if (!/^[A-Za-z0-9._-]{1,128}$/.test(effectiveKid)) throw new Error('invalid kid');
      const key = createPrivateKey({ key: jwk, format: 'jwk' });
      if (key.asymmetricKeyType !== 'rsa' || Number(key.asymmetricKeyDetails?.modulusLength || 0) < 3072) throw new Error('invalid');
    } catch { issues.push('ARIX_CLEARANCE_PRIVATE_JWK_INVALID_OR_MISSING'); }
    try {
      const vercel = JSON.parse(await readFile(join(root, 'vercel.json'), 'utf8'));
      const headerValues = (vercel.headers || []).flatMap((item) => item.headers || []).map((item) => `${item.key}:${item.value}`.toLowerCase());
      if (!headerValues.some((value) => value.startsWith('strict-transport-security:')) || !headerValues.some((value) => value.includes('upgrade-insecure-requests'))) issues.push('HTTPS_SECURITY_HEADERS_MISSING');
    } catch { issues.push('HTTPS_CONFIGURATION_UNVERIFIABLE'); }
  }
  return { ok: issues.length === 0 || !production, production, issues, checkedAt: new Date().toISOString(), manifestRoot: manifest?.rootDigest || null };
}

export function verifyRuntimeIntegrity({ refresh = false } = {}) {
  if (refresh || !cachedPromise) cachedPromise = verify().catch((error) => ({ ok: false, production: process.env.NODE_ENV === 'production', issues: [`INTEGRITY_CHECK_FAILED:${String(error?.message || error).slice(0, 120)}`], checkedAt: new Date().toISOString(), manifestRoot: null }));
  return cachedPromise;
}
