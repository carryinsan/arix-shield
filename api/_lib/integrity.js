import { readFile, readdir } from 'node:fs/promises';
import { createHash, createHmac, timingSafeEqual, createPrivateKey } from 'node:crypto';
import { join } from 'node:path';
import { CLEARANCE_RSA_MIN_BITS } from './security-constants.js';
import { inspectLinuxHostHardening, inspectLinuxHardeningStatus } from './host-attestation.js';
export { inspectLinuxHardeningStatus };

let cachedPromise;
const root = process.cwd();
const digest = (value) => createHash('sha256').update(value).digest('hex');
const signedFields = (manifest) => JSON.stringify({ schema: manifest.schema, algorithm: manifest.algorithm, fileCount: manifest.fileCount, rootDigest: manifest.rootDigest, files: manifest.files });
const SOURCE_PATH_PATTERN = /^(?:proxy(?:-core)?\.js|(?:api|sdk|edge|scripts|public|test|security-test-pack|state)\/[A-Za-z0-9._/-]+\.(?:js|mjs|html))$/;
const IGNORED_DIRECTORIES = new Set(['node_modules', '.git', '.vercel', '.next', 'coverage']);

function validManifestPath(path) {
  if (typeof path !== 'string' || !SOURCE_PATH_PATTERN.test(path)) return false;
  const segments = path.split('/');
  return segments.every((part) => part && part !== '.' && part !== '..');
}

async function collectApiSourcePaths(directory, relativeDirectory = 'api', output = [], issues = []) {
  for (const item of await readdir(directory, { withFileTypes: true })) {
    const relativePath = `${relativeDirectory}/${item.name}`;
    if (item.isSymbolicLink()) {
      issues.push(`INTEGRITY_API_SYMLINK_REJECTED:${relativePath}`);
      continue;
    }
    if (item.isDirectory()) await collectApiSourcePaths(join(directory, item.name), relativePath, output, issues);
    else if (item.isFile() && /\.(?:js|mjs)$/.test(item.name)) output.push(relativePath);
  }
  return output;
}

async function verify() {
  const deploymentProduction = process.env.VERCEL_ENV === 'production' || process.env.NODE_ENV === 'production';
  const production = deploymentProduction;
  const issues = [];
  let manifest;
  try { manifest = JSON.parse(await readFile(join(root, 'api', '_integrity-manifest.json'), 'utf8')); }
  catch { issues.push('INTEGRITY_MANIFEST_MISSING_OR_INVALID'); }
  const secret = process.env.ARIX_MASTER_SECRET;
  const secretReady = typeof secret === 'string' && Buffer.byteLength(secret) >= 32;
  if (!secretReady && production) issues.push('ARIX_MASTER_SECRET_MISSING_OR_TOO_SHORT');
  if (deploymentProduction && process.env.NODE_ENV !== 'production') issues.push('NODE_ENV_NOT_PRODUCTION');
  if (production && process.env.VERCEL !== '1' && process.env.ARIX_FORCE_HTTPS !== 'true') issues.push('HTTPS_DEPLOYMENT_NOT_ATTESTED');
  if (process.env.ARIX_REQUIRE_HARDENED_HOST === 'true') {
    const host = await inspectLinuxHostHardening();
    if (!host.supported) issues.push('HOST_HARDENING_NOT_SUPPORTED');
    else if (!host.ok) issues.push(...host.issues);
  }

  if (manifest) {
    if (manifest.schema !== 'arixshield.integrity.v1' || manifest.algorithm !== 'SHA-256' || !Array.isArray(manifest.files)) {
      issues.push('INTEGRITY_MANIFEST_SCHEMA_INVALID');
    } else {
      const allPaths = manifest.files.map((entry) => entry?.path);
      if (!Number.isSafeInteger(manifest.fileCount) || manifest.fileCount !== manifest.files.length || new Set(allPaths).size !== allPaths.length) {
        issues.push('INTEGRITY_MANIFEST_FILE_COUNT_OR_DUPLICATE_PATH_ERROR');
      }
      const listedApi = new Set();
      for (const entry of manifest.files) {
        if (!entry || !validManifestPath(entry.path) || !/^[a-f0-9]{64}$/.test(entry.sha256 || '')) {
          issues.push(`INTEGRITY_MANIFEST_ENTRY_INVALID:${String(entry?.path || 'unknown').slice(0, 100)}`);
          continue;
        }
        if (entry.path.startsWith('api/')) listedApi.add(entry.path);
        // The API tree is bundled in every serverless function (see vercel.json),
        // so verify all route handlers as well as shared libraries, not only _lib.
        if (entry.path.startsWith('api/')) {
          const segments = entry.path.split('/');
          try {
            const actual = digest(await readFile(join(root, ...segments)));
            if (actual !== entry.sha256) issues.push(`FILE_DRIFT:${entry.path}`);
          } catch { issues.push(`FILE_MISSING:${entry.path}`); }
        }
      }
      const expectedApiPaths = [];
      try { await collectApiSourcePaths(join(root, 'api'), 'api', expectedApiPaths, issues); }
      catch { issues.push('INTEGRITY_API_SOURCE_TREE_UNREADABLE'); }
      const expected = new Set(expectedApiPaths);
      for (const path of expected) if (!listedApi.has(path)) issues.push(`INTEGRITY_API_SOURCE_NOT_MANIFESTED:${path}`);
      for (const path of listedApi) if (!expected.has(path)) issues.push(`INTEGRITY_MANIFEST_EXTRA_API_SOURCE:${path}`);

      const rootDigest = digest(JSON.stringify(manifest.files));
      if (!/^[a-f0-9]{64}$/.test(manifest.rootDigest || '') || rootDigest !== manifest.rootDigest) issues.push('INTEGRITY_ROOT_DIGEST_MISMATCH');
      if (production) {
        const signature = manifest.signature;
        if (!secretReady || signature?.algorithm !== 'HMAC-SHA256' || !/^[a-f0-9]{64}$/.test(signature?.value || '')) issues.push('INTEGRITY_MANIFEST_UNSIGNED');
        else {
          const expectedSignature = createHmac('sha256', secret).update(signedFields(manifest)).digest();
          const actualSignature = Buffer.from(signature.value, 'hex');
          if (actualSignature.length !== expectedSignature.length || !timingSafeEqual(actualSignature, expectedSignature)) issues.push('INTEGRITY_SIGNATURE_INVALID');
        }
      } else if (manifest.signature?.algorithm === 'HMAC-SHA256' && /^[a-f0-9]{64}$/.test(manifest.signature?.value || '') && secretReady) {
        const expectedSignature = createHmac('sha256', secret).update(signedFields(manifest)).digest();
        const actualSignature = Buffer.from(manifest.signature.value, 'hex');
        if (actualSignature.length !== expectedSignature.length || !timingSafeEqual(actualSignature, expectedSignature)) issues.push('INTEGRITY_SIGNATURE_INVALID');
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
      if (key.asymmetricKeyType !== 'rsa' || Number(key.asymmetricKeyDetails?.modulusLength || 0) < CLEARANCE_RSA_MIN_BITS) throw new Error('invalid');
    } catch { issues.push('ARIX_CLEARANCE_PRIVATE_JWK_INVALID_OR_MISSING'); }
    try {
      const vercel = JSON.parse(await readFile(join(root, 'vercel.json'), 'utf8'));
      const headerValues = (vercel.headers || []).flatMap((item) => item.headers || []).map((item) => `${item.key}:${item.value}`.toLowerCase());
      if (!headerValues.some((value) => value.startsWith('strict-transport-security:')) || !headerValues.some((value) => value.includes('upgrade-insecure-requests'))) issues.push('HTTPS_SECURITY_HEADERS_MISSING');
    } catch { issues.push('HTTPS_CONFIGURATION_UNVERIFIABLE'); }
  }
  return { ok: issues.length === 0, production, issues, checkedAt: new Date().toISOString(), manifestRoot: manifest?.rootDigest || null };
}

export function verifyRuntimeIntegrity({ refresh = false } = {}) {
  if (refresh || !cachedPromise) cachedPromise = verify().catch((error) => ({ ok: false, production: process.env.NODE_ENV === 'production', issues: [`INTEGRITY_CHECK_FAILED:${String(error?.message || error).slice(0, 120)}`], checkedAt: new Date().toISOString(), manifestRoot: null }));
  return cachedPromise;
}
