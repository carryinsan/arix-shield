import { spawnSync } from 'node:child_process';
import { readdir, readFile } from 'node:fs/promises';
import { createPrivateKey } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { normalizeRedisRestUrl } from '../api/_lib/redis.js';
import { CLEARANCE_RSA_MIN_BITS } from '../api/_lib/security-constants.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const env = { ...process.env, NODE_ENV: 'production' };

function requireSecret(name, minimumBytes = 32) {
  const value = env[name];
  if (typeof value !== 'string' || Buffer.byteLength(value) < minimumBytes || /[\u0000-\u0020\u007f]/.test(value)) {
    throw new Error(`${name} must be configured with at least ${minimumBytes} bytes and no control characters.`);
  }
  return value;
}

function productionPreflight() {
  if (process.versions.node.split('.')[0] !== '22') throw new Error('Production build requires the Node.js 22 runtime specified by package.json.');
  const masterSecret = requireSecret('ARIX_MASTER_SECRET');
  const cronSecret = requireSecret('CRON_SECRET');
  if (masterSecret === cronSecret) throw new Error('ARIX_MASTER_SECRET and CRON_SECRET must be independent secrets.');
  if (!normalizeRedisRestUrl(env.UPSTASH_REDIS_REST_URL)) throw new Error('UPSTASH_REDIS_REST_URL must be a credential-free HTTPS REST root URL without query, fragment, or custom port.');
  const redisToken = env.UPSTASH_REDIS_REST_TOKEN;
  if (typeof redisToken !== 'string' || !redisToken || redisToken.length > 8192 || /[\u0000-\u0020\u007f]/.test(redisToken)) throw new Error('UPSTASH_REDIS_REST_TOKEN is missing or malformed.');
  const kid = env.ARIX_CLEARANCE_KID;
  if (typeof kid !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(kid)) throw new Error('ARIX_CLEARANCE_KID is missing or malformed.');
  let jwk;
  try {
    const raw = env.ARIX_CLEARANCE_PRIVATE_JWK;
    if (typeof raw !== 'string' || raw.length > 16000) throw new Error('missing');
    jwk = JSON.parse(raw);
    if (jwk?.kty !== 'RSA' || !jwk.n || !jwk.e || !jwk.d || (jwk.kid && jwk.kid !== kid)) throw new Error('invalid JWK');
    const key = createPrivateKey({ key: jwk, format: 'jwk' });
    if (key.asymmetricKeyType !== 'rsa' || Number(key.asymmetricKeyDetails?.modulusLength || 0) < CLEARANCE_RSA_MIN_BITS) throw new Error('RSA key is below the configured minimum');
  } catch {
    throw new Error(`ARIX_CLEARANCE_PRIVATE_JWK must be a valid RSA private JWK of at least ${CLEARANCE_RSA_MIN_BITS} bits with the configured KID.`);
  }
}

function run(args, label, childEnv = env) {
  process.stdout.write(`[build] ${label}\n`);
  const result = spawnSync(process.execPath, args, { cwd: root, env: childEnv, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status || 1);
}

try {
  productionPreflight();
} catch (error) {
  process.stderr.write(`[build] Refusing production build: ${String(error?.message || error)}\n`);
  process.exit(1);
}

// Sign the source manifest with the already configured production master secret,
// then verify the signed result before running the deterministic regression suite.
run(['scripts/check.mjs', '--write-manifest'], 'compile and sign source integrity manifest');
run(['scripts/check.mjs'], 'verify static security gates and manifest signature');

const testDirectory = join(root, 'test');
const tests = (await readdir(testDirectory, { withFileTypes: true }))
  .filter((entry) => entry.isFile() && entry.name.endsWith('.test.js'))
  .map((entry) => join('test', entry.name))
  .sort();
if (!tests.length) {
  process.stderr.write('[build] Refusing production build: no deterministic test files were found.\n');
  process.exit(1);
}
const testEnv = { ...env, NODE_ENV: 'test' };
// Never let the build's production Redis credentials leak into local tests:
// an accidental test-side write must not touch a real shared security store.
delete testEnv.UPSTASH_REDIS_REST_URL;
delete testEnv.UPSTASH_REDIS_REST_TOKEN;
delete testEnv.VERCEL_ENV;
run(['--test', '--test-concurrency=1', ...tests], `run ${tests.length} deterministic security test files serially (isolated in-memory state)`, testEnv);
process.stdout.write('[build] Production source/configuration gates and local regression suite passed. Live infrastructure and independent compliance assessment remain separate release gates.\n');
