import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const env = { ...process.env, NODE_ENV: 'production' };
if (typeof env.ARIX_MASTER_SECRET !== 'string' || Buffer.byteLength(env.ARIX_MASTER_SECRET) < 32) {
  process.stderr.write('[build] Refusing a production build: set ARIX_MASTER_SECRET to the same unique 32+ byte secret configured for the deployed runtime.\n');
  process.exit(1);
}

for (const args of [['scripts/check.mjs', '--write-manifest'], ['scripts/check.mjs']]) {
  const result = spawnSync(process.execPath, args, { cwd: root, env, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status || 1);
}
