import { generateKeyPairSync } from 'node:crypto';
import { writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const [privateArg, publicArg] = process.argv.slice(2);
if (!privateArg || !publicArg) {
  process.stderr.write('Usage: node scripts/generate-origin-keys.mjs <private-key.pem> <public-key.pem>\n');
  process.exit(2);
}
const privatePath = resolve(privateArg);
const publicPath = resolve(publicArg);
if (privatePath === publicPath) throw new Error('Private and public key paths must differ');
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
await mkdir(dirname(privatePath), { recursive: true });
await mkdir(dirname(publicPath), { recursive: true });
await writeFile(privatePath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
await writeFile(publicPath, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644, flag: 'wx' });
process.stdout.write('Created Ed25519 origin keypair. Protect the private key and distribute only the public key.\n');
