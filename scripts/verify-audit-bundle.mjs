import { readFile } from 'node:fs/promises';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

const filename = process.argv[2];
if (!filename) { process.stderr.write('Usage: npm run audit:verify -- path/to/evidence.jsonl\n'); process.exit(2); }
const secret = process.env.ARIX_MASTER_SECRET;
if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32) { process.stderr.write('ARIX_MASTER_SECRET >= 32 bytes is required to verify this signed evidence.\n'); process.exit(2); }
const lines = (await readFile(filename, 'utf8')).split(/\r?\n/).filter(Boolean);
if (lines.length !== 2) throw new Error('Evidence must contain exactly two JSONL records.');
const first = JSON.parse(lines[0]); const second = JSON.parse(lines[1]);
if (first.type !== 'ARIX_AUDIT_BUNDLE' || second.type !== 'HMAC_SIGNATURE' || second.algorithm !== 'HMAC-SHA256') throw new Error('Unsupported evidence bundle format.');
const bundle = first.bundle;
const expectedSignature = createHmac('sha256', secret).update(JSON.stringify(bundle)).digest();
const suppliedSignature = Buffer.from(String(second.signature || ''), 'hex');
if (suppliedSignature.length !== expectedSignature.length || !timingSafeEqual(suppliedSignature, expectedSignature)) throw new Error('Evidence bundle signature is invalid.');
const chain = bundle?.auditChain;
if (!chain || !Array.isArray(chain.rows) || chain.verified !== true) throw new Error('Bundle does not contain a server-verified audit chain.');
let previous = null;
for (const row of chain.rows) {
  const expectedDigest = createHash('sha256').update(JSON.stringify({ projectId: bundle.projectId, event: row.event })).digest('hex');
  const expectedMac = createHmac('sha256', secret).update(Buffer.from(row.prevChainMac, 'hex')).update(String(row.seq), 'utf8').update(Buffer.from(row.digest, 'hex')).digest('hex');
  if (row.projectId !== bundle.projectId || row.digest !== expectedDigest || row.chainMac !== expectedMac) throw new Error(`Audit chain cryptographic verification failed at sequence ${row.seq}.`);
  if (previous && (Number(row.seq) !== Number(previous.seq) + 1 || row.prevChainMac !== previous.chainMac)) throw new Error(`Audit chain continuity failed at sequence ${row.seq}.`);
  previous = row;
}
if (chain.rows.length && (Number(previous.seq) !== Number(chain.sequence) || previous.chainMac !== chain.head)) throw new Error('Audit chain head does not match the bundle summary.');
console.log(JSON.stringify({ ok: true, projectId: bundle.projectId, sequence: chain.sequence, verifiedRows: chain.rows.length, windowTruncated: Boolean(chain.windowTruncated), bundleSignedAt: bundle.createdAt }, null, 2));
