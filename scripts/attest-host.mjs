import { inspectLinuxHostHardening } from '../api/_lib/host-attestation.js';

const strict = process.argv.includes('--strict');
const result = await inspectLinuxHostHardening();
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (strict && !result.ok) process.exitCode = 1;
