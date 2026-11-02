import { readFile, writeFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compileXorFilter } from '../api/_lib/breach-filter.js';

const [inputArg, outputArg] = process.argv.slice(2);
if (!inputArg || !outputArg) {
  process.stderr.write('Usage: node scripts/compile-breach-filter.mjs <wordlist.txt> <output.json>\n');
  process.exit(2);
}
const input = resolve(inputArg);
const output = resolve(outputArg);
const metadata = await stat(input);
if (!metadata.isFile() || metadata.size > 128 * 1024 * 1024) throw new RangeError('Input word list must be a regular file no larger than 128 MiB');
const text = await readFile(input, 'utf8');
const words = text.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
const filter = compileXorFilter(words);
await writeFile(output, `${JSON.stringify(filter)}\n`, { mode: 0o600 });
process.stdout.write(`Compiled ${filter.count} unique normalized entries to ${output}\n`);
