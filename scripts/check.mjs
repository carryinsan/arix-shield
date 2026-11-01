import { readdir } from 'node:fs/promises';
import { join, extname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const root = new URL('../', import.meta.url).pathname;
const ignored = new Set(['node_modules', '.git', '.vercel']);
const files = [];
async function walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!ignored.has(entry.name)) await walk(join(directory, entry.name));
    } else if (['.js', '.mjs'].includes(extname(entry.name))) files.push(join(directory, entry.name));
  }
}
await walk(root);
let failed = false;
for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) {
    failed = true;
    process.stderr.write(`\n[syntax] ${file}\n${result.stderr || result.stdout}`);
  }
}
if (failed) process.exit(1);

// Import server-side modules as well: syntax-only checks do not catch missing named exports.
const serverModules = files.filter((file) => file.includes(`${join('', 'api')}/`) || file.includes(`${join('', 'sdk')}/`));
for (const file of serverModules) {
  try { await import(pathToFileURL(file).href); }
  catch (error) {
    failed = true;
    process.stderr.write(`\n[import] ${file}\n${error?.stack || error}`);
  }
}
if (failed) process.exit(1);
console.log(`Syntax checks passed for ${files.length} JavaScript files; imported ${serverModules.length} server modules successfully.`);
