import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, relative, extname, posix } from 'node:path';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL, fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const manifestPath = join(root, 'docs', 'INTEGRITY-MANIFEST.json');
const ignored = new Set(['node_modules', '.git', '.vercel', '.next', 'coverage']);
const sourceFiles = [];
const repositoryFiles = [];
async function walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) { if (!ignored.has(entry.name)) await walk(join(directory, entry.name)); }
    else if (entry.isFile()) {
      const file = join(directory, entry.name);
      repositoryFiles.push(file);
      if (['.js', '.mjs', '.html'].includes(extname(entry.name))) sourceFiles.push(file);
    }
  }
}
await walk(root);
const stableSort = (a, b) => { const x = relative(root, a).split('\\').join('/'); const y = relative(root, b).split('\\').join('/'); return x < y ? -1 : x > y ? 1 : 0; };
sourceFiles.sort(stableSort);
repositoryFiles.sort(stableSort);

function lexicalMask(source) {
  // Preserve identifiers/punctuation but blank comments and quoted/template literal contents.
  // This is intentionally a dependency-free lexical gate, not a complete JavaScript AST parser.
  let out = ''; let i = 0; let state = 'code'; let quote = ''; let escaped = false;
  while (i < source.length) {
    const ch = source[i]; const next = source[i + 1];
    if (state === 'line') { if (ch === '\n') { state = 'code'; out += '\n'; } else out += ' '; i++; continue; }
    if (state === 'block') { if (ch === '*' && next === '/') { out += '  '; i += 2; state = 'code'; } else { out += ch === '\n' ? '\n' : ' '; i++; } continue; }
    if (state === 'string') { out += ch === '\n' ? '\n' : ' '; if (escaped) escaped = false; else if (ch === '\\') escaped = true; else if (ch === quote) state = 'code'; i++; continue; }
    if (ch === '/' && next === '/') { out += '  '; i += 2; state = 'line'; continue; }
    if (ch === '/' && next === '*') { out += '  '; i += 2; state = 'block'; continue; }
    if (ch === '"' || ch === "'" || ch === '`') { quote = ch; state = 'string'; out += ' '; i++; continue; }
    out += ch; i++;
  }
  return out;
}
function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function hmac(secret, value) { return createHmac('sha256', secret).update(value).digest('hex'); }

let failed = false;
for (const file of sourceFiles.filter((name) => ['.js', '.mjs'].includes(extname(name)))) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) { failed = true; process.stderr.write(`\n[syntax] ${relative(root, file)}\n${result.stderr || result.stdout}`); }
}
if (failed) process.exit(1);

const serverModules = sourceFiles.filter((file) => /[/\\](?:api|sdk)[/\\]/.test(file) && ['.js', '.mjs'].includes(extname(file)));
for (const file of serverModules) {
  try { await import(pathToFileURL(file).href); }
  catch (error) { failed = true; process.stderr.write(`\n[import] ${relative(root, file)}\n${error?.stack || error}`); }
}
if (failed) process.exit(1);

const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
const dependencySections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
for (const section of dependencySections) {
  if (Object.keys(pkg[section] || {}).length) { failed = true; process.stderr.write(`[supply-chain] package.json ${section} must remain empty; found ${Object.keys(pkg[section]).join(', ')}\n`); }
}

const banned = [
  ['DYNAMIC_EVAL', /\beval\s*\(/],
  ['DYNAMIC_FUNCTION', /\bnew\s+Function\s*\(/],
  ['CHILD_PROCESS_EXEC', /\bchild_process\s*\.\s*exec\s*\(/],
  ['UNSAFE_INNER_HTML', /\.(?:innerHTML|outerHTML)\s*=/]
];
const secretPatterns = [/\bARIX_SECRET_(?:KEY|SERVER_KEY)\s*[:=]\s*["'][^"']{8,}/i, /\bUPSTASH_(?:REDIS_REST_URL|REDIS_REST_TOKEN)\s*[:=]\s*["'][^"']{8,}/i, /\b(?:sk_live_|gh[pousr]_[A-Za-z0-9]{20,})/];
for (const file of sourceFiles) {
  const ext = extname(file); const source = await readFile(file, 'utf8');
  if (file === fileURLToPath(import.meta.url)) continue; // The checker documents its own forbidden-token patterns.
  const code = lexicalMask(source);
  for (const [id, pattern] of banned) if (pattern.test(code)) { failed = true; process.stderr.write(`[sast:${id}] ${relative(root, file)}\n`); }
}

// Scan every repository text file for committed credentials, not only executable sources.
const textExtensions = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.html', '.css', '.json', '.jsonl', '.md', '.txt', '.yml', '.yaml', '.toml', '.ini', '.env', '.example', '.sql', '.sh', '.ps1', '.xml', '.csv']);
for (const file of repositoryFiles) {
  if (file === fileURLToPath(import.meta.url) || file === manifestPath) continue;
  const ext = extname(file);
  if (!textExtensions.has(ext) && !/^\.env(?:\.|$)/.test(file.slice(root.length).replaceAll('\\', '/'))) continue;
  const bytes = await readFile(file);
  if (bytes.length > 5 * 1024 * 1024 || bytes.includes(0)) continue;
  const source = bytes.toString('utf8');
  if (secretPatterns.some((pattern) => pattern.test(source))) {
    failed = true;
    process.stderr.write(`[secret-scan] Potential committed credential in ${relative(root, file)}\n`);
  }
}

const entries = [];
for (const file of sourceFiles) {
  const rel = posix.normalize(relative(root, file).split('\\').join('/'));
  entries.push({ path: rel, sha256: sha256(await readFile(file)) });
}
const rootDigest = sha256(JSON.stringify(entries));
const manifest = { schema: 'arixshield.integrity.v1', algorithm: 'SHA-256', generatedAt: 'deterministic', fileCount: entries.length, rootDigest, files: entries, signature: null };
const secret = process.env.ARIX_MASTER_SECRET;
if (secret && Buffer.byteLength(secret) >= 32) manifest.signature = { algorithm: 'HMAC-SHA256', value: hmac(secret, JSON.stringify({ schema: manifest.schema, algorithm: manifest.algorithm, fileCount: manifest.fileCount, rootDigest, files: entries })) };
const productionBuild = process.env.NODE_ENV === 'production' || process.env.VERCEL_ENV === 'production';
if (process.argv.includes('--write-manifest') && productionBuild && (!secret || Buffer.byteLength(secret) < 32)) {
  failed = true;
  process.stderr.write('[manifest] refusing to write an unsigned production manifest; set ARIX_MASTER_SECRET >= 32 bytes\n');
}
if (failed) process.exit(1);
if (process.argv.includes('--write-manifest')) {
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`[manifest] wrote ${entries.length} files; root ${rootDigest}`);
} else {
  let previous;
  try { previous = JSON.parse(await readFile(manifestPath, 'utf8')); }
  catch { failed = true; process.stderr.write('[manifest] missing or invalid docs/INTEGRITY-MANIFEST.json; run npm run integrity:update\n'); }
  if (previous) {
    const same = previous.schema === manifest.schema && previous.rootDigest === rootDigest && JSON.stringify(previous.files) === JSON.stringify(entries);
    if (!same) { failed = true; process.stderr.write('[manifest] source drift detected; update and review docs/INTEGRITY-MANIFEST.json\n'); }
    if (process.env.NODE_ENV === 'production') {
      if (!secret || Buffer.byteLength(secret) < 32 || previous.signature?.algorithm !== 'HMAC-SHA256' || !/^[a-f0-9]{64}$/.test(previous.signature?.value || '')) { failed = true; process.stderr.write('[manifest] production requires a signed manifest and ARIX_MASTER_SECRET >= 32 bytes\n'); }
      else { const expected = hmac(secret, JSON.stringify({ schema: previous.schema, algorithm: previous.algorithm, fileCount: previous.fileCount, rootDigest: previous.rootDigest, files: previous.files })); const a = Buffer.from(expected, 'hex'); const b = Buffer.from(previous.signature.value, 'hex'); if (a.length !== b.length || !timingSafeEqual(a, b)) { failed = true; process.stderr.write('[manifest] HMAC signature verification failed\n'); } }
    }
    if (secret && Buffer.byteLength(secret) >= 32 && previous.signature?.value) {
      const expected = hmac(secret, JSON.stringify({ schema: previous.schema, algorithm: previous.algorithm, fileCount: previous.fileCount, rootDigest: previous.rootDigest, files: previous.files }));
      const actual = Buffer.from(previous.signature.value, 'hex'); const wanted = Buffer.from(expected, 'hex');
      if (actual.length !== wanted.length || !timingSafeEqual(actual, wanted)) { failed = true; process.stderr.write('[manifest] signed manifest does not match configured ARIX_MASTER_SECRET\n'); }
    }
  }
}
if (failed) process.exit(1);
console.log(`Syntax checks passed for ${sourceFiles.filter((file) => ['.js', '.mjs'].includes(extname(file))).length} JS modules; imported ${serverModules.length}; zero third-party dependencies; static scanner passed; manifest ${process.argv.includes('--write-manifest') ? 'written' : 'verified'} (${entries.length} files, ${rootDigest.slice(0, 16)}…).`);
