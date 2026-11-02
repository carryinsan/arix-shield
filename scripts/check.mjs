import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, relative, extname, posix } from 'node:path';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { PASSWORD_KDF, LEGACY_PBKDF2_ITERATIONS, CLEARANCE_RSA_MIN_BITS, HIBP_LOOKUP_TIMEOUT_MS } from '../api/_lib/security-constants.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const manifestPath = join(root, 'docs', 'INTEGRITY-MANIFEST.json');
const runtimeManifestPath = join(root, 'api', '_integrity-manifest.json');
const buildReportPath = join(root, 'BUILD-REPORT.md');
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
try {
  const vercel = JSON.parse(await readFile(join(root, 'vercel.json'), 'utf8'));
  const apiFunction = vercel.functions?.['api/**/*.js'];
  if (apiFunction?.includeFiles !== 'api/**/*') {
    failed = true;
    process.stderr.write('[deployment] Vercel API functions must include the complete api/**/* tree, including its runtime integrity manifest.\n');
  }
} catch {
  failed = true;
  process.stderr.write('[deployment] vercel.json is missing or invalid.\n');
}
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
const directDatabaseClientConstructors = [
  ['PRISMA_CLIENT', /\bnew\s+PrismaClient\s*\(/],
  ['PG_POOL', /\bnew\s+pg\s*\.\s*Pool\s*\(/],
  ['MYSQL_CREATE_POOL', /\bmysql\s*\.\s*createPool\s*\(/],
  ['MONGO_CLIENT_CONNECT', /\bMongoClient\s*\.\s*connect\s*\(/]
];
for (const file of sourceFiles) {
  const ext = extname(file); const source = await readFile(file, 'utf8');
  if (file === fileURLToPath(import.meta.url)) continue; // The checker documents its own forbidden-token patterns.
  const code = lexicalMask(source);
  for (const [id, pattern] of banned) if (pattern.test(code)) { failed = true; process.stderr.write(`[sast:${id}] ${relative(root, file)}\n`); }
  if (/[/\\](?:api|sdk)[/\\]/.test(file)) {
    for (const [id, pattern] of directDatabaseClientConstructors) if (pattern.test(code)) {
      failed = true;
      process.stderr.write(`[database-client-gate:${id}] ${relative(root, file)}: direct driver construction is not accepted; route database creation through a reviewed tenant-scope adapter. This lexical gate is a tripwire, not a full AST/data-flow proof.\n`);
    }
  }
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
const generatedMarkers = {
  count: `<!-- ARIX-MANIFEST-FILE-COUNT:${entries.length} -->`,
  root: `<!-- ARIX-MANIFEST-ROOT:${rootDigest} -->`,
  constants: `<!-- ARIX-SECURITY-CONSTANTS:RSA_MIN_BITS=${CLEARANCE_RSA_MIN_BITS};SCRYPT_N=${PASSWORD_KDF.N};SCRYPT_R=${PASSWORD_KDF.r};SCRYPT_P=${PASSWORD_KDF.p};LEGACY_PBKDF2_ITERATIONS=${LEGACY_PBKDF2_ITERATIONS};HIBP_LOOKUP_TIMEOUT_MS=${HIBP_LOOKUP_TIMEOUT_MS} -->`
};
let buildReport = await readFile(buildReportPath, 'utf8');
const operationsDoc = await readFile(join(root, 'docs', 'OPERATIONS.md'), 'utf8');
const upgradesDoc = await readFile(join(root, 'docs', 'SECURITY-UPGRADES-6-10.md'), 'utf8');
const documentedKdf = new RegExp(`N=${PASSWORD_KDF.N}\\s*,\\s*r=${PASSWORD_KDF.r}\\s*,\\s*p=${PASSWORD_KDF.p}`);
const documentedMaxmem = `${Math.ceil(PASSWORD_KDF.maxmem / (1024 * 1024))} MiB maxmem`;
for (const [name, ok] of [
  ['scrypt parameters', documentedKdf.test(operationsDoc)],
  ['scrypt max memory', operationsDoc.includes(documentedMaxmem)],
  ['HIBP timeout', operationsDoc.includes(`${HIBP_LOOKUP_TIMEOUT_MS} ms timeout`)],
  ['clearance RSA minimum in operations guide', operationsDoc.includes(`RSA-${CLEARANCE_RSA_MIN_BITS}`)],
  ['clearance RSA minimum in security-upgrade guide', upgradesDoc.includes(`RSA private JWK of at least ${CLEARANCE_RSA_MIN_BITS} bits`)]
]) if (!ok) {
  failed = true;
  process.stderr.write(`[docs] ${name} diverges from api/_lib/security-constants.js\n`);
}

const markerPatterns = {
  count: /<!-- ARIX-MANIFEST-FILE-COUNT:\d+ -->/,
  root: /<!-- ARIX-MANIFEST-ROOT:[a-f0-9]{64} -->/,
  constants: /<!-- ARIX-SECURITY-CONSTANTS:[^>]+ -->/
};
for (const key of Object.keys(generatedMarkers)) {
  if (!markerPatterns[key].test(buildReport)) {
    failed = true;
    process.stderr.write(`[docs] BUILD-REPORT.md is missing generated ${key} metadata marker\n`);
  } else if (process.argv.includes('--write-manifest')) {
    buildReport = buildReport.replace(markerPatterns[key], generatedMarkers[key]);
  } else if (buildReport.match(markerPatterns[key])?.[0] !== generatedMarkers[key]) {
    failed = true;
    process.stderr.write(`[docs] BUILD-REPORT.md ${key} metadata drift; run npm run integrity:update and review the generated report values\n`);
  }
}

if (process.argv.includes('--write-manifest') && productionBuild && (!secret || Buffer.byteLength(secret) < 32)) {
  failed = true;
  process.stderr.write('[manifest] refusing to write an unsigned production manifest; set ARIX_MASTER_SECRET >= 32 bytes\n');
}
if (failed) process.exit(1);
if (process.argv.includes('--write-manifest')) {
  const serializedManifest = `${JSON.stringify(manifest, null, 2)}\n`;
  await writeFile(manifestPath, serializedManifest);
  await writeFile(runtimeManifestPath, serializedManifest);
  await writeFile(buildReportPath, buildReport);
  console.log(`[manifest] wrote ${entries.length} files; root ${rootDigest}`);
} else {
  let previous;
  try { previous = JSON.parse(await readFile(manifestPath, 'utf8')); }
  catch { failed = true; process.stderr.write('[manifest] missing or invalid docs/INTEGRITY-MANIFEST.json; run npm run integrity:update\n'); }
  try {
    const runtimeManifest = JSON.parse(await readFile(runtimeManifestPath, 'utf8'));
    if (JSON.stringify(runtimeManifest) !== JSON.stringify(previous)) {
      failed = true;
      process.stderr.write('[manifest] API-bundled runtime manifest diverges from docs/INTEGRITY-MANIFEST.json; run npm run integrity:update\n');
    }
  } catch {
    failed = true;
    process.stderr.write('[manifest] missing or invalid api/_integrity-manifest.json; run npm run integrity:update\n');
  }
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
