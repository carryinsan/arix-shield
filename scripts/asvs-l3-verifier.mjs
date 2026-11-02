#!/usr/bin/env node
/**
 * Creates a full ASVS 5.0.0 requirement ledger from OWASP's official JSON.
 * Evidence is never inferred from filenames: only explicit evidence-map entries
 * are attached. Missing evidence stays NOT_ASSESSED.
 */
import { readFile, writeFile, mkdir, access } from 'node:fs/promises';
import path from 'node:path';

function arg(name, fallback = null) {
  const at = process.argv.indexOf(name);
  return at < 0 ? fallback : process.argv[at + 1] ?? fallback;
}
function gather(items, chapter, section = null, out = []) {
  for (const item of items || []) {
    if (!item || typeof item !== 'object') continue;
    const code = String(item.Shortcode || '');
    const isRequirement = /^V\d+\.\d+\.\d+$/.test(code) && item.Description;
    if (isRequirement) out.push({ id: code.slice(1), chapter, section, level: String(item.L || ''), description: String(item.Description) });
    else if (Array.isArray(item.Items)) gather(item.Items, code.startsWith('V') && /^V\d+$/.test(code) ? code : chapter, code, out);
  }
  return out;
}
async function fileExists(root, file) {
  if (!file) return false;
  try { await access(path.resolve(root, file)); return true; } catch { return false; }
}

const asvsPath = arg('--asvs-json');
if (!asvsPath) {
  console.error('Usage: node scripts/asvs-l3-verifier.mjs --asvs-json /path/to/official-ASVS-5.0.0.json [--repo-root /path/to/ArixShield] [--out-dir results]');
  process.exit(2);
}
const repoRoot = path.resolve(arg('--repo-root', path.resolve('.')));
const outDir = path.resolve(arg('--out-dir', 'results'));
const asvs = JSON.parse(await readFile(path.resolve(asvsPath), 'utf8'));
if (String(asvs.Version) !== '5.0.0' || !Array.isArray(asvs.Requirements)) throw new Error('Expected the official OWASP ASVS 5.0.0 JSON structure.');
const mapPath = arg('--evidence-map', 'docs/asvs-evidence-map.json');
const evidenceMap = JSON.parse(await readFile(path.resolve(mapPath), 'utf8'));
const requirements = gather(asvs.Requirements, '');
const rows = [];
for (const req of requirements) {
  const evidence = evidenceMap.evidence?.[req.id] || null;
  const files = evidence?.files || [];
  const existing = [];
  for (const f of files) if (await fileExists(repoRoot, f)) existing.push(f);
  const status = !evidence ? 'NOT_ASSESSED' : (files.length && existing.length === 0 ? 'EVIDENCE_FILE_MISSING' : evidence.status || 'NOT_ASSESSED');
  rows.push({ ...req, status, evidence: evidence ? { ...evidence, existingFiles: existing } : null });
}
const chapters = asvs.Requirements.map((chapter) => ({ id: chapter.Shortcode, name: chapter.Name, shortName: chapter.ShortName }));
const counts = rows.reduce((acc, row) => { acc[row.status] = (acc[row.status] || 0) + 1; return acc; }, {});
const l3Rows = rows.filter((r) => r.level === '3');
const chapterRows = chapters.map((chapter) => {
  const selected = rows.filter((row) => row.chapter === chapter.id);
  return { ...chapter, total: selected.length, l3: selected.filter((r) => r.level === '3').length, notAssessed: selected.filter((r) => r.status === 'NOT_ASSESSED').length, evidenceRows: selected.filter((r) => r.evidence).length };
});
let md = `# OWASP ASVS 5.0.0 — Level 3 evidence ledger\n\n`;
md += `**Assessment mode:** repository test evidence ledger, not certification.\n\n`;
md += `- Source version: ${asvs.Version}\n- Requirements enumerated: ${rows.length}\n- Level 3-labelled requirements: ${l3Rows.length}\n- Evidence map entries attached: ${rows.filter((r) => r.evidence).length}\n- Status counts: ${Object.entries(counts).map(([k,v]) => `${k}=${v}`).join(', ')}\n\n`;
md += `The ASVS Level 3 assessment evaluates all applicable requirements across the standard, not just requirements labelled Level 3. Any requirement without reviewed evidence remains **NOT ASSESSED**. A passing unit test is supporting evidence, not proof of deployed control effectiveness.\n\n`;
md += `## Chapter coverage\n\n| Chapter | Topic | Requirements | L3-labelled | Evidence mapped | Not assessed |\n|---|---|---:|---:|---:|---:|\n`;
for (const c of chapterRows) md += `| ${c.id} | ${c.name} | ${c.total} | ${c.l3} | ${c.evidenceRows} | ${c.notAssessed} |\n`;
md += `\n## Requirement-by-requirement ledger\n\n`;
for (const chapter of chapters) {
  md += `### ${chapter.id} — ${chapter.name}\n\n`;
  md += `| Requirement | Level | Status | Requirement statement | Evidence (file / symbol / test) |\n|---|---:|---|---|---|\n`;
  for (const row of rows.filter((r) => r.chapter === chapter.id)) {
    const desc = row.description.replaceAll('|', '\\|').replace(/\s+/g, ' ').trim();
    const ev = row.evidence ? `${row.evidence.existingFiles.join(', ') || 'MISSING FILE'}; ${row.evidence.symbol || ''}; ${row.evidence.test || ''}; ${row.evidence.note || ''}`.replaceAll('|', '\\|') : 'No mapped evidence';
    md += `| v5.0.0-${row.id} | ${row.level || '—'} | **${row.status}** | ${desc} | ${ev} |\n`;
  }
  md += `\n`;
}
md += `## Evidence interpretation\n\n- **PARTIAL** means a local helper or test covers only part of the requirement. It must not be represented as satisfied.\n- **NOT_ASSESSED** means no defensible evidence is mapped.\n- **EVIDENCE_FILE_MISSING** means the map points to files unavailable in the selected repository checkout.\n- **TESTED** is intentionally not auto-assigned; a test result alone is not a control assessment.\n\nGenerated by \`scripts/asvs-l3-verifier.mjs\`. Standard source: OWASP ASVS 5.0.0.\n`;
await mkdir(outDir, { recursive: true });
await writeFile(path.join(outDir, 'ASVS-5.0.0-L3-VERIFICATION-MATRIX.md'), md);
await writeFile(path.join(outDir, 'ASVS-5.0.0-L3-VERIFICATION-MATRIX.json'), `${JSON.stringify({ version: asvs.Version, requirementCount: rows.length, level3LabelledCount: l3Rows.length, counts, chapters: chapterRows, requirements: rows }, null, 2)}\n`);
console.log(JSON.stringify({ version: asvs.Version, requirementCount: rows.length, level3LabelledCount: l3Rows.length, counts, output: outDir }, null, 2));
