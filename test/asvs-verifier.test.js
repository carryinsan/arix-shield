import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = path.join(ROOT, 'scripts/asvs-l3-verifier.mjs');

test('ASVS verifier enumerates requirements and leaves unmapped controls unassessed', async () => {
  const temp = await mkdtemp(path.join(tmpdir(), 'arix-asvs-verifier-'));
  try {
    const source = {
      Version: '5.0.0',
      Requirements: [{
        Shortcode: 'V1', Name: 'Encoding and Sanitization', ShortName: 'Encoding', Items: [{
          Shortcode: 'V1.1', Name: 'Canonicalization', Items: [
            { Shortcode: 'V1.1.1', Description: 'Verify canonicalization.', L: '2' },
            { Shortcode: 'V1.1.2', Description: 'Verify output encoding.', L: '3' }
          ]
        }]
      }]
    };
    const evidence = { evidence: {
      '1.1.1': { status: 'PARTIAL', files: ['test/asvs-verifier.test.js'], symbol: 'fixture', test: 'verifier smoke test', note: 'fixture only' }
    } };
    const sourcePath = path.join(temp, 'asvs.json');
    const mapPath = path.join(temp, 'map.json');
    const outPath = path.join(temp, 'out');
    await writeFile(sourcePath, JSON.stringify(source));
    await writeFile(mapPath, JSON.stringify(evidence));
    execFileSync(process.execPath, [SCRIPT, '--asvs-json', sourcePath, '--repo-root', ROOT, '--evidence-map', mapPath, '--out-dir', outPath], { cwd: ROOT, stdio: 'pipe' });
    const report = JSON.parse(await readFile(path.join(outPath, 'ASVS-5.0.0-L3-VERIFICATION-MATRIX.json'), 'utf8'));
    assert.equal(report.requirementCount, 2);
    assert.equal(report.level3LabelledCount, 1);
    assert.equal(report.counts.PARTIAL, 1);
    assert.equal(report.counts.NOT_ASSESSED, 1);
    assert.equal(report.requirements.find((item) => item.id === '1.1.2').status, 'NOT_ASSESSED');
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});
