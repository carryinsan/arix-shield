import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const app = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
const dashboard = await readFile(new URL('../public/dashboard.html', import.meta.url), 'utf8');

test('dashboard binds every threat-feed and audit-witness element before use', () => {
  const bindings = [
    ['feedWarning', 'threat-feed-warning'],
    ['witnessStatus', 'audit-witness-status'],
    ['auditDownload', 'download-audit-bundle'],
  ];

  for (const [variable, id] of bindings) {
    assert.match(dashboard, new RegExp(`id=[\"']${id}[\"']`), `dashboard must contain #${id}`);
    const declaration = new RegExp(`\\bconst\\s+${variable}\\s*=\\s*\\$\\(\\s*['\"]#${id}['\"]\\s*\\)`);
    assert.match(app, declaration, `${variable} must be explicitly bound to #${id}`);
  }
});
