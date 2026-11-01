import { createHash } from 'node:crypto';
import { listPopBatch, listPushTrim, setAdd, setJson, setString } from './redis.js';

function hash(value) { return createHash('sha256').update(value).digest('hex'); }

export function merkleRoot(hashes) {
  let level = hashes.filter((value) => /^[a-f0-9]{64}$/i.test(String(value))).map((value) => Buffer.from(value, 'hex'));
  if (!level.length) return hash('ARIXSHIELD_EMPTY_MERKLE_TREE_V1');
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = level[index + 1] || left;
      next.push(createHash('sha256').update(Buffer.concat([left, right])).digest());
    }
    level = next;
  }
  return level[0].toString('hex');
}

export async function appendAuditEvent(projectId, event) {
  const canonical = JSON.stringify({ projectId, event });
  const digest = hash(canonical);
  await listPushTrim(`arix:audit:pending:${projectId}`, { hash: digest, timestamp: Date.now(), type: String(event.type || 'SECURITY_EVENT').slice(0, 64) }, 10000);
  await setAdd('arix:audit:projects', projectId);
  return digest;
}

async function commitAnchor(root, metadata) {
  const { ARIX_AUDIT_GITHUB_TOKEN: token, ARIX_AUDIT_GITHUB_OWNER: owner, ARIX_AUDIT_GITHUB_REPO: repo } = process.env;
  if (!token || !owner || !repo) return { anchored: false, reason: 'GITHUB_AUDIT_ANCHOR_NOT_CONFIGURED' };
  const basePath = String(process.env.ARIX_AUDIT_GITHUB_PATH || 'arixshield/audit-roots').replace(/^\/+|\/+$/g, '');
  const day = new Date().toISOString().slice(0, 10);
  const path = `${basePath}/${day}.jsonl`;
  if (path.split('/').some((part) => part === '..')) throw new Error('Invalid audit anchor path.');
  const branch = process.env.ARIX_AUDIT_GITHUB_BRANCH || 'main';
  const url = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${path.split('/').map(encodeURIComponent).join('/')}`;
  const headers = { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'ArixShield-Audit-Anchoring' };
  const current = await fetch(`${url}?ref=${encodeURIComponent(branch)}`, { headers, signal: AbortSignal.timeout(7000) });
  let sha;
  let previousContent = '';
  if (current.ok) {
    const file = await current.json();
    sha = file.sha;
    previousContent = Buffer.from(String(file.content || '').replace(/\n/g, ''), 'base64').toString('utf8');
  } else if (current.status !== 404) throw new Error(`GitHub audit read failed (${current.status}).`);
  const line = JSON.stringify({ ...metadata, root, committedAt: new Date().toISOString() });
  const content = Buffer.from(`${previousContent}${line}\n`).toString('base64');
  const put = await fetch(url, {
    method: 'PUT', headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: `ArixShield audit root ${root.slice(0, 12)}`, content, branch, ...(sha ? { sha } : {}) }),
    signal: AbortSignal.timeout(10000)
  });
  if (!put.ok) throw new Error(`GitHub audit commit failed (${put.status}): ${(await put.text()).slice(0, 180)}`);
  const result = await put.json();
  return { anchored: true, url: result?.content?.html_url ?? null, commit: result?.commit?.sha ?? null };
}

export async function anchorPendingAuditEvents(projectId) {
  const values = await listPopBatch(`arix:audit:pending:${projectId}`, 1000);
  const rows = values.flatMap((value) => {
    try { const parsed = typeof value === 'string' ? JSON.parse(value) : value; return parsed?.hash ? [parsed] : []; }
    catch { return []; }
  });
  if (!rows.length) return { projectId, events: 0, anchored: false, reason: 'NO_PENDING_EVENTS' };
  const root = merkleRoot(rows.map((row) => row.hash));
  const metadata = { projectId, leafCount: rows.length, firstEventAt: Math.min(...rows.map((r) => Number(r.timestamp) || Date.now())), lastEventAt: Math.max(...rows.map((r) => Number(r.timestamp) || Date.now())) };
  try {
    const anchor = await commitAnchor(root, metadata);
    if (!anchor.anchored) {
      for (const row of [...rows].reverse()) await listPushTrim(`arix:audit:pending:${projectId}`, row, 10000);
      return { ...metadata, root, ...anchor, queued: true };
    }
    await setJson(`arix:audit:anchor:${projectId}:${Date.now()}`, { ...metadata, root, anchor }, 60 * 60 * 24 * 365);
    await setString(`arix:audit:latest:${projectId}`, JSON.stringify({ ...metadata, root, anchor }), 60 * 60 * 24 * 365);
    return { ...metadata, root, ...anchor };
  } catch (error) {
    for (const row of [...rows].reverse()) await listPushTrim(`arix:audit:pending:${projectId}`, row, 10000);
    throw error;
  }
}
