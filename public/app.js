(() => {
  'use strict';

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const jsonFetch = async (url, options = {}) => {
    const response = await fetch(url, {
      credentials: 'same-origin',
      ...options,
      headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) }
    });
    let data;
    try { data = await response.json(); } catch { data = {}; }
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
    return data;
  };
  const showNotice = (node, message, type = 'success') => {
    if (!node) return;
    node.textContent = message;
    node.className = `notice show ${type}`;
  };
  const hideNotice = (node) => { if (node) node.className = 'notice'; };
  const copyText = async (value) => {
    if (navigator.clipboard?.writeText) return navigator.clipboard.writeText(value);
    const input = document.createElement('textarea');
    input.value = value;
    input.setAttribute('readonly', '');
    input.className = 'clipboard-helper';
    document.body.append(input);
    input.select();
    const copied = document.execCommand('copy');
    input.remove();
    if (!copied) throw new Error('Clipboard access was denied.');
  };


  async function initDeveloper() {
    const form = $('#auth-form');
    if (!form) return;
    const tabs = $$('[data-auth-mode]');
    const nameField = $('#full-name');
    const projectField = $('#project-name');
    const originField = $('#origin');
    const passField = $('#password');
    const submit = $('#auth-submit');
    const notice = $('#auth-notice');
    const keysPanel = $('#keys-panel');
    let authMode = 'signup';
    let activeKeys = { liveKey: '', serverKey: '', canaryKey: '' };

    const updateSnippet = () => {
      const target = $('#snippet-code');
      const type = $('#snippet-type')?.value || 'html';
      const base = location.origin;
      const live = activeKeys.liveKey || 'ARIX_LIVE_PROJECT_IDENTIFIER';
      const secret = activeKeys.serverKey || 'ARIX_SECRET_SERVER_ONLY';
      const snippets = {
        html: `<script src="${base}/arix-client.js" data-arix-key="${live}" defer><\/script>`,
        node: `import express from 'express';\nimport { createArixShield } from './sdk/node.js';\n\nconst app = express();\napp.use(express.json({ limit: '32kb' }));\napp.use(createArixShield({\n  serverKey: process.env.ARIX_SECRET_KEY,\n  endpoint: '${base}',\n  mode: 'ENFORCE',\n  rateLimitPerMinute: 120,\n  globalRateLimit: true\n}));\n\n// Define your API routes after the ArixShield middleware.`,
        next: `import { protectRequest } from './sdk/next.js';\n\nexport async function POST(request) {\n  const decision = await protectRequest(request, {\n    endpoint: '${base}',\n    serverKey: process.env.ARIX_SECRET_KEY,\n    mode: 'ENFORCE',\n    rateLimitPerMinute: 120,\n    globalRateLimit: true,\n    userId: 'authenticated-user-id'\n  });\n  if (!decision.allowed) return decision.response;\n\n  // Still perform application authorization and schema validation here.\n  return Response.json({ ok: true, riskScore: decision.riskScore });\n}`,
        python: `import json
import os
import threading
import urllib.request
from flask import Flask, request

ARIX_ENDPOINT = '${base}'
ARIX_SECRET_KEY = os.environ['ARIX_SECRET_KEY']  # server environment only
app = Flask(__name__)

def _send_arix_event(payload):
    body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        ARIX_ENDPOINT + '/api/shield', body=body, method='POST',
        headers={'Content-Type': 'application/json', 'X-Arix-Server-Key': ARIX_SECRET_KEY}
    )
    try:
        with urllib.request.urlopen(req, timeout=2.5) as response:
            response.read(1024)
    except Exception:
        app.logger.exception('ArixShield telemetry delivery failed')

@app.after_request
def arix_telemetry(response):
    payload = {
        'action': 'server-event', 'type': 'FLASK_REQUEST',
        'path': request.path[:180], 'method': request.method,
        'blocked': response.status_code >= 400,
    }
    threading.Thread(target=_send_arix_event, args=(payload,), daemon=True).start()
    return response

# FastAPI alternative (use this instead of the Flask imports/app above):
# from fastapi import FastAPI, Request
# import asyncio
# fastapi_app = FastAPI()
# @fastapi_app.middleware('http')
# async def arix_fastapi_telemetry(request: Request, call_next):
#     response = await call_next(request)
#     event = {'action': 'server-event', 'type': 'FASTAPI_REQUEST', 'path': request.url.path[:180], 'method': request.method, 'blocked': response.status_code >= 400}
#     asyncio.create_task(asyncio.to_thread(_send_arix_event, event))
#     return response
# Telemetry only; this snippet is not a Python WAF SDK.`,
        curl: `curl -X POST '${base}/api/shield' \\\n  -H 'Content-Type: application/json' \\\n  -H 'X-Arix-Server-Key: ${secret}' \\\n  -d '{"action":"server-event","type":"DEPLOYMENT_CHECK","path":"/api/health","method":"GET","blocked":false}'`
      };
      if (target) target.textContent = snippets[type];
    };

    const changeMode = (mode) => {
      authMode = mode;
      tabs.forEach((tab) => tab.classList.toggle('active', tab.dataset.authMode === mode));
      $$('.signup-field').forEach((element) => element.classList.toggle('hidden', mode !== 'signup'));
      [nameField, projectField, originField].forEach((field) => { if (field) field.required = mode === 'signup'; });
      if (passField) passField.autocomplete = mode === 'signup' ? 'new-password' : 'current-password';
      submit.textContent = mode === 'signup' ? 'Create account & project' : 'Sign in';
      hideNotice(notice);
    };
    tabs.forEach((tab) => tab.addEventListener('click', () => changeMode(tab.dataset.authMode)));

    try {
      const session = await jsonFetch('/api/auth');
      if (session.authenticated) {
        location.replace('/dashboard');
        return;
      }
    } catch { /* The form remains available; a submit will show the actionable error. */ }

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      hideNotice(notice);
      submit.disabled = true;
      submit.textContent = authMode === 'signup' ? 'Creating secure project…' : 'Signing in…';
      const data = Object.fromEntries(new FormData(form).entries());
      data.action = authMode;
      try {
        const result = await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify(data) });
        if (authMode === 'login') {
          showNotice(notice, `Welcome back, ${result.user.name}. Opening your dashboard…`, 'success');
          location.href = '/dashboard';
          return;
        }
        activeKeys = result.keys;
        $('#live-key').textContent = result.keys.liveKey;
        $('#server-key').textContent = result.keys.serverKey;
        $('#canary-key').textContent = result.keys.canaryKey;
        keysPanel.classList.add('show');
        changeMode('login');
        form.classList.add('hidden');
        updateSnippet();
        showNotice(notice, 'Account and project created successfully.', 'success');
      } catch (error) {
        showNotice(notice, error.message, 'error');
      } finally {
        submit.disabled = false;
        if (authMode === 'login') submit.textContent = 'Sign in';
      }
    });

    $('#snippet-type')?.addEventListener('change', updateSnippet);
    $('#copy-snippet')?.addEventListener('click', async () => {
      try { await copyText($('#snippet-code').textContent); showNotice(notice, 'Snippet copied.', 'success'); }
      catch (error) { showNotice(notice, error.message, 'error'); }
    });
    $$('[data-copy-target]').forEach((button) => button.addEventListener('click', async () => {
      try { await copyText($(`#${button.dataset.copyTarget}`).textContent); button.textContent = 'Copied'; }
      catch (error) { showNotice(notice, error.message, 'error'); }
    }));
    updateSnippet();
  }

  async function initDashboard() {
    if (!$('#visitor-table')) return;
    const status = $('#connection-status');
    const showDashError = (message) => {
      status.textContent = 'DISCONNECTED';
      status.classList.add('is-danger');
      status.classList.remove('is-good');
      $('#project-origin').textContent = message;
    };
    try {
      const account = await jsonFetch('/api/auth');
      if (!account.authenticated) { location.href = '/developer'; return; }
      $('#dash-user').textContent = account.user.email;
      const poll = async () => {
        const data = await jsonFetch('/api/telemetry');
        $('#project-title').textContent = data.project.name;
        $('#project-origin').textContent = `${data.project.origin} · ${data.project.id}`;
        status.textContent = 'LIVE · 1.5S POLL';
        status.classList.add('is-good');
        status.classList.remove('is-danger');
        $('#metric-requests').textContent = Number(data.metrics.totalRequests || 0).toLocaleString();
        $('#metric-blocked').textContent = Number(data.metrics.blockedAttacks || 0).toLocaleString();
        $('#metric-trapped').textContent = Number(data.metrics.trappedHackers || 0).toLocaleString();
        $('#metric-visitors').textContent = Number(data.metrics.activeVisitors || 0).toLocaleString();
        $('#visitor-count').textContent = `${data.metrics.activeVisitors || 0} active`;
        renderVisitors(data.visitors || []);
        renderThreats(data.threats || []);
        syncPolicy(data.policy || {});
      };
      await poll();
      window.setInterval(() => poll().catch((error) => showDashError(error.message)), 1500);
    } catch (error) {
      showDashError(error.message);
      if (/sign in/i.test(error.message)) location.href = '/developer';
    }

    function renderVisitors(rows) {
      const body = $('#visitor-table');
      body.replaceChildren();
      if (!rows.length) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 4;
        td.className = 'empty';
        td.textContent = 'No visitor events yet. Add the browser script to your configured site origin.';
        tr.append(td); body.append(tr); return;
      }
      rows.forEach((row) => {
        const tr = document.createElement('tr');
        const values = [
          `${row.visitorId || '—'} · ${row.ip || 'unavailable'}`,
          `${row.country || '—'} · AS${row.asn || '—'}`,
          row.path || '/',
          row.dpopVerified ? 'Verified' : '—'
        ];
        values.forEach((value, i) => {
          const td = document.createElement('td');
          td.textContent = value;
          if (i === 3 && row.dpopVerified) { const tag = document.createElement('span'); tag.className = 'status-tag'; tag.textContent = 'DPoP'; td.replaceChildren(tag); }
          tr.append(td);
        });
        body.append(tr);
      });
    }

    function renderThreats(rows) {
      const terminal = $('#threat-terminal');
      terminal.replaceChildren();
      if (!rows.length) { terminal.textContent = 'No threats recorded for this project.'; return; }
      rows.slice(0, 18).forEach((row) => {
        const line = document.createElement('div');
        const time = row.timestamp ? new Date(row.timestamp).toLocaleTimeString() : '--:--:--';
        const label = row.type || 'SECURITY_EVENT';
        const detail = row.reason || (Array.isArray(row.findings) ? row.findings.map((item) => item.category).join(', ') : row.path || 'Event recorded');
        line.textContent = `[${time}] ${label} :: ${detail}`;
        terminal.append(line);
        if (row.mirage) {
          const payload = document.createElement('div');
          payload.textContent = `  ↳ synthetic response ${JSON.stringify(row.mirage).slice(0, 360)}`;
          terminal.append(payload);
        }
      });
    }

    function syncPolicy(policy) {
      $('#policy-mode').value = policy.mode === 'DRY_RUN' ? 'DRY_RUN' : 'ENFORCE';
      $('#policy-dc').checked = Boolean(policy.blockDatacenterAsn);
      $('#policy-deception').checked = policy.deceptionEnabled !== false;
      $('#policy-limit').value = Number(policy.rateLimitPerMinute) || 120;
    }

    $('#save-policy')?.addEventListener('click', async () => {
      const notice = $('#policy-notice');
      const payload = {
        action: 'policy',
        mode: $('#policy-mode').value,
        blockDatacenterAsn: $('#policy-dc').checked,
        deceptionEnabled: $('#policy-deception').checked,
        rateLimitPerMinute: Number($('#policy-limit').value)
      };
      try {
        const result = await jsonFetch('/api/telemetry', { method: 'POST', body: JSON.stringify(payload) });
        syncPolicy(result.policy);
        showNotice(notice, 'Security policy saved.', 'success');
      } catch (error) { showNotice(notice, error.message, 'error'); }
    });

    $('#decode-leak')?.addEventListener('click', async () => {
      const notice = $('#decode-notice');
      const resultNode = $('#decode-result');
      resultNode.classList.add('hidden');
      try {
        const result = await jsonFetch('/api/decode-leak', { method: 'POST', body: JSON.stringify({ text: $('#leak-input').value }) });
        if (!result.found) {
          showNotice(notice, `No valid watermark found (${result.reason || 'unknown'}).`, 'error');
          return;
        }
        showNotice(notice, result.attributed ? 'Signed watermark verified and attribution resolved.' : 'Marker is valid, but its attribution record is no longer available.', result.attributed ? 'success' : 'error');
        resultNode.replaceChildren();
        const fields = [
          ['Attribution ID', result.attributionId], ['Session ID', result.sessionId], ['User ID', result.userId], ['IP hint', result.ip], ['Timestamp', result.timestamp], ['Country / ASN', `${result.country || 'not recorded'} / ${result.asn || 'not recorded'}`]
        ];
        fields.forEach(([key, value]) => {
          const line = document.createElement('div');
          const label = document.createElement('label'); label.textContent = key;
          const text = document.createElement('div'); text.textContent = value || '—'; text.className = 'key-value';
          line.append(label, text); resultNode.append(line);
        });
        resultNode.classList.remove('hidden');
      } catch (error) { showNotice(notice, error.message, 'error'); }
    });

    $('#logout')?.addEventListener('click', async () => {
      try { await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify({ action: 'logout' }) }); }
      finally { location.href = '/'; }
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    const page = document.body.dataset.page;
    if (page === 'developer') initDeveloper();
    if (page === 'dashboard') initDashboard();
  });
})();
