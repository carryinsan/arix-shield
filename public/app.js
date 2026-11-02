(() => {
  'use strict';
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const jsonFetch = async (url, options = {}) => {
    const response = await fetch(url, { credentials: 'same-origin', ...options, headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) } });
    let data; try { data = await response.json(); } catch { data = {}; }
    if (!response.ok) { const error = new Error(data.error || `Request failed (${response.status}).`); error.status = response.status; error.data = data; throw error; } return data;
  };
  const showNotice = (node, message, type = 'success') => { if (!node) return; node.textContent = message; node.className = `notice show ${type}`; };
  const hideNotice = (node) => { if (node) node.className = 'notice'; };
  const requestStepUp = ({ title = 'Confirm your identity', description = 'Re-enter your credentials to continue.', requirePassword = true, requireTotp = false } = {}) => new Promise((resolve) => {
    const dialog = $('#step-up-modal'); const form = $('#step-up-form'); const passwordField = $('#step-up-password-field'); const totpField = $('#step-up-totp-field');
    const password = $('#step-up-password'); const totp = $('#step-up-totp');
    if (!dialog || typeof dialog.showModal !== 'function' || !form || dialog.open) { resolve(null); return; }
    $('#step-up-title').textContent = title; $('#step-up-description').textContent = description;
    passwordField.classList.toggle('hidden', !requirePassword); totpField.classList.toggle('hidden', !requireTotp);
    password.required = requirePassword; totp.required = requireTotp; password.value = ''; totp.value = '';
    let settled = false;
    const finish = (value) => { if (settled) return; settled = true; form.removeEventListener('submit', submit); $('#step-up-cancel').removeEventListener('click', cancel); dialog.removeEventListener('cancel', onCancel); if (dialog.open) dialog.close(); password.value = ''; totp.value = ''; resolve(value); };
    const cancel = () => finish(null);
    const onCancel = (event) => { event.preventDefault(); finish(null); };
    const submit = (event) => {
      event.preventDefault();
      const passwordValue = password.value;
      const totpValue = totp.value.trim();
      if (requirePassword && !passwordValue) { password.focus(); return; }
      if (requireTotp && !/^\d{6}$/.test(totpValue)) { totp.setCustomValidity('Enter the six-digit authenticator code.'); totp.reportValidity(); totp.setCustomValidity(''); totp.focus(); return; }
      finish({ password: passwordValue, totpCode: totpValue });
    };
    form.addEventListener('submit', submit); $('#step-up-cancel').addEventListener('click', cancel); dialog.addEventListener('cancel', onCancel);
    try { dialog.showModal(); (requirePassword ? password : totp).focus(); } catch { finish(null); }
  });
  const copyText = async (value) => { if (navigator.clipboard?.writeText) return navigator.clipboard.writeText(value); const input = document.createElement('textarea'); input.value = value; input.setAttribute('readonly', ''); input.className = 'clipboard-helper'; document.body.append(input); input.select(); const copied = document.execCommand('copy'); input.remove(); if (!copied) throw new Error('Clipboard access was denied.'); };
  const solveLoginPow = async (challenge, onProgress = () => {}) => {
    if (!challenge?.nonce || !challenge?.token || !Number.isInteger(challenge.difficulty) || challenge.difficulty < 12 || challenge.difficulty > 20) throw new Error('The sign-in proof-of-work challenge is invalid.');
    const encoder = new TextEncoder(); const prefix = encoder.encode(`${challenge.nonce}:`); const difficulty = challenge.difficulty; const digestInput = new Uint8Array(prefix.length + 16); digestInput.set(prefix);
    for (let solution = 0; solution < 5000000; solution++) {
      const suffix = encoder.encode(String(solution)); digestInput.set(suffix, prefix.length);
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', digestInput.subarray(0, prefix.length + suffix.length)));
      let remaining = difficulty; let valid = true;
      for (const byte of digest) { const bits = Math.min(8, remaining); if (bits > 0 && (byte >>> (8 - bits)) !== 0) { valid = false; break; } remaining -= bits; if (remaining <= 0) break; }
      if (valid) return String(solution);
      if ((solution & 511) === 511) { onProgress(solution); await new Promise((resolve) => setTimeout(resolve, 0)); }
    }
    throw new Error('Could not complete the sign-in proof-of-work challenge within the work budget.');
  };

  const b64urlToBytes = (value) => Uint8Array.from(atob(String(value).replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - String(value).length % 4) % 4)), (character) => character.charCodeAt(0));
  const bytesToB64url = (value) => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  function serializeWebAuthnCredential(credential) {
    if (!credential || credential.type !== 'public-key') throw new Error('The authenticator did not return a public-key credential.');
    const response = credential.response;
    const result = { id: credential.id, rawId: bytesToB64url(credential.rawId), type: credential.type, response: { clientDataJSON: bytesToB64url(response.clientDataJSON) } };
    if (response.attestationObject) result.response.attestationObject = bytesToB64url(response.attestationObject);
    if (response.authenticatorData) result.response.authenticatorData = bytesToB64url(response.authenticatorData);
    if (response.signature) result.response.signature = bytesToB64url(response.signature);
    if (response.userHandle) result.response.userHandle = bytesToB64url(response.userHandle);
    if (typeof response.getTransports === 'function') result.response.transports = response.getTransports().slice(0, 8);
    return result;
  }

  async function initDeveloper() {
    const form = $('#auth-form'); if (!form) return;
    const tabs = $$('[data-auth-mode]'); const nameField = $('#full-name'); const projectField = $('#project-name'); const originField = $('#origin'); const passField = $('#password'); const submit = $('#auth-submit'); const notice = $('#auth-notice'); const keysPanel = $('#keys-panel'); const passkeyLogin = $('#passkey-login');
    let authMode = 'signup'; let activeKeys = { liveKey: '', serverKey: '', canaryKey: '' };
    const updateSnippet = () => {
      const target = $('#snippet-code'); const type = $('#snippet-type')?.value || 'html'; const base = location.origin; const live = activeKeys.liveKey || 'ARIX_LIVE_PROJECT_IDENTIFIER'; const secret = activeKeys.serverKey || 'ARIX_SECRET_SERVER_ONLY';
      const snippets = {
        html: `<script src="${base}/arix-client.js" data-arix-key="${live}" data-arix-protect="/api/login,/api/signup,/api/checkout,/api/otp,/api/ai" defer><\/script>`,
        node: `import express from 'express';\nimport { createArixShield } from './sdk/node.js';\n\nconst app = express();\n// Preserve exact request bytes so request-body DPoP can verify the same bytes the browser signed.\napp.use(express.json({ limit: '32kb', verify: (req, res, buf) => { req.rawBody = Buffer.from(buf); } }));\napp.use(createArixShield({\n  serverKey: process.env.ARIX_SECRET_KEY,\n  endpoint: '${base}',\n  mode: 'ENFORCE',\n  rateLimitPerMinute: 120,\n  globalRateLimit: true\n}));\n\n// Define your API routes after the ArixShield middleware.`,
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
      authMode = mode; tabs.forEach((tab) => tab.classList.toggle('active', tab.dataset.authMode === mode)); $$('.signup-field').forEach((element) => element.classList.toggle('hidden', mode !== 'signup')); $$('.login-field').forEach((element) => element.classList.toggle('hidden', mode !== 'login'));
      [nameField, projectField, originField].forEach((field) => { if (field) field.required = mode === 'signup'; }); if (passField) passField.autocomplete = mode === 'signup' ? 'new-password' : 'current-password'; submit.textContent = mode === 'signup' ? 'Create account & project' : 'Sign in'; hideNotice(notice);
    };
    tabs.forEach((tab) => tab.addEventListener('click', () => changeMode(tab.dataset.authMode)));
    try { const session = await jsonFetch('/api/auth'); if (session.authenticated) { location.replace('/dashboard'); return; } } catch { /* Keep the form available; submit shows the service error. */ }
    passkeyLogin?.addEventListener('click', async () => {
      passkeyLogin.disabled = true; hideNotice(notice);
      try {
        if (!window.isSecureContext || !navigator.credentials?.get) throw new Error('Passkey sign-in requires a supported browser on HTTPS or localhost.');
        const options = await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify({ action: 'passkey-login-options' }) });
        const publicKey = { ...options.publicKey, challenge: b64urlToBytes(options.publicKey.challenge) };
        const credential = await navigator.credentials.get({ publicKey });
        if (!credential) throw new Error('Passkey sign-in was cancelled.');
        const result = await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify({ action: 'passkey-login', challenge: options.challenge, credential: serializeWebAuthnCredential(credential) }) });
        showNotice(notice, `Welcome back, ${result.user.name}. Opening your dashboard…`, 'success'); location.href = '/dashboard';
      } catch (error) { showNotice(notice, error.message, 'error'); }
      finally { passkeyLogin.disabled = false; }
    });
    form.addEventListener('submit', async (event) => {
      event.preventDefault(); hideNotice(notice); submit.disabled = true; submit.textContent = authMode === 'signup' ? 'Creating secure project…' : 'Signing in…'; const data = Object.fromEntries(new FormData(form).entries()); data.action = authMode;
      try {
        let result;
        try { result = await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify(data) }); }
        catch (error) {
          const challenge = error.status === 428 ? error.data?.challenge : null;
          if (authMode !== 'login' || !challenge) throw error;
          showNotice(notice, 'Additional sign-in protection is active. Verifying this browser…', 'info');
          data.powToken = challenge.token;
          data.powSolution = await solveLoginPow(challenge, (attempt) => { if (attempt % 8192 === 0) showNotice(notice, `Verifying this browser… ${Math.round(attempt / 65536)}%`, 'info'); });
          result = await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify(data) });
        }
        if (authMode === 'login') { showNotice(notice, `Welcome back, ${result.user.name}. Opening your dashboard…`, 'success'); location.href = '/dashboard'; return; }
        activeKeys = result.keys; $('#live-key').textContent = result.keys.liveKey; $('#server-key').textContent = result.keys.serverKey; $('#canary-key').textContent = result.keys.canaryKey; keysPanel.classList.add('show'); changeMode('login'); form.classList.add('hidden'); updateSnippet(); showNotice(notice, 'Account and project created successfully.', 'success');
      } catch (error) { showNotice(notice, error.message, 'error'); }
      finally { submit.disabled = false; if (authMode === 'login') submit.textContent = 'Sign in'; }
    });
    $('#snippet-type')?.addEventListener('change', updateSnippet);
    $('#copy-snippet')?.addEventListener('click', async () => { try { await copyText($('#snippet-code').textContent); showNotice(notice, 'Snippet copied.', 'success'); } catch (error) { showNotice(notice, error.message, 'error'); } });
    $$('[data-copy-target]').forEach((button) => button.addEventListener('click', async () => { try { await copyText($(`#${button.dataset.copyTarget}`).textContent); button.textContent = 'Copied'; } catch (error) { showNotice(notice, error.message, 'error'); } }));
    updateSnippet();
  }

  async function initDashboard() {
    if (!$('#visitor-table')) return;
    const status = $('#connection-status'); const primaryOriginInput = $('#primary-origin'); const customOriginsInput = $('#custom-origins'); const originsForm = $('#origins-form'); const originsNotice = $('#origins-notice'); let originsDirty = false; let dashboardTotpEnabled = false; let currentPolicyMode = 'ENFORCE';
    const promptStepUp = (purpose) => requestStepUp({ title: 'Confirm sensitive change', description: `Confirm your identity to ${purpose}.`, requirePassword: true, requireTotp: dashboardTotpEnabled });
    const showDashError = (message) => { status.textContent = 'DISCONNECTED'; status.classList.add('is-danger'); status.classList.remove('is-good'); $('#project-origin').textContent = message; };
    const updateOriginCount = () => { if (!primaryOriginInput || !customOriginsInput) return; const primary = primaryOriginInput.value.trim().replace(/\/$/, ''); const extras = [...new Set(customOriginsInput.value.split(/[\n,]+/).map((value) => value.trim().replace(/\/$/, '')).filter((value) => value && value !== primary))]; $('#origin-count').textContent = `${1 + extras.length} / 11 origins configured`; };
    const syncOrigins = (project) => { if (!primaryOriginInput || !customOriginsInput) return; const primary = project.origin || ''; const allowed = Array.isArray(project.allowedOrigins) && project.allowedOrigins.length ? project.allowedOrigins : [primary].filter(Boolean); primaryOriginInput.value = primary; customOriginsInput.value = allowed.filter((origin) => origin && origin !== primary).join(', '); originsDirty = false; updateOriginCount(); };
    primaryOriginInput?.addEventListener('input', () => { originsDirty = true; updateOriginCount(); hideNotice(originsNotice); });
    customOriginsInput?.addEventListener('input', () => { originsDirty = true; updateOriginCount(); hideNotice(originsNotice); });
    originsForm?.addEventListener('submit', async (event) => {
      event.preventDefault(); const saveButton = $('#save-origins'); saveButton.disabled = true; saveButton.textContent = 'Saving origins…'; hideNotice(originsNotice);
      try { const stepUp = await promptStepUp('change application origins'); if (!stepUp) { showNotice(originsNotice, 'Origin change canceled.', 'info'); return; } const result = await jsonFetch('/api/telemetry', { method: 'POST', body: JSON.stringify({ action: 'origins', origin: primaryOriginInput.value.trim(), customOrigins: customOriginsInput.value, ...stepUp }) }); syncOrigins(result.project); showNotice(originsNotice, 'Origin allowlist saved. It is active for the next browser telemetry request; no redeployment is required.', 'success'); }
      catch (error) { showNotice(originsNotice, error.message, 'error'); }
      finally { saveButton.disabled = false; saveButton.textContent = 'Save origins'; }
    });
    try {
      const account = await jsonFetch('/api/auth'); if (!account.authenticated) { location.href = '/developer'; return; } $('#dash-user').textContent = account.user.email; dashboardTotpEnabled = account.security?.totpEnabled === true;
      initializeAccountSecurity(account.security || {});
      const poll = async () => {
        const data = await jsonFetch('/api/telemetry'); $('#project-title').textContent = data.project.name; $('#project-origin').textContent = `${data.project.origin} · ${data.project.id}`; if (!originsDirty) syncOrigins(data.project);
        status.textContent = 'LIVE · 5S POLL'; status.classList.add('is-good'); status.classList.remove('is-danger');
        $('#metric-requests').textContent = Number(data.metrics.totalRequests || 0).toLocaleString(); $('#metric-blocked').textContent = Number(data.metrics.blockedAttacks || 0).toLocaleString(); $('#metric-trapped').textContent = Number(data.metrics.trappedHackers || 0).toLocaleString(); $('#metric-visitors').textContent = Number(data.metrics.activeVisitors || 0).toLocaleString(); $('#visitor-count').textContent = `${data.metrics.activeVisitors || 0} active`;
        renderVisitors(data.visitors || []); renderThreats(data.threats || []); renderAttackerGraph(data.threats || []); renderAnalytics(data.analytics, data.auditAnchor); renderCatalog(data.apiCatalog || []); renderReplay(data.forensicReplay || []); syncPolicy(data.policy || {}); renderThreatFeedStatus(data.threatFeedStatus); await updateAuditWitness(data.project.id, data.auditChain);
      };
      await poll(); window.setInterval(() => poll().catch((error) => showDashError(error.message)), 5000);
    } catch (error) { showDashError(error.message); if (/sign in/i.test(error.message)) location.href = '/developer'; }

    function openWitnessDb() {
      return new Promise((resolve, reject) => {
        if (!window.indexedDB) { reject(new Error('IndexedDB is unavailable in this browser.')); return; }
        const request = indexedDB.open('arixshield-audit-witness-v1', 1);
        request.onupgradeneeded = () => { const db = request.result; if (!db.objectStoreNames.contains('roots')) db.createObjectStore('roots', { keyPath: 'projectId' }); };
        request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error || new Error('Could not open local audit witness storage.'));
      });
    }
    async function witnessGet(projectId) {
      const db = await openWitnessDb();
      try { return await new Promise((resolve, reject) => { const request = db.transaction('roots', 'readonly').objectStore('roots').get(projectId); request.onsuccess = () => resolve(request.result || null); request.onerror = () => reject(request.error); }); }
      finally { db.close(); }
    }
    async function witnessPut(value) {
      const db = await openWitnessDb();
      try { await new Promise((resolve, reject) => { const transaction = db.transaction('roots', 'readwrite'); transaction.objectStore('roots').put(value); transaction.oncomplete = resolve; transaction.onerror = () => reject(transaction.error); transaction.onabort = () => reject(transaction.error || new Error('Audit witness transaction aborted.')); }); }
      finally { db.close(); }
    }
    async function updateAuditWitness(projectId, chain) {
      if (!witnessStatus) return;
      if (!chain || chain.verified !== true || !Number.isSafeInteger(Number(chain.sequence)) || !/^[a-f0-9]{64}$/.test(String(chain.head || ''))) {
        witnessStatus.textContent = 'Server audit chain failed verification; local witness not advanced.'; witnessStatus.dataset.state = 'error'; if (auditDownload) auditDownload.disabled = true; return;
      }
      if (auditDownload) auditDownload.disabled = false;
      try {
        const saved = await witnessGet(projectId);
        const sequence = Number(chain.sequence); const head = String(chain.head);
        if (!saved) {
          await witnessPut({ projectId, sequence, head, pinnedAt: new Date().toISOString(), trustOnFirstUse: true });
          witnessStatus.textContent = `First local pin saved at sequence ${sequence}. This device cannot detect tampering that predates this first visit.`; witnessStatus.dataset.state = 'first-pin'; return;
        }
        if (sequence < Number(saved.sequence) || (sequence === Number(saved.sequence) && head !== saved.head)) {
          witnessStatus.textContent = `ALERT: audit rollback or fork detected (local ${saved.sequence}, server ${sequence}).`; witnessStatus.dataset.state = 'error'; if (auditDownload) auditDownload.disabled = true; return;
        }
        if (sequence === Number(saved.sequence)) {
          witnessStatus.textContent = `Local witness matches server head at sequence ${sequence}.`; witnessStatus.dataset.state = 'ok'; return;
        }
        const rows = Array.isArray(chain.rows) ? [...chain.rows].sort((a, b) => Number(a.seq) - Number(b.seq)) : [];
        const extension = rows.filter((row) => Number(row.seq) > Number(saved.sequence));
        if (!extension.length || Number(extension[0].seq) !== Number(saved.sequence) + 1 || extension[0].prevChainMac !== saved.head || Number(extension.at(-1).seq) !== sequence || extension.at(-1).chainMac !== head) {
          witnessStatus.textContent = 'Audit history gap: the server window cannot prove a continuous extension from this device’s last pin. Local pin preserved.'; witnessStatus.dataset.state = 'warning'; return;
        }
        let priorSeq = Number(saved.sequence); let priorMac = saved.head; let continuous = true;
        for (const row of extension) { if (Number(row.seq) !== priorSeq + 1 || row.prevChainMac !== priorMac) { continuous = false; break; } priorSeq = Number(row.seq); priorMac = row.chainMac; }
        if (!continuous) { witnessStatus.textContent = 'ALERT: audit chain extension is discontinuous. Local pin preserved.'; witnessStatus.dataset.state = 'error'; if (auditDownload) auditDownload.disabled = true; return; }
        await witnessPut({ projectId, sequence, head, pinnedAt: saved.pinnedAt, lastExtendedAt: new Date().toISOString(), trustOnFirstUse: true });
        witnessStatus.textContent = `Audit chain continuously extended to sequence ${sequence}; local witness updated.`; witnessStatus.dataset.state = 'ok';
      } catch (error) { witnessStatus.textContent = `Local audit witness unavailable: ${error.message}`; witnessStatus.dataset.state = 'warning'; }
    }
    function renderThreatFeedStatus(status) {
      if (!feedWarning) return;
      const stale = Array.isArray(status?.staleFeeds) ? status.staleFeeds : [];
      feedWarning.textContent = status?.warning ? `THREAT_FEED_STALE: reduced confidence for feeds older than 24 hours or missing (${stale.join(', ')}).` : status?.loaded ? 'Threat feeds loaded and within the freshness window.' : 'Threat feed status unavailable; no feed-based hard block is inferred.';
      feedWarning.classList.toggle('hidden', !status?.warning);
      feedWarning.classList.toggle('threat-warning', Boolean(status?.warning));
    }
    auditDownload?.addEventListener('click', async () => {
      auditDownload.disabled = true;
      try {
        const result = await jsonFetch('/api/telemetry', { method: 'POST', body: JSON.stringify({ action: 'audit-bundle' }) });
        const lines = [JSON.stringify({ type: 'ARIX_AUDIT_BUNDLE', bundle: result.bundle }), JSON.stringify({ type: 'HMAC_SIGNATURE', algorithm: result.signature.algorithm, signature: result.signature.value })];
        const blob = new Blob([`${lines.join('\n')}\n`], { type: 'application/x-ndjson' }); const url = URL.createObjectURL(blob);
        const link = document.createElement('a'); link.href = url; link.download = `arixshield-audit-${String(result.bundle.projectId).replace(/[^a-z0-9_-]/gi, '_')}-${Date.now()}.jsonl`; document.body.append(link); link.click(); link.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      } catch (error) { if (witnessStatus) witnessStatus.textContent = `Evidence export failed: ${error.message}`; }
      finally { auditDownload.disabled = false; }
    });

    function initializeAccountSecurity(security) {
      const notice = $('#security-notice');
      const enrollment = $('#totp-enrollment'); const disablePanel = $('#totp-disable-panel');
      dashboardTotpEnabled = security?.totpEnabled === true;
      $('#password-change-form')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const changeButton = $('#change-password'); const passwordNotice = $('#password-change-notice');
        const currentPassword = $('#password-current').value; const newPassword = $('#password-new').value; const confirmPassword = $('#password-confirm').value;
        if (newPassword !== confirmPassword) { showNotice(passwordNotice, 'New password and confirmation do not match.', 'error'); return; }
        const proof = dashboardTotpEnabled ? await requestStepUp({ title: 'Confirm password change', description: 'Enter your current authenticator code.', requirePassword: false, requireTotp: true }) : { totpCode: '' };
        if (!proof) return;
        const totpCode = proof.totpCode;
        changeButton.disabled = true;
        try { await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify({ action: 'change-password', currentPassword, newPassword, confirmPassword, totpCode: String(totpCode || '').trim() }) }); $('#password-current').value = ''; $('#password-new').value = ''; $('#password-confirm').value = ''; showNotice(passwordNotice, 'Password changed. Other sessions were revoked; this browser remains signed in.', 'success'); }
        catch (error) { showNotice(passwordNotice, error.message, 'error'); }
        finally { changeButton.disabled = false; }
      });
      const totpStart = $('#totp-start'); const passkeyStatus = $('#passkey-status'); const passkeyList = $('#passkey-list');
      let securityState = security || {};
      const render = () => {
        const enabled = securityState.totpEnabled === true;
        $('#totp-status').textContent = enabled ? 'Enabled · authenticator code required at sign-in' : 'Not enabled';
        if (totpStart) { totpStart.disabled = enabled; totpStart.textContent = enabled ? 'MFA enabled' : 'Set up TOTP'; }
        if (disablePanel) disablePanel.classList.toggle('hidden', !enabled);
        const keys = Array.isArray(securityState.passkeys) ? securityState.passkeys : [];
        if (passkeyStatus) passkeyStatus.textContent = `${keys.length} registered · maximum 10`;
        if (passkeyList) {
          passkeyList.replaceChildren();
          if (!keys.length) passkeyList.textContent = 'No passkeys registered.';
          keys.forEach((item, index) => {
            const row = document.createElement('div'); row.className = 'inline-form';
            const label = document.createElement('span'); label.textContent = `Passkey ${index + 1} · last used ${item.lastUsedAt ? new Date(item.lastUsedAt).toLocaleString() : 'not yet used'}`;
            const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'btn btn-secondary'; remove.textContent = 'Remove'; remove.addEventListener('click', async () => {
              const proof = await requestStepUp({ title: 'Remove passkey', description: 'Re-authenticate before removing this passkey.', requirePassword: true, requireTotp: securityState.totpEnabled === true }); if (!proof) return;
              try { await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify({ action: 'passkey-remove', credentialId: item.credentialId, password: proof.password, totpCode: proof.totpCode }) }); showNotice(notice, 'Passkey removed.', 'success'); await refreshSecurity(); }
              catch (error) { showNotice(notice, error.message, 'error'); }
            }); row.append(label, remove); passkeyList.append(row);
          });
        }
      };
      const refreshSecurity = async () => { const current = await jsonFetch('/api/auth'); securityState = current.security || {}; dashboardTotpEnabled = securityState.totpEnabled === true; render(); };
      render();

      $('#totp-start')?.addEventListener('click', async () => {
        totpStart.disabled = true;
        try { const result = await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify({ action: 'totp-enroll' }) });
          $('#totp-secret').textContent = result.secret; $('#totp-uri').value = result.otpauthUri; enrollment.classList.remove('hidden'); showNotice(notice, 'Add this secret to your authenticator app, then enter its current code to confirm. The enrollment expires in 10 minutes.', 'info');
        } catch (error) { showNotice(notice, error.message, 'error'); }
        finally { totpStart.disabled = false; }
      });
      $('#totp-confirm')?.addEventListener('click', async () => {
        const totpCode = $('#totp-confirm-code').value.trim();
        try { await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify({ action: 'totp-confirm', totpCode }) }); enrollment.classList.add('hidden'); $('#totp-confirm-code').value = ''; showNotice(notice, 'Authenticator MFA enabled. Other sessions were revoked; this browser has been issued a fresh session.', 'success'); await refreshSecurity(); }
        catch (error) { showNotice(notice, error.message, 'error'); }
      });
      $('#totp-disable')?.addEventListener('click', async () => {
        try { await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify({ action: 'totp-disable', password: $('#totp-disable-password').value, totpCode: $('#totp-disable-code').value.trim() }) }); $('#totp-disable-password').value = ''; $('#totp-disable-code').value = ''; showNotice(notice, 'Authenticator MFA disabled. Other sessions were revoked; this browser has a fresh session.', 'success'); await refreshSecurity(); }
        catch (error) { showNotice(notice, error.message, 'error'); }
      });
      $('#passkey-add')?.addEventListener('click', async () => {
        const button = $('#passkey-add'); button.disabled = true;
        try {
          if (!window.isSecureContext || !navigator.credentials?.create) throw new Error('Passkey enrollment requires a supported browser on HTTPS or localhost.');
          const options = await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify({ action: 'passkey-register-options' }) });
          const publicKey = { ...options.publicKey, challenge: b64urlToBytes(options.publicKey.challenge), user: { ...options.publicKey.user, id: b64urlToBytes(options.publicKey.user.id) }, excludeCredentials: (options.publicKey.excludeCredentials || []).map((item) => ({ ...item, id: b64urlToBytes(item.id) })) };
          const credential = await navigator.credentials.create({ publicKey });
          if (!credential) throw new Error('Passkey enrollment was cancelled.');
          await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify({ action: 'passkey-register', challenge: options.challenge, credential: serializeWebAuthnCredential(credential) }) });
          showNotice(notice, 'Passkey registered. Store a recovery method before removing other credentials.', 'success'); await refreshSecurity();
        } catch (error) { showNotice(notice, error.message, 'error'); }
        finally { button.disabled = false; }
      });
      const refreshSessions = async () => {
        const root = $('#session-list'); if (!root) return;
        try {
          const result = await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify({ action: 'list-sessions' }) }); root.replaceChildren();
          if (!result.sessions?.length) { root.textContent = 'No active sessions.'; return; }
          result.sessions.forEach((session, index) => {
            const row = document.createElement('div'); row.className = 'inline-form';
            const label = document.createElement('span'); label.textContent = `Device ${index + 1} · last active ${new Date(session.lastActiveAt).toLocaleString()} · ${session.ipHint || 'IP unavailable'} · ${(session.uaHint || '').slice(0, 80)}`;
            const revoke = document.createElement('button'); revoke.type = 'button'; revoke.className = 'btn btn-secondary'; revoke.textContent = 'Revoke'; revoke.addEventListener('click', async () => {
              try { await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify({ action: 'revoke-session', tokenHash: session.tokenHash }) }); showNotice(notice, 'Session revoked.', 'success'); await refreshSessions(); }
              catch (error) { showNotice(notice, error.message, 'error'); }
            }); row.append(label, revoke); root.append(row);
          });
        } catch (error) { root.textContent = error.message; }
      };
      $('#refresh-sessions')?.addEventListener('click', () => refreshSessions());
      $('#rotate-key')?.addEventListener('click', async () => {
        const button = $('#rotate-key'); button.disabled = true; const graceSeconds = Number($('#rotate-grace').value);
        try {
          if (!Number.isInteger(graceSeconds) || graceSeconds < 0 || graceSeconds > 86400) throw new Error('Grace period must be an integer from 0 to 86400 seconds.');
          const result = await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify({ action: 'rotate-server-key', password: $('#rotate-password').value, totpCode: $('#rotate-totp').value.trim(), graceSeconds }) });
          $('#rotated-server-key').textContent = result.serverKey; $('#rotated-key-panel').classList.remove('hidden');
          showNotice(notice, `Server key rotated. Update your server environment now. Previous key grace: ${result.oldKeyGraceSeconds} seconds${result.cleanupWarning ? ' · post-rotation cleanup needs operator review' : ''}.`, result.cleanupWarning ? 'error' : 'success');
          $('#rotate-password').value = ''; $('#rotate-totp').value = ''; await refreshSessions();
        } catch (error) { showNotice(notice, error.message, 'error'); }
        finally { button.disabled = false; }
      });
      refreshSessions();
    }

    function renderAttackerGraph(events) {
      const canvas = document.getElementById('attacker-graph'); const note = document.getElementById('attacker-graph-note'); if (!canvas) return; const rect = canvas.getBoundingClientRect(); const ratio = Math.min(2, window.devicePixelRatio || 1); const width = Math.max(320, Math.floor(rect.width || 640)); const height = 280; canvas.width = Math.floor(width * ratio); canvas.height = Math.floor(height * ratio); const ctx = canvas.getContext('2d'); if (!ctx) { if (note) note.textContent = 'Canvas is unavailable in this browser.'; return; }
      ctx.scale(ratio, ratio); ctx.clearRect(0, 0, width, height); const actors = new Map(); const indicators = new Map(); const links = [];
      (events || []).filter((event) => event.blocked !== false).slice(0, 40).forEach((event, index) => {
        const actorId = String(event.actorHash || event.ip || `${event.type || 'event'}-${index}`).slice(0, 96); const actor = actors.get(actorId) || { id: `actor:${actorId}`, label: event.ip ? `${String(event.ip).replace(/(\d+\.\d+)\.\d+\.\d+/, '$1.*.*')}` : `event ${index + 1}`, type: 'actor' }; actors.set(actorId, actor);
        for (const [kind, raw] of [['ASN', event.asn], ['JA4', event.ja4]]) { if (!raw) continue; const value = String(raw).slice(0, 64); const key = `${kind}:${value}`; const indicator = indicators.get(key) || { id: key, label: `${kind} ${value}`, type: 'indicator' }; indicators.set(key, indicator); links.push([actor.id, indicator.id]); }
      });
      const nodes = [...actors.values(), ...indicators.values()]; if (!nodes.length) { ctx.fillStyle = '#718096'; ctx.font = '13px system-ui'; ctx.textAlign = 'center'; ctx.fillText('No blocked-event indicators available yet', width / 2, height / 2); if (note) note.textContent = 'Add network and SDK telemetry to populate correlation edges.'; return; }
      const positions = new Map(); nodes.forEach((node, index) => { const count = nodes.length; const angle = (Math.PI * 2 * index / count) - Math.PI / 2; const radius = node.type === 'actor' ? Math.min(width * .34, height * .38) : Math.min(width * .43, height * .46); positions.set(node.id, { x: width / 2 + Math.cos(angle) * radius, y: height / 2 + Math.sin(angle) * radius }); });
      ctx.lineWidth = 1; ctx.strokeStyle = '#a9b9d2'; links.forEach(([a, b]) => { const p1 = positions.get(a); const p2 = positions.get(b); if (!p1 || !p2) return; ctx.beginPath(); ctx.moveTo(p1.x, p1.y); ctx.lineTo(p2.x, p2.y); ctx.stroke(); });
      nodes.forEach((node) => { const pos = positions.get(node.id); ctx.beginPath(); ctx.arc(pos.x, pos.y, node.type === 'actor' ? 6 : 5, 0, Math.PI * 2); ctx.fillStyle = node.type === 'actor' ? '#285be6' : '#c07a1c'; ctx.fill(); ctx.fillStyle = '#24344d'; ctx.font = '10px system-ui'; ctx.textAlign = 'center'; const text = node.label.length > 22 ? `${node.label.slice(0, 20)}…` : node.label; ctx.fillText(text, pos.x, Math.min(height - 7, pos.y + 17)); });
      if (note) note.textContent = `${actors.size} actor indicators · ${indicators.size} shared network/fingerprint indicators · ${links.length} observed relationships`;
    }
    function renderAnalytics(data, anchor) {
      const fields = [['analytics-requests', data?.requests], ['analytics-blocked', data?.blocked], ['analytics-p50', data?.p50], ['analytics-p95', data?.p95], ['analytics-p99', data?.p99]];
      for (const [id, value] of fields) { const node = document.getElementById(id); if (node) node.textContent = value === undefined || value === null ? (data ? '—' : 'Not configured') : Number(value).toLocaleString(); }
      const errors = document.getElementById('analytics-errors'); if (errors) errors.textContent = data ? `${Number(data.errors_4xx || 0).toLocaleString()} / ${Number(data.errors_5xx || 0).toLocaleString()}` : '—';
      const root = document.getElementById('audit-root'); if (root) root.textContent = anchor?.root ? `Last Merkle root: ${anchor.root}${anchor.anchor?.anchored ? ` · GitHub commit ${anchor.anchor.commit || 'created'}` : ' · not externally anchored'}` : 'Audit root: no externally anchored batch yet. Configure GitHub audit anchoring.';
    }
    function renderCatalog(rows) { const node = document.getElementById('api-catalog'); if (!node) return; node.textContent = rows.length ? rows.slice(0, 100).join('\n') : 'No observed routes yet. Enable Shadow API catalog and install an SDK wrapper.'; }
    function renderReplay(rows) { const node = document.getElementById('forensic-replay'); if (!node) return; if (!rows.length) { node.textContent = 'No sanitized forensic events yet.'; return; } node.textContent = rows.slice(0, 40).map((row) => { const time = row.timestamp ? new Date(row.timestamp).toLocaleString() : 'unknown time'; return `[${time}] ${row.method || '—'} ${row.route || '/'} → ${row.status ?? '—'} · ${row.country || '—'} · AS${row.asn || '—'}`; }).join('\n'); }
    function renderVisitors(rows) {
      const body = $('#visitor-table'); body.replaceChildren();
      if (!rows.length) { const tr = document.createElement('tr'); const td = document.createElement('td'); td.colSpan = 4; td.className = 'empty'; td.textContent = 'No visitor events yet. Add the browser script to your configured site origin.'; tr.append(td); body.append(tr); return; }
      rows.forEach((row) => { const tr = document.createElement('tr'); const values = [`${row.visitorId || '—'} · ${row.ip || 'unavailable'}`, `${row.country || '—'} · AS${row.asn || '—'}`, row.path || '/', row.dpopVerified ? 'Verified' : '—']; values.forEach((value, index) => { const td = document.createElement('td'); td.textContent = value; if (index === 3 && row.dpopVerified) { const tag = document.createElement('span'); tag.className = 'status-tag'; tag.textContent = 'DPoP'; td.replaceChildren(tag); } tr.append(td); }); body.append(tr); });
    }
    function renderThreats(rows) {
      const terminal = $('#threat-terminal'); terminal.replaceChildren(); if (!rows.length) { terminal.textContent = 'No threats recorded for this project.'; return; }
      rows.slice(0, 18).forEach((row) => { const line = document.createElement('div'); const time = row.timestamp ? new Date(row.timestamp).toLocaleTimeString() : '--:--:--'; const label = row.type || 'SECURITY_EVENT'; const detail = row.reason || (Array.isArray(row.findings) ? row.findings.map((item) => item.category).join(', ') : row.path || 'Event recorded'); line.textContent = `[${time}] ${label} :: ${detail}`; terminal.append(line); if (row.mirage) { const payload = document.createElement('div'); payload.textContent = ` !³ synthetic response ${JSON.stringify(row.mirage).slice(0, 360)}`; terminal.append(payload); } });
    }
    function syncPolicy(policy) {
      currentPolicyMode = policy.mode === 'DRY_RUN' ? 'DRY_RUN' : 'ENFORCE'; $('#policy-mode').value = currentPolicyMode; $('#policy-dc').checked = Boolean(policy.blockDatacenterAsn); $('#policy-deception').checked = policy.deceptionEnabled !== false; $('#policy-abuse').checked = policy.abuseProtectionEnabled === true; $('#policy-feeds').checked = policy.threatFeedEnabled !== false; $('#policy-geo').checked = policy.geoVelocityEnabled === true; $('#policy-shadow').checked = policy.shadowApiCatalogEnabled === true; $('#policy-forensic').checked = policy.forensicReplayEnabled === true; $('#policy-limit').value = Number(policy.rateLimitPerMinute) || 120; $('#policy-alert-webhook').value = policy.alertWebhookUrl || ''; $('#policy-auto-containment').checked = policy.autoContainmentEnabled === true;
    }
    $('#save-policy')?.addEventListener('click', async () => {
      const notice = $('#policy-notice'); const payload = { action: 'policy', mode: $('#policy-mode').value, blockDatacenterAsn: $('#policy-dc').checked, deceptionEnabled: $('#policy-deception').checked, abuseProtectionEnabled: $('#policy-abuse').checked, threatFeedEnabled: $('#policy-feeds').checked, geoVelocityEnabled: $('#policy-geo').checked, shadowApiCatalogEnabled: $('#policy-shadow').checked, forensicReplayEnabled: $('#policy-forensic').checked, rateLimitPerMinute: Number($('#policy-limit').value), alertWebhookUrl: $('#policy-alert-webhook').value.trim(), autoContainmentEnabled: $('#policy-auto-containment').checked };
      try { if (payload.mode === 'DRY_RUN' && currentPolicyMode !== 'DRY_RUN') { const stepUp = await promptStepUp('switch enforcement to DRY_RUN'); if (!stepUp) { showNotice(notice, 'Policy change canceled.', 'info'); return; } Object.assign(payload, stepUp); } const result = await jsonFetch('/api/telemetry', { method: 'POST', body: JSON.stringify(payload) }); syncPolicy(result.policy); showNotice(notice, 'Security policy saved.', 'success'); } catch (error) { showNotice(notice, error.message, 'error'); }
    });
    $('#decode-leak')?.addEventListener('click', async () => {
      const notice = $('#decode-notice'); const resultNode = $('#decode-result'); resultNode.classList.add('hidden');
      try {
        const result = await jsonFetch('/api/decode-leak', { method: 'POST', body: JSON.stringify({ text: $('#leak-input').value }) });
        if (!result.found) { showNotice(notice, `No valid watermark found (${result.reason || 'unknown'}).`, 'error'); return; }
        showNotice(notice, result.attributed ? 'Signed watermark verified and attribution resolved.' : 'Marker is valid, but its attribution record is no longer available.', result.attributed ? 'success' : 'error'); resultNode.replaceChildren();
        const fields = [['Attribution ID', result.attributionId], ['Session ID', result.sessionId], ['User ID', result.userId], ['IP hint', result.ip], ['Timestamp', result.timestamp], ['Country / ASN', `${result.country || 'not recorded'} / ${result.asn || 'not recorded'}`]];
        fields.forEach(([key, value]) => { const line = document.createElement('div'); const label = document.createElement('label'); label.textContent = key; const valueNode = document.createElement('div'); valueNode.textContent = value || '—'; valueNode.className = 'key-value'; line.append(label, valueNode); resultNode.append(line); }); resultNode.classList.remove('hidden');
      } catch (error) { showNotice(notice, error.message, 'error'); }
    });
    $('#logout')?.addEventListener('click', async () => { try { await jsonFetch('/api/auth', { method: 'POST', body: JSON.stringify({ action: 'logout' }) }); } finally { location.href = '/'; } });
  }
  document.addEventListener('DOMContentLoaded', () => { const page = document.body.dataset.page; if (page === 'developer') initDeveloper(); if (page === 'dashboard') initDashboard(); });
})();
