(() => {
  'use strict';
  const form = document.getElementById('origins-form');
  if (!form) return;
  const primary = document.getElementById('primary-origin');
  const extra = document.getElementById('custom-origins');
  const notice = document.getElementById('origins-notice');
  const count = document.getElementById('origin-count');
  const save = document.getElementById('save-origins');
  const show = (message, type = 'success') => { notice.textContent = message; notice.className = `notice show ${type}`; };
  const parseList = (value) => [...new Set(String(value || '').split(/[\n,]+/).map((item) => item.trim()).filter(Boolean))];
  const renderCount = () => { const amount = 1 + parseList(extra.value).length; count.textContent = `${amount} / 11 origins configured`; };
  async function request(method, data) {
    const response = await fetch('/api/telemetry', { method, credentials: 'same-origin', cache: 'no-store', headers: data ? { 'Content-Type': 'application/json' } : {}, body: data ? JSON.stringify(data) : undefined });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || `Request failed (${response.status}).`);
    return result;
  }
  async function load() {
    try {
      const result = await request('GET');
      primary.value = result.project?.origin || '';
      const current = Array.isArray(result.project?.allowedOrigins) ? result.project.allowedOrigins : [];
      const primaryOrigin = result.project?.origin || current[0] || '';
      extra.value = current.filter((origin) => origin !== primaryOrigin).join(', ');
      renderCount();
    } catch (error) { show(error.message, 'error'); }
  }
  extra.addEventListener('input', renderCount);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    save.disabled = true; save.textContent = 'Saving…';
    try {
      const result = await request('POST', { action: 'origins', origin: primary.value.trim(), customOrigins: extra.value });
      primary.value = result.project.origin;
      extra.value = result.project.allowedOrigins.filter((origin) => origin !== result.project.origin).join(', ');
      renderCount(); show('Origins saved. Changes apply to the next browser telemetry request.', 'success');
      const heading = document.getElementById('project-origin');
      if (heading) heading.textContent = result.project.allowedOrigins.join(' · ');
    } catch (error) { show(error.message, 'error'); }
    finally { save.disabled = false; save.textContent = 'Save origins'; }
  });
  load();
})();
