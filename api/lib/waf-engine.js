const MAX_BODY_BYTES = 32768;
const MAX_NESTING_DEPTH = 24;
const MAX_NODES = 6000;

const RULES = [
  { id: 'SQLI_UNION', category: 'SQL_INJECTION', severity: 'high', pattern: /\bunion\s+(?:all\s+)?select\b|\bselect\b[\s\S]{0,80}\bfrom\b[\s\S]{0,80}\bwhere\b/i },
  { id: 'SQLI_BOOLEAN', category: 'SQL_INJECTION', severity: 'high', pattern: /(?:'|\")\s*(?:or|and)\s+\d+\s*=\s*\d+|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1/i },
  { id: 'SQLI_COMMENT', category: 'SQL_INJECTION', severity: 'medium', pattern: /(?:--\s|#\s|\/\*[\s\S]*?\*\/)/ },
  { id: 'XSS_SCRIPT', category: 'XSS', severity: 'high', pattern: /<\s*script\b|javascript\s*:|\bon\w+\s*=\s*(?:['\"]?\s*)?(?:alert|prompt|confirm)\s*\(/i },
  { id: 'XSS_HTML', category: 'XSS', severity: 'medium', pattern: /<\s*(?:iframe|object|embed|svg|math)\b[^>]*(?:onload|onerror|href|src)\s*=/i },
  { id: 'SSRF_METADATA', category: 'SSRF', severity: 'critical', pattern: /(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)/i },
  { id: 'SSRF_LOCAL', category: 'SSRF', severity: 'high', pattern: /(?:https?:\/\/)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::\d+)?/i },
  { id: 'PATH_TRAVERSAL', category: 'PATH_TRAVERSAL', severity: 'high', pattern: /(?:\.\.\/|\.\.\\|%2e%2e(?:%2f|%5c))/i },
  { id: 'NOSQL_OPERATOR', category: 'NOSQL_INJECTION', severity: 'high', pattern: /["']?\$(?:gt|gte|lt|lte|ne|nin|where|regex|function)["']?\s*:/i },
  { id: 'COMMAND_INJECTION', category: 'COMMAND_INJECTION', severity: 'high', pattern: /(?:;\s*(?:cat|curl|wget|bash|sh|python|nc)\b|\$\([^)]*(?:curl|wget|bash|sh)|`[^`]*(?:curl|wget|bash|sh))/i },
  { id: 'PROMPT_INJECTION', category: 'PROMPT_INJECTION', severity: 'medium', pattern: /ignore\s+(?:all\s+)?previous\s+instructions|reveal\s+(?:the\s+)?system\s+prompt|developer\s+message\s*:/i }
];

function safeStringify(value) {
  try { return typeof value === 'string' ? value : JSON.stringify(value); }
  catch { return '[unserializable]'; }
}

function walkDepth(value, depth = 0, state = { nodes: 0, tooDeep: false, tooMany: false }) {
  state.nodes++;
  if (depth > MAX_NESTING_DEPTH) state.tooDeep = true;
  if (state.nodes > MAX_NODES) state.tooMany = true;
  if (state.tooDeep || state.tooMany || value === null || typeof value !== 'object') return state;
  const children = Array.isArray(value) ? value : Object.values(value);
  for (const child of children) {
    walkDepth(child, depth + 1, state);
    if (state.tooDeep || state.tooMany) break;
  }
  return state;
}

function detectSequentialIds(url) {
  const matches = [...String(url).matchAll(/(?:^|\/)(\d{3,})(?=\/|\?|$)/g)].map((m) => Number(m[1]));
  for (let i = 1; i < matches.length; i++) {
    if (matches[i] - matches[i - 1] === 1) return true;
  }
  return matches.length >= 4 && Math.max(...matches) - Math.min(...matches) <= matches.length * 2;
}

export function inspectRequest({ method = 'GET', url = '/', headers = {}, body = null, contentLength = 0 } = {}) {
  const findings = [];
  const add = (id, category, severity, detail) => findings.push({ id, category, severity, detail: String(detail).slice(0, 180) });
  const methodUpper = String(method).toUpperCase();
  const headerEntries = headers instanceof Headers ? [...headers.entries()] : Object.entries(headers ?? {});
  const normalizedHeaders = Object.fromEntries(headerEntries.map(([k, v]) => [String(k).toLowerCase(), String(v)]));
  const bodyText = safeStringify(body);
  const bytes = new TextEncoder().encode(bodyText === 'null' ? '' : bodyText).length;
  const declaredBytes = Number(contentLength) || 0;

  if (declaredBytes > MAX_BODY_BYTES || bytes > MAX_BODY_BYTES) add('BODY_SIZE', 'PROTOCOL', 'high', 'Request body exceeds the configured 32 KiB inspection limit.');
  if (normalizedHeaders['x-http-method-override'] || normalizedHeaders['x-method-override']) add('METHOD_OVERRIDE', 'PROTOCOL', 'medium', 'HTTP method override headers are not accepted by default.');
  if (/\0|%00/i.test(String(url)) || /\0/.test(bodyText)) add('NULL_BYTE', 'PROTOCOL', 'high', 'Null byte detected in request data.');
  const contentType = normalizedHeaders['content-type'] ?? '';
  if (body != null && !['GET', 'HEAD', 'OPTIONS'].includes(methodUpper) && bodyText !== 'null' && contentType && !/(?:application\/json|application\/x-www-form-urlencoded|multipart\/form-data|text\/plain)/i.test(contentType)) {
    add('CONTENT_TYPE', 'PROTOCOL', 'medium', 'Unexpected content type for a body-bearing request.');
  }

  let parsedUrl;
  try { parsedUrl = new URL(String(url), 'https://arixshield.invalid'); }
  catch { add('URL_PARSE', 'PROTOCOL', 'high', 'Malformed request URL.'); }
  const inspectText = [
    String(url),
    ...headerEntries.filter(([k]) => !['cookie', 'authorization', 'x-arix-secret'].includes(String(k).toLowerCase())).map(([k, v]) => `${k}:${String(v).slice(0, 1000)}`),
    bodyText.slice(0, MAX_BODY_BYTES)
  ].join('\n');

  for (const rule of RULES) {
    if (rule.pattern.test(inspectText)) add(rule.id, rule.category, rule.severity, `Matched ${rule.category.toLowerCase().replaceAll('_', ' ')} heuristic.`);
  }
  if (parsedUrl && detectSequentialIds(parsedUrl.pathname)) add('BOLA_SEQUENCE_HEURISTIC', 'BOLA_HEURISTIC', 'medium', 'Sequential numeric resource identifiers detected; confirm authorization in the application layer.');

  if (body && typeof body === 'object') {
    const depth = walkDepth(body);
    if (depth.tooDeep) add('JSON_DEPTH', 'PROTOCOL', 'high', `JSON nesting exceeds ${MAX_NESTING_DEPTH} levels.`);
    if (depth.tooMany) add('JSON_NODES', 'PROTOCOL', 'high', `JSON object exceeds ${MAX_NODES} nodes.`);
  }

  const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
  findings.sort((a, b) => (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0));
  return {
    allowed: findings.length === 0,
    findings,
    riskScore: Math.min(100, findings.reduce((score, item) => score + (severityRank[item.severity] ?? 1) * 17, 0)),
    inspectedBytes: bytes
  };
}

export function validateJsonSchema(value, schema, path = '$', depth = 0) {
  const errors = [];
  if (!schema || typeof schema !== 'object' || depth > MAX_NESTING_DEPTH) return { valid: false, errors: [`${path}: invalid schema or excessive schema depth`] };
  const type = schema.type;
  const actual = Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value;
  const expected = Array.isArray(type) ? type : type ? [type] : [];
  const normalized = actual === 'number' && Number.isInteger(value) && expected.includes('integer') ? 'integer' : actual;
  if (expected.length && !expected.includes(actual) && !expected.includes(normalized)) errors.push(`${path}: expected ${expected.join('|')}, got ${actual}`);
  if (typeof value === 'string') {
    if (Number.isFinite(schema.minLength) && value.length < schema.minLength) errors.push(`${path}: shorter than minLength`);
    if (Number.isFinite(schema.maxLength) && value.length > schema.maxLength) errors.push(`${path}: longer than maxLength`);
    if (schema.pattern) {
      try { if (!new RegExp(schema.pattern).test(value)) errors.push(`${path}: pattern mismatch`); }
      catch { errors.push(`${path}: invalid schema pattern`); }
    }
  }
  if (typeof value === 'number') {
    if (Number.isFinite(schema.minimum) && value < schema.minimum) errors.push(`${path}: below minimum`);
    if (Number.isFinite(schema.maximum) && value > schema.maximum) errors.push(`${path}: above maximum`);
  }
  if (Array.isArray(value)) {
    if (Number.isFinite(schema.minItems) && value.length < schema.minItems) errors.push(`${path}: fewer than minItems`);
    if (Number.isFinite(schema.maxItems) && value.length > schema.maxItems) errors.push(`${path}: more than maxItems`);
    if (schema.items) value.slice(0, 1000).forEach((item, index) => errors.push(...validateJsonSchema(item, schema.items, `${path}[${index}]`, depth + 1).errors));
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const required of schema.required ?? []) if (!Object.hasOwn(value, required)) errors.push(`${path}.${required}: required`);
    const properties = schema.properties ?? {};
    for (const [key, child] of Object.entries(value)) {
      if (!Object.hasOwn(properties, key) && schema.additionalProperties === false) errors.push(`${path}.${key}: additional property not allowed`);
      else if (Object.hasOwn(properties, key)) errors.push(...validateJsonSchema(child, properties[key], `${path}.${key}`, depth + 1).errors);
    }
  }
  return { valid: errors.length === 0, errors: errors.slice(0, 100) };
}

const SECRET_PATTERNS = [
  { type: 'AWS_ACCESS_KEY', regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { type: 'STRIPE_SECRET', regex: /\bsk_live_[0-9A-Za-z]{16,}\b/g },
  { type: 'PRIVATE_KEY', regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { type: 'JWT', regex: /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g },
  { type: 'EMAIL', regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi },
  { type: 'CARD_CANDIDATE', regex: /\b(?:\d[ -]*?){13,19}\b/g }
];

function isLuhnCandidate(value) {
  const digits = value.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19 || /^0+$/.test(digits)) return false;
  let sum = 0;
  let doubleDigit = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = Number(digits[i]);
    if (doubleDigit) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    doubleDigit = !doubleDigit;
  }
  return sum % 10 === 0;
}

export function redactSensitiveText(input) {
  let output = String(input);
  const detected = [];
  for (const item of SECRET_PATTERNS) {
    output = output.replace(item.regex, (match) => {
      if (item.type !== 'CARD_CANDIDATE' || isLuhnCandidate(match)) {
        detected.push(item.type);
        return `[REDACTED_${item.type}]`;
      }
      return match;
    });
  }
  return { text: output, detected: [...new Set(detected)] };
}

export function getDataBytes(value) {
  return new TextEncoder().encode(safeStringify(value)).length;
}
