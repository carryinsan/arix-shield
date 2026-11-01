const DEFAULT_MAX_BODY_BYTES = 32768;
const ABSOLUTE_MAX_BODY_BYTES = 262144;
const DEFAULT_MAX_LEAF_BYTES = 4096;
const MAX_NESTING_DEPTH = 24;
const MAX_NODES = 6000;
const STREAM_CHUNK_BYTES = 16 * 1024;
const STREAM_OVERLAP_BYTES = 512;

const NON_SQL_RULES = [
  { id: 'XSS_SCRIPT', category: 'XSS', severity: 'high', pattern: /<\s*script\b|javascript\s*:|\bon\w+\s*=\s*(?:['"]?\s*)?(?:alert|prompt|confirm)\s*\(/i },
  { id: 'XSS_HTML', category: 'XSS', severity: 'medium', pattern: /<\s*(?:iframe|object|embed|svg|math)\b[^>]*(?:onload|onerror|href|src)\s*=/i },
  { id: 'SSRF_METADATA', category: 'SSRF', severity: 'critical', pattern: /(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)/i },
  { id: 'SSRF_LOCAL', category: 'SSRF', severity: 'high', pattern: /(?:https?:\/\/)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::\d+)?/i },
  { id: 'PATH_TRAVERSAL', category: 'PATH_TRAVERSAL', severity: 'high', pattern: /(?:\.\.\/|\.\.\\|%2e%2e(?:%2f|%5c))/i },
  { id: 'COMMAND_INJECTION', category: 'COMMAND_INJECTION', severity: 'high', pattern: /(?:;\s*(?:cat|curl|wget|bash|sh|python|nc)\b|\$\([^)]*(?:curl|wget|bash|sh)|`[^`]*(?:curl|wget|bash|sh))/i },
  { id: 'PROMPT_INJECTION', category: 'PROMPT_INJECTION', severity: 'medium', pattern: /ignore\s+(?:all\s+)?previous\s+instructions|reveal\s+(?:the\s+)?system\s+prompt|developer\s+message\s*:/i }
];

const SQL_KEYWORDS = new Set([
  'SELECT', 'UNION', 'ALL', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'CREATE',
  'INTO', 'VALUES', 'JOIN', 'HAVING', 'ORDER', 'GROUP', 'BY', 'EXEC', 'EXECUTE', 'DECLARE', 'CAST',
  'CONVERT', 'WAITFOR', 'CURL', 'WGET', 'BASH', 'SH', 'POWERSHELL', 'XP_CMDSHELL'
]);
const SQL_OPERATORS = new Set(['OR', 'AND', 'NOT', '=', '!=', '<>', '<', '>', '<=', '>=', '||', '&&']);
const DANGEROUS_FUNCTIONS = new Set(['SLEEP', 'BENCHMARK', 'PG_SLEEP', 'DBMS_LOCK', 'CHAR', 'CHR', 'ASCII', 'EVAL', 'SYSTEM', 'Popen'.toUpperCase(), 'LOAD_FILE', 'INTO_OUTFILE']);
const BANNED_FINGERPRINTS = new Set(['SONONC', 'SOSOS', 'KKK', 'OFN', 'OKF']);
const SYMBOLS = new Set(["'", '"', ';', '(', ')', '{', '}', '$', '\\', '`', '<', '>', '=', '|', '&']);

function safeStringify(value) {
  try { return typeof value === 'string' ? value : JSON.stringify(value); }
  catch { return '[unserializable]'; }
}

function decodeHtmlEntities(input) {
  const named = { amp: '&', apos: "'", quot: '"', lt: '<', gt: '>', colon: ':', sol: '/', bsol: '\\', Tab: '\t', NewLine: '\n' };
  return input.replace(/&(#(?:x[0-9a-f]{1,6}|[0-9]{1,7})|[a-zA-Z][a-zA-Z0-9]+);?/g, (whole, entity) => {
    if (entity[0] === '#') {
      const hex = entity[1]?.toLowerCase() === 'x';
      const code = Number.parseInt(entity.slice(hex ? 2 : 1), hex ? 16 : 10);
      if (!Number.isInteger(code) || code < 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return whole;
      try { return String.fromCodePoint(code); } catch { return whole; }
    }
    return Object.hasOwn(named, entity) ? named[entity] : whole;
  });
}

function decodeLiteralEscapes(input) {
  return input
    .replace(/\\u\{([0-9a-f]{1,6})\}/gi, (whole, hex) => {
      const code = Number.parseInt(hex, 16);
      if (code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) return whole;
      try { return String.fromCodePoint(code); } catch { return whole; }
    })
    .replace(/\\u([0-9a-f]{4})/gi, (whole, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\x([0-9a-f]{2})/gi, (whole, hex) => String.fromCharCode(Number.parseInt(hex, 16)));
}

function normalizeOnePass(input) {
  let output = decodeLiteralEscapes(input);
  try { if (/%[0-9a-f]{2}/i.test(output)) output = decodeURIComponent(output.replace(/\+/g, '%2B')); } catch { /* Malformed percent escapes remain visible to inspection. */ }
  output = decodeHtmlEntities(output);
  // Preserve the content of MySQL executable comments; remove ordinary comments.
  output = output.replace(/\/\*!\s*\d*(.*?)\*\//gs, ' $1 ');
  output = output.replace(/\/\*[\s\S]*?\*\//g, ' ');
  // Flatten quoted-string concatenation without evaluating the input.
  for (let i = 0; i < 3; i++) {
    const next = output.replace(/(['"])([^'"\r\n]{1,128})\1\s*(?:\+|\|\|)\s*(['"])([^'"\r\n]{1,128})\3/g, (_m, _q1, left, _q2, right) => `'${left}${right}'`);
    if (next === output) break;
    output = next;
  }
  return output.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim();
}

/** Decode at most three layers. Still-changing input is suspicious, not silently truncated. */
export function canonicalizeSecurityText(value) {
  let current = String(value);
  for (let pass = 0; pass < 3; pass++) {
    const next = normalizeOnePass(current);
    if (next === current) return { value: current, passes: pass, excessiveEncoding: false };
    current = next;
  }
  return { value: current, passes: 3, excessiveEncoding: normalizeOnePass(current) !== current };
}

function tokenizeGrammar(input) {
  const tokens = [];
  const matcher = /--[^\n]*|#[^\n]*|\/\*[\s\S]*?\*\/|'(?:''|\\.|[^'])*'|"(?:""|\\.|[^"])*"|0x[0-9a-f]+|\b\d+(?:\.\d+)?\b|[a-z_][a-z0-9_$]*|!=|<>|<=|>=|\|\||&&|[=<>]|[^\s]/gi;
  let match;
  while ((match = matcher.exec(input)) !== null) {
    const raw = match[0];
    if (/^(?:--|#|\/\*)/.test(raw)) { tokens.push({ type: 'C', raw }); continue; }
    if (/^['"]/.test(raw)) { tokens.push({ type: 'S', raw }); continue; }
    if (/^(?:0x[0-9a-f]+|\d)/i.test(raw)) { tokens.push({ type: 'N', raw }); continue; }
    const upper = raw.toUpperCase();
    if (SQL_OPERATORS.has(upper)) { tokens.push({ type: 'O', raw: upper }); continue; }
    if (DANGEROUS_FUNCTIONS.has(upper)) { tokens.push({ type: 'F', raw: upper }); continue; }
    if (SQL_KEYWORDS.has(upper)) { tokens.push({ type: 'K', raw: upper }); continue; }
    // Identifiers followed by '(' are function-call tokens; only high-risk calls matter.
    if (/^[a-z_][a-z0-9_$]*$/i.test(raw) && input.slice(matcher.lastIndex).match(/^\s*\(/)) {
      tokens.push({ type: DANGEROUS_FUNCTIONS.has(upper) ? 'F' : 'I', raw: upper });
    } else tokens.push({ type: 'I', raw: upper });
  }
  return tokens;
}

function grammarFindings(value) {
  const tokens = tokenizeGrammar(value);
  const fingerprint = tokens.map((token) => token.type).join('');
  const findings = [];
  if ([...BANNED_FINGERPRINTS].some((pattern) => fingerprint.includes(pattern))) {
    findings.push({ id: 'SQLI_GRAMMAR', category: 'SQL_INJECTION', severity: 'high', detail: `Suspicious SQL/shell token grammar (${fingerprint.slice(0, 32)}).` });
  }
  const words = tokens.map((token) => token.raw);
  if (words.some((word, index) => word === 'UNION' && ['SELECT'].includes(words[index + 1]) || word === 'UNION' && words[index + 1] === 'ALL' && words[index + 2] === 'SELECT' || word === 'UN' && words[index + 1] === 'ION' && words[index + 2] === 'SELECT')) {
    findings.push({ id: 'SQLI_UNION', category: 'SQL_INJECTION', severity: 'high', detail: 'UNION-based SQL grammar detected.' });
  }
  if (tokens.some((token, index) => token.type === 'O' && ['OR', 'AND'].includes(token.raw) && tokens[index + 1]?.type === 'S' && tokens[index + 2]?.type === 'O' && tokens[index + 3]?.type === 'S')) {
    findings.push({ id: 'SQLI_BOOLEAN', category: 'SQL_INJECTION', severity: 'high', detail: 'Quoted boolean SQL expression detected.' });
  }
  if (tokens.some((token, index) => token.type === 'O' && ['OR', 'AND'].includes(token.raw) && tokens[index + 1]?.type === 'N' && tokens[index + 2]?.type === 'O' && tokens[index + 3]?.type === 'N')) {
    findings.push({ id: 'SQLI_BOOLEAN', category: 'SQL_INJECTION', severity: 'high', detail: 'Numeric boolean SQL expression detected.' });
  }
  if (tokens.some((token, index) => token.type === 'O' && ['OR', 'AND'].includes(token.raw) && tokens[index + 1]?.type === 'F')) {
    findings.push({ id: 'SQLI_TIME_FUNCTION', category: 'SQL_INJECTION', severity: 'high', detail: 'Conditional time-delay SQL function detected.' });
  }
  if (tokens.some((token) => token.type === 'C')) findings.push({ id: 'SQLI_COMMENT', category: 'SQL_INJECTION', severity: 'medium', detail: 'SQL or shell comment token detected.' });
  return findings;
}

function symbolDensityExceeded(value) {
  const windowSize = 50;
  if (value.length < windowSize) return false;
  let symbols = 0;
  for (let index = 0; index < windowSize; index++) if (SYMBOLS.has(value[index])) symbols++;
  if (symbols > windowSize * 0.2) return true;
  for (let index = windowSize; index < value.length; index++) {
    if (SYMBOLS.has(value[index - windowSize])) symbols--;
    if (SYMBOLS.has(value[index])) symbols++;
    if (symbols > windowSize * 0.2) return true;
  }
  return false;
}

function inspectStructure(value, options, state, path = '$', depth = 0, add) {
  state.nodes++;
  if (depth > MAX_NESTING_DEPTH) { state.tooDeep = true; return; }
  if (state.nodes > MAX_NODES) { state.tooMany = true; return; }
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'string') {
      const bytes = new TextEncoder().encode(value).length;
      const allowedLong = Array.isArray(options.allowedLongFields) && options.allowedLongFields.some((name) => path === name || path.endsWith(`.${name}`));
      if (bytes > options.maxLeafBytes && !allowedLong) add('BODY_LEAF_SIZE', 'PROTOCOL', 'high', `String leaf at ${path.slice(0, 80)} exceeds ${options.maxLeafBytes} bytes.`);
      const canonical = canonicalizeSecurityText(value);
      if (canonical.excessiveEncoding) add('NESTED_ENCODING', 'PROTOCOL', 'high', `Repeated encoding did not reach a canonical form at ${path.slice(0, 80)}.`);
      const text = canonical.value;
      for (const rule of NON_SQL_RULES) if (rule.pattern.test(text)) add(rule.id, rule.category, rule.severity, `Matched ${rule.category.toLowerCase().replaceAll('_', ' ')} heuristic at ${path.slice(0, 80)}.`);
      for (const finding of scanTextInChunks(text)) add(finding.id, finding.category, finding.severity, `${finding.detail} Field: ${path.slice(0, 60)}.`);
      if (symbolDensityExceeded(text)) add('SYMBOL_DENSITY', 'PROTOCOL', 'medium', `High structural-symbol density in a 50-character window at ${path.slice(0, 80)}.`);
      if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) add('CONTROL_CHARACTERS', 'PROTOCOL', 'medium', `Control characters detected at ${path.slice(0, 80)}.`);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length && !state.tooDeep && !state.tooMany; index++) inspectStructure(value[index], options, state, `${path}[${index}]`, depth + 1, add);
    return;
  }
  for (const key of Object.keys(value)) {
    const lower = key.toLowerCase();
    if (key.startsWith('$')) add('NOSQL_OPERATOR', 'NOSQL_INJECTION', 'high', `NoSQL operator key detected at ${path.slice(0, 60)}.${key.slice(0, 60)}.`);
    if (key.includes('.')) add('DOTTED_OBJECT_KEY', 'NOSQL_INJECTION', 'high', `Dotted object key detected at ${path.slice(0, 60)}.${key.slice(0, 60)}.`);
    if (['__proto__', 'constructor', 'prototype'].includes(lower)) add('PROTOTYPE_POLLUTION', 'PROTOTYPE_POLLUTION', 'critical', `Prototype-pollution key detected at ${path.slice(0, 60)}.${key.slice(0, 60)}.`);
    inspectStructure(value[key], options, state, `${path}.${key}`, depth + 1, add);
    if (state.tooDeep || state.tooMany) break;
  }
}

/** Scan a byte/string stream in bounded chunks with overlap so boundary-spanning payloads are not lost. */
export function scanTextInChunks(input, scan = (chunk) => grammarFindings(canonicalizeSecurityText(chunk).value), options = {}) {
  const text = String(input ?? '');
  const chunkSize = Math.max(1024, Math.min(64 * 1024, Number(options.chunkBytes) || STREAM_CHUNK_BYTES));
  const overlap = Math.max(64, Math.min(4096, Number(options.overlapBytes) || STREAM_OVERLAP_BYTES));
  const findings = [];
  let tail = '';
  for (let offset = 0; offset < text.length; offset += chunkSize) {
    const chunk = tail + text.slice(offset, offset + chunkSize);
    findings.push(...scan(chunk));
    tail = chunk.slice(-overlap);
  }
  return findings;
}

export function inspectRequest({ method = 'GET', url = '/', headers = {}, body = null, contentLength = 0, maxBodyBytes = DEFAULT_MAX_BODY_BYTES, maxLeafBytes = DEFAULT_MAX_LEAF_BYTES, allowedLongFields = [] } = {}) {
  const findings = [];
  const seen = new Set();
  const add = (id, category, severity, detail) => {
    const safeDetail = String(detail).slice(0, 180);
    const key = `${id}:${safeDetail}`;
    if (!seen.has(key)) { seen.add(key); findings.push({ id, category, severity, detail: safeDetail }); }
  };
  const methodUpper = String(method).toUpperCase();
  const headerEntries = headers instanceof Headers ? [...headers.entries()] : Object.entries(headers ?? {});
  const normalizedHeaders = Object.fromEntries(headerEntries.map(([key, value]) => [String(key).toLowerCase(), String(value)]));
  const bodyText = safeStringify(body);
  const bytes = new TextEncoder().encode(bodyText === 'null' ? '' : bodyText).length;
  const declaredBytes = Number(contentLength) || 0;
  const configuredMax = Math.max(1024, Math.min(ABSOLUTE_MAX_BODY_BYTES, Number(maxBodyBytes) || DEFAULT_MAX_BODY_BYTES));
  if (declaredBytes > configuredMax || bytes > configuredMax) add('BODY_SIZE', 'PROTOCOL', 'high', `Request body exceeds the configured ${configuredMax}-byte inspection limit.`);
  if (normalizedHeaders['x-http-method-override'] || normalizedHeaders['x-method-override']) add('METHOD_OVERRIDE', 'PROTOCOL', 'medium', 'HTTP method override headers are not accepted by default.');
  if (/\0|%00/i.test(String(url))) add('NULL_BYTE', 'PROTOCOL', 'high', 'Null byte detected in request URL.');
  const contentType = normalizedHeaders['content-type'] ?? '';
  const hasPayload = declaredBytes > 0 || (body != null && bodyText !== 'null' && bytes > 2);
  if (hasPayload && !['GET', 'HEAD', 'OPTIONS'].includes(methodUpper)) {
    if (!contentType || !/(?:application\/json|application\/x-www-form-urlencoded|multipart\/form-data|text\/plain|application\/octet-stream)/i.test(contentType)) add('CONTENT_TYPE', 'PROTOCOL', 'medium', 'Missing or unexpected content type for a body-bearing request.');
    else if (/application\/json/i.test(contentType) && typeof body === 'string') add('JSON_PARSE', 'PROTOCOL', 'high', 'JSON content type was received but the body was not valid parsed JSON.');
  }
  try { new URL(String(url), 'https://arixshield.invalid'); } catch { add('URL_PARSE', 'PROTOCOL', 'high', 'Malformed request URL.'); }
  const excludedHeaders = new Set(['cookie', 'authorization', 'x-arix-secret', 'x-arix-server-key', 'x-arix-key']);
  const headerText = headerEntries.filter(([key]) => !excludedHeaders.has(String(key).toLowerCase())).map(([key, value]) => `${key}:${String(value).slice(0, 1000)}`).join('\n');
  const urlText = canonicalizeSecurityText(String(url));
  for (const rule of NON_SQL_RULES) {
    if (rule.pattern.test(urlText.value) || rule.pattern.test(headerText)) add(rule.id, rule.category, rule.severity, `Matched ${rule.category.toLowerCase().replaceAll('_', ' ')} heuristic in request metadata.`);
  }
  for (const finding of grammarFindings(urlText.value + '\n' + headerText)) add(finding.id, finding.category, finding.severity, finding.detail);
  if (body && typeof body === 'object') {
    const state = { nodes: 0, tooDeep: false, tooMany: false };
    inspectStructure(body, { maxLeafBytes: Math.max(128, Math.min(65536, Number(maxLeafBytes) || DEFAULT_MAX_LEAF_BYTES)), allowedLongFields }, state, '$', 0, add);
    if (state.tooDeep) add('JSON_DEPTH', 'PROTOCOL', 'high', `JSON nesting exceeds ${MAX_NESTING_DEPTH} levels.`);
    if (state.tooMany) add('JSON_NODES', 'PROTOCOL', 'high', `JSON object exceeds ${MAX_NODES} nodes.`);
  } else if (typeof body === 'string' && body !== '') {
    const canonical = canonicalizeSecurityText(body);
    if (canonical.excessiveEncoding) add('NESTED_ENCODING', 'PROTOCOL', 'high', 'Repeated encoding did not reach a canonical form.');
    for (const rule of NON_SQL_RULES) if (rule.pattern.test(canonical.value)) add(rule.id, rule.category, rule.severity, `Matched ${rule.category.toLowerCase().replaceAll('_', ' ')} heuristic.`);
    for (const finding of scanTextInChunks(canonical.value)) add(finding.id, finding.category, finding.severity, finding.detail);
  }
  const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
  findings.sort((a, b) => (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0));
  return { allowed: findings.length === 0, findings, riskScore: Math.min(100, findings.reduce((score, item) => score + (severityRank[item.severity] ?? 1) * 17, 0)), inspectedBytes: bytes, maxBodyBytes: configuredMax };
}

export function validateJsonSchema(value, schema, path = '$', depth = 0) {
  const errors = [];
  if (!schema || typeof schema !== 'object' || Array.isArray(schema) || depth > MAX_NESTING_DEPTH) return { valid: false, errors: [`${path}: invalid schema or excessive schema depth`] };
  const actual = Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value;
  const expected = Array.isArray(schema.type) ? schema.type : schema.type ? [schema.type] : [];
  const normalized = actual === 'number' && Number.isInteger(value) && expected.includes('integer') ? 'integer' : actual;
  if (expected.length && !expected.includes(actual) && !expected.includes(normalized)) errors.push(`${path}: expected ${expected.join('|')}, got ${actual}`);
  if (Object.hasOwn(schema, 'const') && JSON.stringify(value) !== JSON.stringify(schema.const)) errors.push(`${path}: does not match const`);
  if (Array.isArray(schema.enum) && !schema.enum.some((candidate) => JSON.stringify(candidate) === JSON.stringify(value))) errors.push(`${path}: value is not in enum`);
  if (typeof value === 'string') {
    if (Number.isFinite(schema.minLength) && value.length < schema.minLength) errors.push(`${path}: shorter than minLength`);
    if (Number.isFinite(schema.maxLength) && value.length > schema.maxLength) errors.push(`${path}: longer than maxLength`);
    if (schema.pattern) { try { if (!new RegExp(schema.pattern).test(value)) errors.push(`${path}: pattern mismatch`); } catch { errors.push(`${path}: invalid schema pattern`); } }
    if (schema.format === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) errors.push(`${path}: invalid email format`);
    if (schema.format === 'uuid' && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) errors.push(`${path}: invalid UUID format`);
    if (schema.format === 'date-time' && !/^\d{4}-\d{2}-\d{2}T/.test(value) || (schema.format === 'date-time' && !Number.isFinite(Date.parse(value)))) errors.push(`${path}: invalid date-time format`);
    if (schema.format === 'uri') { try { new URL(value); } catch { errors.push(`${path}: invalid URI format`); } }
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    if (Number.isFinite(schema.minimum) && value < schema.minimum) errors.push(`${path}: below minimum`);
    if (Number.isFinite(schema.maximum) && value > schema.maximum) errors.push(`${path}: above maximum`);
    if (Number.isFinite(schema.exclusiveMinimum) && value <= schema.exclusiveMinimum) errors.push(`${path}: below exclusiveMinimum`);
    if (Number.isFinite(schema.exclusiveMaximum) && value >= schema.exclusiveMaximum) errors.push(`${path}: above exclusiveMaximum`);
    if (Number.isFinite(schema.multipleOf) && schema.multipleOf > 0 && Math.abs(value / schema.multipleOf - Math.round(value / schema.multipleOf)) > 1e-10) errors.push(`${path}: is not a multiple of ${schema.multipleOf}`);
  }
  if (Array.isArray(value)) {
    if (Number.isFinite(schema.minItems) && value.length < schema.minItems) errors.push(`${path}: fewer than minItems`);
    if (Number.isFinite(schema.maxItems) && value.length > schema.maxItems) errors.push(`${path}: more than maxItems`);
    if (schema.uniqueItems === true) { const serialized = value.map((item) => JSON.stringify(item)); if (new Set(serialized).size !== serialized.length) errors.push(`${path}: array items must be unique`); }
    if (schema.items) value.slice(0, 1000).forEach((item, index) => errors.push(...validateJsonSchema(item, schema.items, `${path}[${index}]`, depth + 1).errors));
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const keys = Object.keys(value);
    if (Number.isFinite(schema.minProperties) && keys.length < schema.minProperties) errors.push(`${path}: fewer than minProperties`);
    if (Number.isFinite(schema.maxProperties) && keys.length > schema.maxProperties) errors.push(`${path}: more than maxProperties`);
    for (const required of schema.required ?? []) if (!Object.hasOwn(value, required)) errors.push(`${path}.${required}: required`);
    const properties = schema.properties ?? {};
    for (const [key, child] of Object.entries(value)) {
      if (Object.hasOwn(properties, key)) errors.push(...validateJsonSchema(child, properties[key], `${path}.${key}`, depth + 1).errors);
      else if (schema.additionalProperties === false) errors.push(`${path}.${key}: additional property not allowed`);
      else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') errors.push(...validateJsonSchema(child, schema.additionalProperties, `${path}.${key}`, depth + 1).errors);
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
  { type: 'US_SSN', regex: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  { type: 'CARD_CANDIDATE', regex: /\b(?:\d[ -]*?){13,19}\b/g }
];
function isLuhnCandidate(value) {
  const digits = value.replace(/\D/g, ''); if (digits.length < 13 || digits.length > 19 || /^0+$/.test(digits)) return false; let sum = 0; let doubleDigit = false;
  for (let i = digits.length - 1; i >= 0; i--) { let n = Number(digits[i]); if (doubleDigit) { n *= 2; if (n > 9) n -= 9; } sum += n; doubleDigit = !doubleDigit; }
  return sum % 10 === 0;
}
export function redactSensitiveText(input) {
  let output = String(input); const detected = [];
  for (const item of SECRET_PATTERNS) output = output.replace(item.regex, (match) => { if (item.type !== 'CARD_CANDIDATE' || isLuhnCandidate(match)) { detected.push(item.type); return `[REDACTED_${item.type}]`; } return match; });
  return { text: output, detected: [...new Set(detected)] };
}
export function getDataBytes(value) { return new TextEncoder().encode(safeStringify(value)).length; }
