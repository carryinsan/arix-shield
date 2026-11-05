const DEFAULT_MAX_BODY_BYTES = 32768;
const ABSOLUTE_MAX_BODY_BYTES = 262144;
const DEFAULT_MAX_LEAF_BYTES = 4096;
const MAX_NESTING_DEPTH = 24;
const MAX_NODES = 6000;
const STREAM_CHUNK_BYTES = 64 * 1024;
const STREAM_OVERLAP_BYTES = 512;

const NON_SQL_RULES = [
  { id: 'XSS_SCRIPT', category: 'XSS', severity: 'high', pattern: /<\s*script\b|javascript\s*:|\bon\w+\s*=\s*(?:['"]?\s*)?(?:alert|prompt|confirm)\s*\(/i },
  { id: 'XSS_HTML', category: 'XSS', severity: 'medium', pattern: /<\s*(?:iframe|object|embed|svg|math)\b[^>]*(?:onload|onerror|href|src)\s*=/i },
  { id: 'PATH_TRAVERSAL', category: 'PATH_TRAVERSAL', severity: 'high', pattern: /(?:\.\.\/|\.\.\\|%2e%2e(?:%2f|%5c))/i },
  { id: 'COMMAND_INJECTION', category: 'COMMAND_INJECTION', severity: 'high', pattern: /(?:;\s*(?:cat|curl|wget|bash|sh|python|nc)\b|\$\([^)]*(?:curl|wget|bash|sh)|`[^`]*(?:curl|wget|bash|sh))/i },
  { id: 'PROMPT_INJECTION', category: 'PROMPT_INJECTION', severity: 'medium', pattern: /ignore\s+(?:all\s+)?previous\s+instructions|reveal\s+(?:the\s+)?system\s+prompt|developer\s+message\s*:/i },
  { id: 'LDAP_INJECTION', category: 'LDAP_INJECTION', severity: 'high', pattern: /(?:\)\s*\(\s*[|&]|\\(?:2a|28|29|5c|00)|\*\)\s*\()/i },
  { id: 'SSTI_TEMPLATE', category: 'SSTI', severity: 'high', pattern: /(?:\{\{[^}]{0,160}(?:__|config|self|request|cycler|joiner|lipsum|namespace|class|mro)[^}]*\}\}|\$\{[^}]{0,160}(?:process|runtime|environment|env|class|mro)[^}]*\}|<%[\s\S]{0,160}(?:=|include|exec|process)[\s\S]{0,80}%>|__class__\s*\.\s*__mro__|#\{[^}]{0,128}(?:system|runtime|class)[^}]*\})/i },
  { id: 'UNSAFE_DESERIALIZATION', category: 'UNSAFE_DESERIALIZATION', severity: 'critical', pattern: /(?:rO0AB[A-Za-z0-9+/=]{8,}|\\xac\\xed\\x00\\x05|\u00ac\u00ed\x00\x05|O:\d{1,3}:"[^"]+"|C:\d{1,3}:"[^"]+"|__reduce__|c__builtin__|_\$\$ND_FUNC\$_\$)/i }
];

const SQL_KEYWORDS = new Set([
  'SELECT', 'UNION', 'ALL', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'CREATE',
  'INTO', 'VALUES', 'JOIN', 'HAVING', 'ORDER', 'GROUP', 'BY', 'EXEC', 'EXECUTE', 'DECLARE', 'CAST',
  'CONVERT', 'WAITFOR', 'CURL', 'WGET', 'BASH', 'SH', 'POWERSHELL', 'XP_CMDSHELL'
]);
const SQL_OPERATORS = new Set(['OR', 'AND', 'NOT', '=', '!=', '<>', '<', '>', '<=', '>=', '||', '&&']);
const DANGEROUS_FUNCTIONS = new Set(['SLEEP', 'BENCHMARK', 'PG_SLEEP', 'DBMS_LOCK', 'CHAR', 'CHR', 'ASCII', 'EVAL', 'SYSTEM', 'Popen'.toUpperCase(), 'LOAD_FILE', 'INTO_OUTFILE']);
const BANNED_FINGERPRINTS = new Set(['SONONC', 'SOSOS', 'KKK', 'OFN', 'OKF']);
function mayContainSqlGrammar(input) {
  const text = String(input);
  if (SQL_GRAMMAR_PUNCTUATION.test(text)) return true;
  SQL_GRAMMAR_WORDS.lastIndex = 0;
  let match;
  while ((match = SQL_GRAMMAR_WORDS.exec(text)) !== null) {
    // Every recognized SQL keyword/function is at most 12 characters. Avoid
    // allocating a full uppercase copy when an attacker submits a huge
    // unbroken identifier (common in maximum-body performance probes).
    if (match[0].length > 16) continue;
    const token = match[0].toUpperCase();
    if (SQL_KEYWORDS.has(token) || SQL_OPERATORS.has(token) || DANGEROUS_FUNCTIONS.has(token)) return true;
  }
  return false;
}
const SYMBOLS = new Set(["'", '"', ';', '(', ')', '{', '}', '$', '\\', '`', '<', '>', '=', '|', '&']);
const SQL_GRAMMAR_PUNCTUATION = /['"`;=<>!|]|--|#|\/\*/;
const SQL_GRAMMAR_WORDS = /[a-z_][a-z0-9_$]*/gi;
const NON_SQL_CANDIDATE_NEEDLES = Object.freeze({
  XSS_SCRIPT: ['script', 'javascript', 'on'],
  XSS_HTML: ['<iframe', '<object', '<embed', '<svg', '<math', '< iframe', '< object', '< embed', '< svg', '< math'],
  PATH_TRAVERSAL: ['..', '%2e'],
  COMMAND_INJECTION: [';', '$(', '`'],
  PROMPT_INJECTION: ['ignore', 'reveal', 'developer'],
  LDAP_INJECTION: [')(|', ')(&', ') (|', ') (&', '\\2a', '\\28', '\\29', '\\5c', '\\00', '*)(', '*) ('],
  SSTI_TEMPLATE: ['{{', '${', '<%', '__class__', '#{'],
  UNSAFE_DESERIALIZATION: ['ro0ab', '\\xac\\xed', '¬í', 'o:', 'c:', '__reduce__', 'c__builtin__', '_$$nd_func']
});

const OPAQUE_FIELD_LIMITS = new Map([
  ['password', 256], ['currentpassword', 256], ['newpassword', 256], ['oldpassword', 256],
  ['token', 4096], ['signature', 4096], ['codeverifier', 4096], ['powtoken', 8192],
  ['clearancejwe', 32768], ['hash', 512], ['passwordhash', 512], ['totpsecret', 256]
]);
const DEFAULT_RICH_TEXT_FIELDS = new Set(['content', 'prompt', 'message', 'bio', 'comment', 'markdown', 'description', 'notes', 'text']);

// SSRF is a destination/use-context issue, not a substring issue. Only fields
// that carry a server-side destination are evaluated by the SSRF detector;
// ordinary prose, chat messages, documentation, identifiers and unrelated
// headers are never classified as SSRF merely for mentioning a private host.
const SSRF_DESTINATION_FIELDS = new Set([
  'url', 'uri', 'urls', 'uris', 'target', 'targeturl', 'targeturi',
  'destination', 'destinationurl', 'destinationuri', 'endpoint', 'endpointurl',
  'fetch', 'fetchurl', 'requesturl', 'sourceurl', 'remoteurl', 'upstreamurl',
  'proxyurl', 'imageurl', 'avatarurl', 'importurl', 'downloadurl',
  'webhook', 'webhookurl', 'callback', 'callbackurl', 'redirect', 'redirecturl',
  'redirecturi', 'resourceurl', 'feedurl', 'rssurl', 'originurl',
  'host', 'hostname', 'ip'
]);
const SSRF_URI_CANDIDATE = /(?:[a-z][a-z0-9+.-]{0,31}:)?\/\/[^\s\"'<>]+/gi;

function normalizedFieldName(name) {
  return String(name).toLowerCase().replace(/[^a-z0-9]/g, '');
}

function isSsrfDestinationField(nameOrPath) {
  const fieldName = normalizedFieldName(fieldNameFromPath(nameOrPath));
  return SSRF_DESTINATION_FIELDS.has(fieldName);
}

function ssrfFindingForDestination(input) {
  const canonical = canonicalizeSecurityText(input).value;
  if (!canonical || canonical.length > ABSOLUTE_MAX_BODY_BYTES) return null;

  const candidates = [canonical.trim()];
  // Also inspect embedded URI candidates. This catches nested redirect targets
  // without scanning arbitrary prose fields for IP/hostname substrings.
  SSRF_URI_CANDIDATE.lastIndex = 0;
  let match;
  while ((match = SSRF_URI_CANDIDATE.exec(canonical)) !== null) candidates.push(match[0]);

  for (const rawCandidate of candidates) {
    const candidate = rawCandidate.replace(/[),.;!?]+$/g, '');
    if (!candidate) continue;
    let parsed;
    try {
      parsed = candidate.startsWith('//') ? new URL(`https:${candidate}`) : new URL(candidate);
      if (!parsed.hostname && !/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)) parsed = new URL(`https://${candidate}`);
    } catch {
      // A bare host/IP is a valid destination value even without a scheme.
      if (/^[^\s\/\\?#@]+(?::\d+)?(?:[\/?#].*)?$/.test(candidate)) {
        try { parsed = new URL(`https://${candidate}`); } catch { parsed = null; }
      }
    }
    const hostname = String(parsed?.hostname || '').toLowerCase().replace(/\.$/, '');
    if (!hostname) continue;
    if (hostname === '169.254.169.254' || hostname === 'metadata.google.internal' || hostname === '100.100.100.200') {
      return { id: 'SSRF_METADATA', category: 'SSRF', severity: 'critical', detail: 'Server-side destination resolves to a cloud metadata endpoint.' };
    }
    if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '127.0.0.1' || hostname === '0.0.0.0' || hostname === '[::1]') {
      return { id: 'SSRF_LOCAL', category: 'SSRF', severity: 'high', detail: 'Server-side destination targets a loopback or localhost address.' };
    }
  }
  return null;
}

function addSsrfDestinationFinding(value, add, context) {
  const finding = ssrfFindingForDestination(value);
  if (finding) add(finding.id, finding.category, finding.severity, `${finding.detail} ${context}`);
}

function fieldNameFromPath(path) {
  const segments = String(path).replace(/\[(?:\d+)\]/g, '').split('.');
  return String(segments.at(-1) || '').toLowerCase();
}

function matchingNonSqlRuleFindings(input) {
  const text = String(input);
  const lower = text.toLowerCase();
  const findings = [];
  for (const rule of NON_SQL_RULES) {
    const needles = NON_SQL_CANDIDATE_NEEDLES[rule.id];
    if (needles && !needles.some((needle) => lower.includes(needle))) continue;
    if (rule.pattern.test(text)) findings.push({ id: rule.id, category: rule.category, severity: rule.severity, detail: `Matched ${rule.category.toLowerCase().replaceAll('_', ' ')} heuristic.` });
  }
  return findings;
}

function scanNonSqlTextInChunks(input) {
  // Callers pass canonicalized text already; avoid decoding every chunk again.
  return scanTextInChunks(input, matchingNonSqlRuleFindings);
}

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
  let output = input.normalize('NFKC');
  let needsRenormalize = false;

  // Large ordinary text bodies are common. One quick sentinel scan avoids
  // several full-buffer includes/regex passes when there is no encoding,
  // entity, comment, quote-concatenation or delimiter syntax to decode.
  if (!/[\\%&\/'"`+|]/.test(output)) {
    if (!/[\s\u0000-\u001f\u007f]/.test(output)) return output;
    return collapseSecurityWhitespace(output);
  }

  const hasEscapes = output.includes('\\');
  const hasPercentEncoding = output.includes('%') && /%[0-9a-f]{2}/i.test(output);
  const hasEntities = output.includes('&');
  const hasComments = output.includes('/*');
  const hasQuotedConcat = (output.includes("'") || output.includes('"')) && (output.includes('+') || output.includes('||'));

  if (hasEscapes) {
    const decoded = decodeLiteralEscapes(output);
    if (decoded !== output) needsRenormalize = true;
    output = decoded;
  }
  if (hasPercentEncoding) {
    const decoded = (() => { try { return decodeURIComponent(output.replace(/\+/g, '%2B')); } catch { return output; } })();
    if (decoded !== output) needsRenormalize = true;
    output = decoded;
  }
  if (hasEntities) {
    const decoded = decodeHtmlEntities(output);
    if (decoded !== output) needsRenormalize = true;
    output = decoded;
  }
  // Preserve the content of MySQL executable comments; remove ordinary comments.
  if (hasComments || output.includes('/*')) {
    output = output.replace(/\/\*!\s*\d*(.*?)\*\//gs, ' $1 ');
    output = output.replace(/\/\*[\s\S]*?\*\//g, ' ');
  }
  // Flatten quoted-string concatenation without evaluating the input.
  if (hasQuotedConcat || ((output.includes("'") || output.includes('"')) && (output.includes('+') || output.includes('||')))) {
    for (let i = 0; i < 3; i++) {
      const next = output.replace(/(['"])([^'"\r\n]{1,128})\1\s*(?:\+|\|\|)\s*(['"])([^'"\r\n]{1,128})\3/g, (_m, _q1, left, _q2, right) => `'${left}${right}'`);
      if (next === output) break;
      output = next;
    }
  }
  if (needsRenormalize) output = output.normalize('NFKC');
  if (!/[\s\u0000-\u001f\u007f]/.test(output)) return output;
  return collapseSecurityWhitespace(output);
}

// Preserve line boundaries: SQL -- and # comments terminate at a newline.
// Other control characters and horizontal whitespace are safely collapsed.
function collapseSecurityWhitespace(value) {
  return String(value)
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ')
    .replace(/[\t\v\f \u00a0]+/g, ' ')
    .replace(/[ \t]*\n[ \t]*/g, '\n')
    .trim();
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
  const matcher = /--[^\r\n]*|#[^\r\n]*|\/\*[\s\S]*?\*\/|'(?:''|\\.|[^'])*'|"(?:""|\\.|[^"])*"|0x[0-9a-f]+|\b\d+(?:\.\d+)?\b|[a-z_][a-z0-9_$]*|!=|<>|<=|>=|\|\||&&|[=<>]|[^\s]/gi;
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
  // Comment syntax is common in tutorials and prose; treat it as attack evidence only when
  // it is paired with executable SQL grammar or a MySQL versioned-comment directive.
  if (/\/\*!\s*\d{5,}\s*(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|SLEEP)\b/i.test(String(value))) {
    findings.push({ id: 'SQLI_VERSIONED_COMMENT', category: 'SQL_INJECTION', severity: 'high', detail: 'Executable MySQL versioned comment containing SQL instructions detected.' });
  } else if (tokens.some((token) => token.type === 'C' && /^(?:--|#)\s*$|^\/\*\s*\*\/$/.test(token.raw)) && words.some((word) => ['UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'WHERE'].includes(word))) {
    findings.push({ id: 'SQLI_COMMENT', category: 'SQL_INJECTION', severity: 'medium', detail: 'SQL comment is attached to SQL grammar in an injection-like position.' });
  }
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
    if (typeof value === 'number' && !Number.isFinite(value)) {
      add('JSON_NON_FINITE_NUMBER', 'PROTOCOL', 'high', `Non-finite JSON number detected at ${path.slice(0, 80)}.`);
      return;
    }
    const fieldName = fieldNameFromPath(path);
    const opaqueLimit = OPAQUE_FIELD_LIMITS.get(fieldName);
    if (opaqueLimit) {
      if (typeof value !== 'string') add('OPAQUE_FIELD_TYPE', 'PROTOCOL', 'high', `Opaque security field at ${path.slice(0, 70)} must be a string.`);
      else {
        const bytes = Buffer.byteLength(value, 'utf8');
        if (bytes > opaqueLimit) add('OPAQUE_FIELD_SIZE', 'PROTOCOL', 'high', `Opaque security field at ${path.slice(0, 70)} exceeds its ${opaqueLimit}-byte limit.`);
        if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) add('CONTROL_CHARACTERS', 'PROTOCOL', 'medium', `Control characters detected in opaque field at ${path.slice(0, 70)}.`);
        // Opaque credentials must not be parsed as SQL grammar, but they are
        // still attacker-controlled bytes. Keep the high-confidence non-SQL
        // checks (XSS, SSRF, SSTI, LDAP, XXE, command/deserialization markers)
        // active so a field-name exemption cannot suppress those controls.
        // Inspect the raw representation before canonicalization can replace binary
        // signature bytes such as Java serialization's AC ED 00 05 header.
        for (const finding of scanNonSqlTextInChunks(value)) add(finding.id, finding.category, finding.severity, `${finding.detail} Opaque field: ${path.slice(0, 70)}.`);
        const canonical = canonicalizeSecurityText(value);
        if (canonical.excessiveEncoding) add('NESTED_ENCODING', 'PROTOCOL', 'high', `Repeated encoding did not reach a canonical form in opaque field at ${path.slice(0, 70)}.`);
        for (const finding of scanNonSqlTextInChunks(canonical.value)) add(finding.id, finding.category, finding.severity, `${finding.detail} Opaque field: ${path.slice(0, 70)}.`);
      }
      return; // Keep SQL grammar opaque; non-SQL exploit checks still apply.
    }
    if (typeof value === 'string') {
      const bytes = Buffer.byteLength(value, 'utf8');
      const allowedLong = Array.isArray(options.allowedLongFields) && options.allowedLongFields.some((name) => path === name || path.endsWith(`.${name}`));
      if (bytes > options.maxLeafBytes && !allowedLong) add('BODY_LEAF_SIZE', 'PROTOCOL', 'high', `String leaf at ${path.slice(0, 80)} exceeds ${options.maxLeafBytes} bytes.`);
      // Raw scan is required for byte signatures that canonicalization may
      // normalize away (for example NUL/control bytes in serialization headers).
      for (const finding of scanNonSqlTextInChunks(value)) add(finding.id, finding.category, finding.severity, `${finding.detail} Field: ${path.slice(0, 80)}.`);
      const canonical = canonicalizeSecurityText(value);
      if (canonical.excessiveEncoding) add('NESTED_ENCODING', 'PROTOCOL', 'high', `Repeated encoding did not reach a canonical form at ${path.slice(0, 80)}.`);
      const text = canonical.value;
      if (isSsrfDestinationField(path)) addSsrfDestinationFinding(text, add, `Destination field: ${path.slice(0, 80)}.`);
      const richTextFields = new Set(DEFAULT_RICH_TEXT_FIELDS);
      if (Array.isArray(options.allowedRichTextFields)) for (const name of options.allowedRichTextFields) richTextFields.add(String(name).toLowerCase());
      const richText = richTextFields.has(fieldName);
      // A prose/code field is not SQL to be executed: do not treat SQL comment
      // tokens or tutorial grammar as an injection. Non-SQL exploit checks keep
      // their real severity in every field (including rich text). Scan each text
      // leaf once; the chunk scanner preserves boundary-spanning matches.
      const nonSql = scanNonSqlTextInChunks(text);
      for (const finding of nonSql) add(finding.id, finding.category, finding.severity, `${finding.detail} Field: ${path.slice(0, 80)}.`);
      if (!richText) {
        const scan = scanTextInChunks(text, grammarFindings);
        for (const finding of scan) add(finding.id, finding.category, finding.severity, `${finding.detail} Field: ${path.slice(0, 60)}.`);
      }
      // Symbol density alone is not an exploit indicator and is never a blocking rule.
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
    if (OPAQUE_FIELD_LIMITS.has(lower) && (value[key] === null || typeof value[key] !== 'string')) add('OPAQUE_FIELD_TYPE', 'PROTOCOL', 'high', `Opaque security field at ${path.slice(0, 60)}.${key.slice(0, 60)} must be a string.`);
    inspectStructure(value[key], options, state, `${path}.${key}`, depth + 1, add);
    if (state.tooDeep || state.tooMany) break;
  }
}

/** Scan a byte/string stream in bounded chunks with overlap so boundary-spanning payloads are not lost. */
export function scanTextInChunks(input, scan = (chunk) => grammarFindings(canonicalizeSecurityText(chunk).value), options = {}) {
  const text = String(input ?? '');
  if (scan === grammarFindings && !mayContainSqlGrammar(text)) return [];
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

function scanDuplicateJsonKeys(input) {
  const source = String(input);
  let index = 0;
  let nodes = 0;
  const whitespace = () => { while (/\s/.test(source[index] || '')) index++; };
  const readString = () => {
    const start = index++;
    while (index < source.length) {
      const ch = source[index++];
      if (ch === '\\') { index++; continue; }
      if (ch === '"') return JSON.parse(source.slice(start, index));
    }
    throw new Error('Unterminated JSON string.');
  };
  const parseValue = (depth = 0) => {
    if (++nodes > 12000 || depth > 64) throw Object.assign(new Error('JSON structure limit exceeded.'), { limitExceeded: true });
    whitespace();
    const ch = source[index];
    if (ch === '{') {
      index++; whitespace(); const keys = new Set();
      if (source[index] === '}') { index++; return; }
      while (index < source.length) {
        whitespace();
        if (source[index] !== '"') throw new Error('Expected JSON object key.');
        const key = readString();
        if (keys.has(key)) throw Object.assign(new Error('Duplicate JSON object key.'), { duplicateKey: key });
        keys.add(key); whitespace();
        if (source[index++] !== ':') throw new Error('Expected JSON colon.');
        parseValue(depth + 1); whitespace();
        const separator = source[index++];
        if (separator === '}') return;
        if (separator !== ',') throw new Error('Expected JSON object separator.');
      }
      throw new Error('Unterminated JSON object.');
    }
    if (ch === '[') {
      index++; whitespace();
      if (source[index] === ']') { index++; return; }
      while (index < source.length) {
        parseValue(depth + 1); whitespace();
        const separator = source[index++];
        if (separator === ']') return;
        if (separator !== ',') throw new Error('Expected JSON array separator.');
      }
      throw new Error('Unterminated JSON array.');
    }
    if (ch === '"') { readString(); return; }
    const start = index;
    while (index < source.length && !/[\s,\]}]/.test(source[index])) index++;
    if (start === index) throw new Error('Expected JSON value.');
    const token = source.slice(start, index);
    if (token === 'true' || token === 'false' || token === 'null') return;
    if (!/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(token)) throw new Error('Invalid JSON primitive.');
    if (!Number.isFinite(Number(token))) throw Object.assign(new Error('Non-finite JSON number.'), { nonFiniteNumber: token });
  };
  try {
    parseValue(); whitespace();
    if (index !== source.length) return { valid: false, duplicate: false, nonFiniteNumber: null };
    return { valid: true, duplicate: false, nonFiniteNumber: null };
  } catch (error) {
    return {
      valid: false,
      duplicate: Boolean(error?.duplicateKey),
      key: error?.duplicateKey || null,
      nonFiniteNumber: error?.nonFiniteNumber || null,
      limitExceeded: error?.limitExceeded === true
    };
  }
}

function graphqlLimits(query) {
  const text = String(query || '').slice(0, 200000);
  let depth = 0; let maxDepth = 0; let aliases = 0; let inString = false; let escaped = false; let inComment = false;
  let token = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inComment) { if (ch === '\n') inComment = false; continue; }
    if (inString) { if (escaped) escaped = false; else if (ch === '\\') escaped = true; else if (ch === '"') inString = false; continue; }
    if (ch === '#') { inComment = true; continue; }
    if (ch === '"') { inString = true; continue; }
    if (/[A-Za-z0-9_]/.test(ch)) { token += ch; continue; }
    if (ch === ':') { if (/^[_A-Za-z][_0-9A-Za-z]*$/.test(token)) aliases++; token = ''; continue; }
    if (ch === '{') { depth++; maxDepth = Math.max(maxDepth, depth); }
    if (ch === '}') depth = Math.max(0, depth - 1);
    token = '';
  }
  return { depth: maxDepth, aliases, introspection: /\b__(?:schema|type)\b/.test(text) };
}

function rawPathForInspection(input) {
  let raw = String(input ?? '/');
  const absolute = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*(.*)$/i.exec(raw);
  if (absolute) raw = absolute[1] || '/';
  const query = raw.search(/[?#]/);
  if (query >= 0) raw = raw.slice(0, query);
  return raw || '/';
}

function normalizePathForInspection(input) {
  try {
    const parsed = new URL(String(input), 'https://arixshield.invalid');
    const segments = parsed.pathname.split('/').map((segment) => decodeURIComponent(segment));
    const stack = [];
    for (const segment of segments) {
      if (!segment || segment === '.') continue;
      if (segment === '..') stack.pop();
      else stack.push(segment);
    }
    if (segments.some((segment) => /[\\/\0]/.test(segment))) return null;
    return `/${stack.join('/')}${parsed.search}`;
  } catch { return null; }
}

function checkFileSignature(type, bytes, add) {
  const signatures = {
    'image/png': [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
    'image/jpeg': [0xff, 0xd8, 0xff],
    'application/pdf': [0x25, 0x50, 0x44, 0x46]
  };
  const expected = signatures[type];
  if (expected && (bytes.length < expected.length || !expected.every((byte, index) => bytes[index] === byte))) {
    add('UPLOAD_MAGIC_MISMATCH', 'UPLOAD', 'high', `Upload bytes do not match declared ${type}.`);
    return;
  }
  if (type === 'image/svg+xml') {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, Math.min(bytes.length, 1024 * 1024)));
    if (/<\s*script\b|\bon[a-z]+\s*=|javascript\s*:/i.test(text)) add('SVG_ACTIVE_CONTENT', 'UPLOAD', 'critical', 'Scriptable SVG content is not accepted as an upload.');
  }
}

function inspectMultipart(contentType, body, add) {
  const match = /(?:^|;)\s*boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(contentType);
  const boundary = match?.[1] ?? match?.[2];
  if (!boundary || boundary.length > 70 || !/^[\x21-\x7e]+$/.test(boundary)) {
    add('MULTIPART_BOUNDARY', 'UPLOAD', 'high', 'Multipart boundary is missing or invalid.');
    return;
  }
  const buffer = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  if (buffer.length > ABSOLUTE_MAX_BODY_BYTES) {
    add('MULTIPART_SIZE', 'UPLOAD', 'high', 'Multipart body exceeds the bounded inspection limit.');
    return;
  }
  const delimiter = Buffer.from(`--${boundary}`);
  const separator = Buffer.from(`\r\n--${boundary}`);
  let cursor = buffer.indexOf(delimiter);
  let parts = 0;
  if (cursor !== 0) {
    add('MULTIPART_FORMAT', 'UPLOAD', 'high', 'Multipart body does not begin with its declared boundary.');
    return;
  }
  while (cursor >= 0 && parts < 16) {
    cursor += delimiter.length;
    if (buffer.subarray(cursor, cursor + 2).toString('ascii') === '--') return;
    if (buffer.subarray(cursor, cursor + 2).toString('ascii') !== '\r\n') {
      add('MULTIPART_FORMAT', 'UPLOAD', 'high', 'Malformed multipart boundary framing.');
      return;
    }
    cursor += 2;
    const headerEnd = buffer.indexOf(Buffer.from('\r\n\r\n'), cursor);
    if (headerEnd < 0 || headerEnd - cursor > 4096) {
      add('MULTIPART_HEADERS', 'UPLOAD', 'high', 'Multipart part headers are missing or exceed the inspection limit.');
      return;
    }
    const rawHeaders = buffer.subarray(cursor, headerEnd).toString('latin1');
    const headers = Object.create(null);
    for (const line of rawHeaders.split('\r\n')) {
      const split = line.indexOf(':');
      if (split <= 0) { add('MULTIPART_HEADERS', 'UPLOAD', 'high', 'Malformed multipart part header.'); return; }
      const name = line.slice(0, split).trim().toLowerCase();
      if (Object.hasOwn(headers, name)) { add('MULTIPART_DUPLICATE_HEADER', 'UPLOAD', 'high', 'Duplicate multipart part headers are not accepted.'); return; }
      headers[name] = line.slice(split + 1).trim();
    }
    const dataStart = headerEnd + 4;
    const next = buffer.indexOf(separator, dataStart);
    if (next < 0) { add('MULTIPART_TRUNCATED', 'UPLOAD', 'high', 'Multipart part has no terminating boundary.'); return; }
    const disposition = headers['content-disposition'] ?? '';
    const isFile = /(?:^|;)\s*filename\s*=\s*(?:"[^"]*"|[^;\s]+)/i.test(disposition);
    const nameMatch = /(?:^|;)\s*name\s*=\s*(?:"([^"]*)"|([^;\s]+))/i.exec(disposition);
    const fieldName = String(nameMatch?.[1] ?? nameMatch?.[2] ?? '').slice(0, 80).toLowerCase();
    const partBytes = buffer.subarray(dataStart, next);
    const declaredType = String(headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
    if (isFile) {
      // Executable signatures are rejected regardless of the client-declared
      // MIME type (including a mislabeled image or application/octet-stream).
      if (partBytes.length >= 2 && partBytes[0] === 0x4d && partBytes[1] === 0x5a) {
        add('UPLOAD_EXECUTABLE_SIGNATURE', 'UPLOAD', 'critical', 'Windows executable content is not accepted in multipart file parts.');
      }
      if (!declaredType) add('UPLOAD_PART_CONTENT_TYPE', 'UPLOAD', 'high', 'Uploaded file part has no declared content type.');
      else if (['image/png', 'image/jpeg', 'application/pdf', 'image/svg+xml'].includes(declaredType)) checkFileSignature(declaredType, partBytes, add);
      else if (/^(?:application\/(?:x-msdownload|x-executable|x-sh|x-dosexec|javascript|x-javascript)|text\/html|image\/svg\+xml)$/i.test(declaredType)) add('UPLOAD_EXECUTABLE_TYPE', 'UPLOAD', 'critical', 'Scriptable or executable file content types are not accepted.');
      if (/^(?:application|text)\/(?:xml|[^;]+\+xml)$/i.test(declaredType)) {
        const xml = new TextDecoder('utf-8', { fatal: false }).decode(partBytes);
        if (/<!\s*(?:DOCTYPE|ENTITY)\b/i.test(xml)) add('XML_DTD_XXE', 'XXE', 'critical', 'DOCTYPE and ENTITY declarations are forbidden in multipart XML file parts.');
      }
    } else {
      // Ordinary multipart fields are user-controlled input too; never skip them
      // merely because they have no filename parameter.
      const opaqueLimit = OPAQUE_FIELD_LIMITS.get(fieldName);
      if (opaqueLimit) {
        if (partBytes.length > opaqueLimit) add('OPAQUE_FIELD_SIZE', 'PROTOCOL', 'high', `Multipart opaque field '${fieldName}' exceeds its ${opaqueLimit}-byte limit.`);
        const fieldText = new TextDecoder('utf-8', { fatal: false }).decode(partBytes);
        const canonical = canonicalizeSecurityText(fieldText);
        if (canonical.excessiveEncoding) add('NESTED_ENCODING', 'PROTOCOL', 'high', `Repeated encoding did not reach a canonical form in multipart opaque field '${fieldName}'.`);
        for (const finding of scanNonSqlTextInChunks(canonical.value)) add(finding.id, finding.category, finding.severity, `${finding.detail} Multipart opaque field: ${fieldName || 'unnamed'}.`);
      } else {
        const fieldText = new TextDecoder('utf-8', { fatal: false }).decode(partBytes);
        const canonical = canonicalizeSecurityText(fieldText);
        if (canonical.excessiveEncoding) add('NESTED_ENCODING', 'PROTOCOL', 'high', `Repeated encoding did not reach a canonical form in multipart field '${fieldName || 'unnamed'}'.`);
        if (isSsrfDestinationField(fieldName)) addSsrfDestinationFinding(canonical.value, add, `Multipart destination field: ${fieldName || 'unnamed'}.`);
        for (const finding of scanNonSqlTextInChunks(canonical.value)) add(finding.id, finding.category, finding.severity, `${finding.detail} Multipart field: ${fieldName || 'unnamed'}.`);
        if (!DEFAULT_RICH_TEXT_FIELDS.has(fieldName)) {
          for (const finding of scanTextInChunks(canonical.value, grammarFindings)) add(finding.id, finding.category, finding.severity, `${finding.detail} Multipart field: ${fieldName || 'unnamed'}.`);
        }
      }
    }
    parts++;
    cursor = next + 2;
  }
  const followingBoundary = buffer.indexOf(delimiter, cursor);
  if (parts >= 16 && followingBoundary >= 0 && buffer.subarray(followingBoundary + delimiter.length, followingBoundary + delimiter.length + 2).toString('ascii') !== '--') add('MULTIPART_PART_LIMIT', 'UPLOAD', 'high', 'Multipart request contains more than 16 parts.');
}

function uploadFindings(contentType, rawBody, add) {
  const typeHeader = String(contentType || '');
  const type = typeHeader.split(';')[0].trim().toLowerCase();
  if (!rawBody) {
    if (type === 'multipart/form-data' || type === 'application/octet-stream' || ['image/png', 'image/jpeg', 'application/pdf', 'image/svg+xml'].includes(type)) add('UPLOAD_RAW_BODY_REQUIRED', 'UPLOAD', 'high', 'Raw upload bytes are required for signature inspection.');
    return;
  }
  const bytes = rawBody instanceof Uint8Array ? rawBody : Buffer.isBuffer(rawBody) ? rawBody : null;
  if (!bytes || !bytes.length) return;
  if (type === 'multipart/form-data') { inspectMultipart(typeHeader, bytes, add); return; }
  if (type === 'image/png' || type === 'image/jpeg' || type === 'application/pdf' || type === 'image/svg+xml') checkFileSignature(type, bytes, add);
  if (type === 'application/octet-stream' && bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a) add('UPLOAD_EXECUTABLE_SIGNATURE', 'UPLOAD', 'critical', 'Windows executable content is not accepted as an untyped binary upload.');
}

export function inspectRequest({ method = 'GET', url = '/', headers = {}, rawHeaders = null, httpVersion = '', body = null, rawBody = null, contentLength = 0, maxBodyBytes = DEFAULT_MAX_BODY_BYTES, maxLeafBytes = DEFAULT_MAX_LEAF_BYTES, allowedLongFields = [], allowedQueryArrayFields = [], production = process.env.NODE_ENV === 'production' } = {}) {
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
  const rawHeaderPairs = Array.isArray(rawHeaders) ? Array.from({ length: Math.floor(rawHeaders.length / 2) }, (_, index) => [String(rawHeaders[index * 2]), String(rawHeaders[index * 2 + 1] ?? '')]) : [];
  const rawHeaderNames = rawHeaderPairs.map(([name]) => name.toLowerCase());
  const headerDuplicates = rawHeaderNames.some((name, index) => rawHeaderNames.indexOf(name) !== index);
  if (headerDuplicates) add('DUPLICATE_HEADER', 'PROTOCOL', 'high', 'Duplicate HTTP request headers are not accepted.');
  const allHeaderPairs = [...headerEntries.map(([name, value]) => [String(name), String(value)]), ...rawHeaderPairs];
  const tokenHeaderName = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
  if (allHeaderPairs.some(([name, value]) => /[\r\n]/.test(name) || /[\r\n]/.test(value) || !tokenHeaderName.test(name))) {
    add('HTTP_HEADER_INJECTION', 'PROTOCOL', 'critical', 'HTTP header names and values must not contain CR or LF and names must use valid token characters.');
  }
  if (rawHeaderNames.includes('content-length') && rawHeaderNames.includes('transfer-encoding') || normalizedHeaders['content-length'] && normalizedHeaders['transfer-encoding']) add('HTTP_SMUGGLING_HEADERS', 'PROTOCOL', 'critical', 'Content-Length and Transfer-Encoding must not appear together.');
  const versionMajor = String(httpVersion).split('.')[0];
  const isHttp2Or3 = versionMajor === '2' || versionMajor === '3';
  const connectionSpecificHeaders = ['connection', 'keep-alive', 'proxy-connection', 'upgrade', 'transfer-encoding'];
  if (isHttp2Or3 && connectionSpecificHeaders.some((name) => Object.hasOwn(normalizedHeaders, name) || rawHeaderNames.includes(name))) {
    add('HTTP2_CONNECTION_SPECIFIC_HEADER', 'PROTOCOL', 'critical', 'HTTP/2 and HTTP/3 requests must not contain connection-specific headers.');
  }
  const bodyText = safeStringify(body);
  const bytes = rawBody ? (rawBody.byteLength ?? rawBody.length ?? 0) : Buffer.byteLength(bodyText === 'null' ? '' : bodyText, 'utf8');
  const declaredBytes = Number(contentLength) || 0;
  const configuredMax = Math.max(1024, Math.min(ABSOLUTE_MAX_BODY_BYTES, Number(maxBodyBytes) || DEFAULT_MAX_BODY_BYTES));
  if (declaredBytes > configuredMax || bytes > configuredMax) add('BODY_SIZE', 'PROTOCOL', 'high', `Request body exceeds the configured ${configuredMax}-byte inspection limit.`);
  if (normalizedHeaders['x-http-method-override'] || normalizedHeaders['x-method-override']) add('METHOD_OVERRIDE', 'PROTOCOL', 'medium', 'HTTP method override headers are not accepted by default.');
  if (/\0|%00/i.test(String(url))) add('NULL_BYTE', 'PROTOCOL', 'high', 'Null byte detected in request URL.');
  if (/\/\*!\s*\d{5,}\s*(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|SLEEP)\b/i.test(String(url))) add('SQLI_VERSIONED_COMMENT', 'SQL_INJECTION', 'high', 'Executable MySQL versioned comment containing SQL instructions detected.');
  const rawPath = rawPathForInspection(url);
  const rawPathCanonical = canonicalizeSecurityText(rawPath).value;
  const normalizedPath = normalizePathForInspection(url);
  if (!normalizedPath) add('URL_PATH_NORMALIZATION', 'PROTOCOL', 'high', 'Path cannot be normalized consistently.');
  // WHATWG URL parsing collapses dot segments before exposing pathname. Inspect
  // the original request-target path as well, so normalization cannot erase the
  // evidence that an encoded or literal traversal sequence was supplied.
  if (/(?:^|[\/])\.{1,2}(?:[\/]|$)|(?:%2e){2}(?:%2f|%5c|$)/i.test(rawPathCanonical)) {
    add('PATH_TRAVERSAL', 'PATH_TRAVERSAL', 'high', 'Dot-segment path traversal syntax detected in the original request target.');
  }
  const contentType = normalizedHeaders['content-type'] ?? '';
  const hasPayload = declaredBytes > 0 || (body != null && bodyText !== 'null' && bytes > 2);
  if (hasPayload && !['GET', 'HEAD', 'OPTIONS'].includes(methodUpper)) {
    if (!contentType || !/(?:application\/json|application\/x-www-form-urlencoded|multipart\/form-data|text\/plain|application\/octet-stream|image\/png|image\/jpeg|application\/pdf|image\/svg\+xml|application\/xml|text\/xml)/i.test(contentType)) add('CONTENT_TYPE', 'PROTOCOL', 'medium', 'Missing or unexpected content type for a body-bearing request.');
    else if (/application\/(?:[^;]+\+)?json/i.test(contentType) && typeof body === 'string') add('JSON_PARSE', 'PROTOCOL', 'high', 'JSON content type was received but the body was not valid parsed JSON.');
  }
  try { new URL(String(url), 'https://arixshield.invalid'); } catch { add('URL_PARSE', 'PROTOCOL', 'high', 'Malformed request URL.'); }
  const excludedHeaders = new Set(['cookie', 'authorization', 'x-arix-secret', 'x-arix-server-key', 'x-arix-key', 'x-arix-clearance', 'x-arix-pop']);
  const headerText = headerEntries.filter(([key]) => !excludedHeaders.has(String(key).toLowerCase())).map(([key, value]) => `${key}:${String(value).slice(0, 1000)}`).join('\n');
  const urlText = canonicalizeSecurityText(normalizedPath || String(url));
  for (const rule of NON_SQL_RULES) {
    if (rule.pattern.test(urlText.value) || rule.pattern.test(rawPathCanonical) || rule.pattern.test(headerText)) add(rule.id, rule.category, rule.severity, `Matched ${rule.category.toLowerCase().replaceAll('_', ' ')} heuristic in request metadata.`);
  }
  // Evaluate query parameters only when their names identify a destination
  // sink (for example ?url=, ?target= or ?webhookUrl=). Do not flag a normal
  // query/message parameter because its text happens to mention a local IP.
  try {
    const parsed = new URL(String(url), 'https://arixshield.invalid');
    const params = new Map();
    for (const [key, value] of parsed.searchParams.entries()) {
      params.set(key, (params.get(key) || 0) + 1);
      if (isSsrfDestinationField(key)) addSsrfDestinationFinding(value, add, `Destination query parameter: ${String(key).slice(0, 60)}.`);
    }
    for (const [name, value] of allHeaderPairs) {
      const lowerName = String(name).toLowerCase();
      if (lowerName.startsWith('x-') && isSsrfDestinationField(lowerName.slice(2))) {
        addSsrfDestinationFinding(value, add, `Destination header: ${lowerName.slice(0, 60)}.`);
      }
    }
    for (const finding of grammarFindings(urlText.value + '\n' + headerText)) add(finding.id, finding.category, finding.severity, finding.detail);
    const arrayFields = new Set((Array.isArray(allowedQueryArrayFields) ? allowedQueryArrayFields : []).map((name) => String(name).toLowerCase()));
    for (const [key, count] of params) if (count > 1 && !arrayFields.has(String(key).toLowerCase())) add('HTTP_PARAMETER_POLLUTION', 'PROTOCOL', 'high', `Duplicate query parameter '${key}' is not allowed without an array schema.`);
  } catch { /* Invalid URLs were reported above. */ }
  const rawJson = typeof rawBody === 'string' ? rawBody : rawBody && /application\/(?:[^;]+\+)?json/i.test(contentType) ? new TextDecoder().decode(rawBody) : (typeof body === 'string' && /application\/(?:[^;]+\+)?json/i.test(contentType) ? body : null);
  if (rawJson) {
    const duplicateScan = scanDuplicateJsonKeys(rawJson);
    if (duplicateScan.duplicate) add('JSON_DUPLICATE_KEY', 'PROTOCOL', 'high', `Duplicate JSON object key detected${duplicateScan.key ? `: ${duplicateScan.key}` : ''}.`);
    if (duplicateScan.nonFiniteNumber) add('JSON_NON_FINITE_NUMBER', 'PROTOCOL', 'high', 'JSON numeric value overflows the finite JavaScript number range.');
    if (duplicateScan.limitExceeded) add('JSON_COMPLEXITY_LIMIT', 'PROTOCOL', 'high', 'Raw JSON exceeds the duplicate-key scanner node or depth limit.');
    else if (!duplicateScan.valid && !duplicateScan.duplicate && !duplicateScan.nonFiniteNumber) add('JSON_MALFORMED', 'PROTOCOL', 'high', 'Raw JSON could not be parsed consistently.');
  }
  if (body !== null && (typeof body === 'number' || (typeof body === 'object' && !ArrayBuffer.isView(body)))) {
    const state = { nodes: 0, tooDeep: false, tooMany: false };
    inspectStructure(body, { maxLeafBytes: Math.max(128, Math.min(65536, Number(maxLeafBytes) || DEFAULT_MAX_LEAF_BYTES)), allowedLongFields }, state, '$', 0, add);
    if (state.tooDeep) add('JSON_DEPTH', 'PROTOCOL', 'high', `JSON nesting exceeds ${MAX_NESTING_DEPTH} levels.`);
    if (state.tooMany) add('JSON_NODES', 'PROTOCOL', 'high', `JSON object exceeds ${MAX_NODES} nodes.`);
  } else if (typeof body === 'string' && body !== '') {
    if (/\/\*!\s*\d{5,}\s*(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|SLEEP)\b/i.test(body)) add('SQLI_VERSIONED_COMMENT', 'SQL_INJECTION', 'high', 'Executable MySQL versioned comment containing SQL instructions detected.');
    for (const finding of matchingNonSqlRuleFindings(body)) add(finding.id, finding.category, finding.severity, finding.detail);
    const canonical = canonicalizeSecurityText(body);
    if (canonical.excessiveEncoding) add('NESTED_ENCODING', 'PROTOCOL', 'high', 'Repeated encoding did not reach a canonical form.');
    for (const finding of matchingNonSqlRuleFindings(canonical.value)) add(finding.id, finding.category, finding.severity, finding.detail);
    for (const finding of scanTextInChunks(canonical.value, grammarFindings)) add(finding.id, finding.category, finding.severity, finding.detail);
  }
  if (/\b(?:application\/xml|text\/xml)\b/i.test(contentType)) {
    const xmlText = typeof body === 'string' ? body : rawBody ? (typeof rawBody === 'string' ? rawBody : new TextDecoder('utf-8', { fatal: false }).decode(rawBody)) : rawJson || '';
    if (/<!\s*(?:DOCTYPE|ENTITY)\b/i.test(xmlText)) add('XML_DTD_XXE', 'XXE', 'critical', 'DOCTYPE and ENTITY declarations are forbidden in XML payloads.');
  }
  uploadFindings(contentType, rawBody, add);
  const graphqlQuery = body && typeof body === 'object' && typeof body.query === 'string' ? body.query : (/\/graphql(?:\/|$)/i.test(new URL(String(url), 'https://arixshield.invalid').pathname) && typeof body === 'string' ? body : null);
  if (graphqlQuery) {
    const limits = graphqlLimits(graphqlQuery);
    if (limits.depth > 8) add('GRAPHQL_DEPTH', 'GRAPHQL', 'high', 'GraphQL selection nesting exceeds depth 8.');
    if (limits.aliases > 4) add('GRAPHQL_ALIASES', 'GRAPHQL', 'high', 'GraphQL request contains more than four aliases.');
    if (production && limits.introspection) add('GRAPHQL_INTROSPECTION', 'GRAPHQL', 'medium', 'GraphQL introspection is disabled in production.');
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
  if (typeof value === 'number' && !Number.isFinite(value)) errors.push(`${path}: number must be finite`);
  for (const subschema of schema.allOf || []) {
    const result = validateJsonSchema(value, subschema, path, depth + 1);
    errors.push(...result.errors);
  }
  if (Array.isArray(schema.anyOf)) {
    const matches = schema.anyOf.filter((candidate) => validateJsonSchema(value, candidate, path, depth + 1).valid).length;
    if (matches < 1) errors.push(`${path}: did not match anyOf alternatives`);
  }
  if (Array.isArray(schema.oneOf)) {
    const matches = schema.oneOf.filter((candidate) => validateJsonSchema(value, candidate, path, depth + 1).valid).length;
    if (matches !== 1) errors.push(`${path}: must match exactly one oneOf alternative`);
  }
  if (schema.not && validateJsonSchema(value, schema.not, path, depth + 1).valid) errors.push(`${path}: matched a forbidden schema`);
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
