import { createHash } from 'node:crypto';

const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password12', 'password123', 'password1234', 'password12345',
  'password123456', 'password1234567', 'password12345678', 'passw0rd123456', 'p@ssword123456',
  '123456789012', '1234567890123', '12345678901234', '123456789012345', '1234567890123456',
  '1234567890', '12345678901', '1234567890!', '1234567890a', 'qwerty123456', 'qwertyuiop12',
  'qwerty123456789', 'qwertyuiop123', '1q2w3e4r5t6y', '1qaz2wsx3edc', 'asdfghjkl123',
  'letmein123456', 'welcome123456', 'admin123456', 'administrator123', 'changeme123456',
  'iloveyou123456', 'trustnoone123', 'sunshine123456', 'princess123456', 'football123456',
  'dragon123456', 'monkey123456', 'shadow123456', 'master123456', 'login12345678',
  'abc123abc123', 'abc123456789', 'welcomehome12', 'hellohello123', 'testing123456',
  'winter2026winter', 'summer2026summer', 'spring2026spring', 'autumn2026autumn',
  'letmeinplease', 'thisismypassword', 'mypassword1234', 'mysecretpassword', 'secretpassword',
  'correcthorsebatterystaple', 'iloveyouforever', 'whatever123456', 'qazwsxedcrfv',
  '1q2w3e4r5t6y7u', 'zaq12wsxzaq12', 'asdf1234asdf12', 'baseball123456',
  'football2026!', 'password!@#$%^', 'pass123456789', 'passw0rdpassw0rd',
  'linkedinpassword', 'facebookpassword', 'googlepassword', 'instagram123456',
  'microsoft123456', 'welcome2026!', 'adminadmin123', 'administrator1234',
  'changemeplease', 'letmeinplease1', 'iloveyouiloveyou', 'qwertyqwerty12'
]);

function comparable(value) {
  return String(value || '').normalize('NFKC').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function contextTerms({ email = '', projectName = '' } = {}) {
  const values = ['arix', 'arixshield'];
  const localPart = String(email).split('@', 1)[0];
  for (const source of [localPart, projectName]) {
    const raw = String(source || '').normalize('NFKC').toLowerCase();
    const compact = comparable(raw);
    if (compact.length >= 4) values.push(compact);
    for (const token of raw.split(/[^a-z0-9]+/i)) {
      const term = comparable(token);
      if (term.length >= 4) values.push(term);
    }
  }
  return [...new Set(values)];
}

function isCommonPassword(password) {
  const value = comparable(password);
  if (COMMON_PASSWORDS.has(value)) return true;
  // Block the most common word + predictable numeric/punctuation suffix pattern.
  for (const base of ['password', 'passw0rd', 'qwerty', 'welcome', 'letmein', 'admin', 'administrator', 'changeme', 'iloveyou', 'sunshine', 'princess', 'football', 'dragon', 'monkey', 'shadow', 'master', 'login', 'testing']) {
    if (value.startsWith(base) && value.length - base.length >= 2 && /^\d{2,}$/.test(value.slice(base.length))) return true;
  }
  return false;
}

/**
 * Uses the Pwned Passwords k-anonymity range API: only the first five hex
 * characters of the SHA-1 digest leave this process; the password never does.
 * Fail closed when the breach corpus cannot be checked.
 */
export async function isBreachedPassword(password) {
  const hash = createHash('sha1').update(String(password), 'utf8').digest('hex').toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  let response;
  try {
    response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      method: 'GET',
      headers: { 'Add-Padding': 'true', 'User-Agent': 'ArixShield-Password-Policy/1.0' },
      signal: AbortSignal.timeout(5000)
    });
  } catch {
    throw Object.assign(new Error('Breached-password verification is temporarily unavailable.'), { statusCode: 503 });
  }
  if (!response.ok) throw Object.assign(new Error('Breached-password verification is temporarily unavailable.'), { statusCode: 503 });
  let body;
  try { body = await response.text(); } catch {
    throw Object.assign(new Error('Breached-password verification is temporarily unavailable.'), { statusCode: 503 });
  }
  if (body.length > 1_500_000) throw Object.assign(new Error('Breached-password response exceeded the safety limit.'), { statusCode: 503 });
  for (const line of body.split(/\r?\n/)) {
    const match = /^([A-F0-9]{35}):([0-9]+)$/i.exec(line.trim());
    if (match && match[1].toUpperCase() === suffix && Number(match[2]) > 0) return true;
  }
  return false;
}

export async function validatePasswordPolicy(password, context = {}, breachedLookup = isBreachedPassword) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 128) {
    return { valid: false, code: 'PASSWORD_LENGTH', message: 'Password must be 12–128 characters.' };
  }
  const candidate = comparable(password);
  const blockedContext = contextTerms(context).some((term) => candidate.includes(term));
  if (blockedContext) return { valid: false, code: 'PASSWORD_CONTEXT', message: 'Password must not contain ArixShield, your email name, or your project name.' };
  if (isCommonPassword(password)) return { valid: false, code: 'PASSWORD_COMMON', message: 'Choose a less common password that is not based on a predictable password pattern.' };
  if (await breachedLookup(password)) return { valid: false, code: 'PASSWORD_BREACHED', message: 'This password appears in known breach data. Choose a different password.' };
  return { valid: true };
}
