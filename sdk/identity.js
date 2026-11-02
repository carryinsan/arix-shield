/** Remove an accidentally appended client IP from stable identity strings. */
export function sanitizeArixIdentity(value, clientIp) {
  let identity = String(value ?? '').trim();
  const ip = String(clientIp ?? '').trim();
  if (!ip) return identity.slice(0, 180);
  if (identity === ip) return '';
  for (const separator of [':', '|']) {
    const suffix = `${separator}${ip}`;
    if (identity.endsWith(suffix)) {
      identity = identity.slice(0, -suffix.length).trim();
      break;
    }
  }
  return identity.slice(0, 180);
}
