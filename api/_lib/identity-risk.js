const clamp = (value, min = 0, max = 100) => Math.max(min, Math.min(max, value));

/**
 * Transparent risk heuristic. It is a step-up signal, not an identity verdict.
 * Callers must supply observations from trusted server-side telemetry.
 */
export function evaluateLoginRisk({
  knownDevice = false,
  boundPasskey = false,
  failedLoginCount = 0,
  newCountry = false,
  newAsn = false,
  impossibleGeoVelocity = false,
  deviceKeyContinuity = false,
  activeConcurrentSessions = 0,
  trustedRecoveryFlow = false
} = {}) {
  let score = 0;
  const reasons = [];
  if (knownDevice || boundPasskey) { score -= 25; reasons.push('KNOWN_DEVICE'); }
  score += clamp(Math.max(0, Number(failedLoginCount) || 0), 0, 5) * 15;
  if (failedLoginCount > 0) reasons.push('RECENT_FAILURES');
  if (newCountry) { score += 15; reasons.push('NEW_COUNTRY'); }
  if (newAsn) { score += 15; reasons.push('NEW_ASN'); }
  if (impossibleGeoVelocity && !deviceKeyContinuity) { score += 35; reasons.push('IMPOSSIBLE_GEO_VELOCITY'); }
  if (Number(activeConcurrentSessions) > 0) { score += Math.min(20, Number(activeConcurrentSessions) * 5); reasons.push('CONCURRENT_SESSIONS'); }
  if (trustedRecoveryFlow) { score += 20; reasons.push('RECOVERY_FLOW'); }
  score = clamp(score);
  const decision = score >= 70 ? 'challenge' : score >= 40 ? 'step-up' : 'allow';
  return Object.freeze({ riskScore: score, decision, reasons: Object.freeze(reasons) });
}
