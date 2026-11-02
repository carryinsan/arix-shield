import { createHmac } from 'node:crypto';

const MAX_ACTORS = 20_000;
const actorState = new Map();

function normalizeRoute(route) {
  return String(route || '/').split('?')[0].split('/').map((part) => {
    if (/^\d+$/.test(part) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(part)) return ':id';
    return part.slice(0, 64);
  }).join('/').slice(0, 256) || '/';
}

function boundedState(actorId, now) {
  const id = String(actorId || '').slice(0, 256);
  let state = actorState.get(id);
  if (!state) {
    if (actorState.size >= MAX_ACTORS) {
      const first = actorState.keys().next().value;
      if (first !== undefined) actorState.delete(first);
    }
    state = { routes: [], times: [], updatedAt: now };
    actorState.set(id, state);
  }
  state.updatedAt = now;
  return state;
}

/** Adds bounded Markov-transition and inter-arrival timing signals. */
export function scoreEndpointTransition({ actorId, method = 'GET', route = '/', now = Date.now(), baseline = {}, maxHistory = 8 } = {}) {
  if (!actorId) throw new TypeError('actorId is required');
  const state = boundedState(actorId, now);
  const current = `${String(method).toUpperCase().slice(0, 8)} ${normalizeRoute(route)}`;
  const previous = state.routes.at(-1);
  const transitionKey = previous ? `${previous} -> ${current}` : `START -> ${current}`;
  const count = Number(baseline[transitionKey] || 0);
  const total = Number(baseline[`${previous || 'START'} -> *`] || 0);
  const probability = total > 0 ? count / total : null;
  let transitionRisk = probability === null ? 0 : probability < 0.001 ? 30 : probability < 0.01 ? 15 : 0;
  if (!previous && /POST (?:\/api\/)?(?:auth|checkout|payment)(?:\/|$)/i.test(current)) transitionRisk = Math.max(transitionRisk, 20);
  state.routes.push(current);
  if (state.routes.length > Math.min(8, Math.max(2, maxHistory))) state.routes.shift();
  state.times.push(now);
  if (state.times.length > 10) state.times.shift();
  const intervals = state.times.slice(1).map((time, index) => Math.max(0, time - state.times[index]));
  const mean = intervals.length ? intervals.reduce((sum, value) => sum + value, 0) / intervals.length : 0;
  const variance = intervals.length ? intervals.reduce((sum, value) => sum + ((value - mean) ** 2), 0) / intervals.length : 0;
  const cv = mean > 0 ? Math.sqrt(variance) / mean : null;
  const ratePerSecond = mean > 0 ? 1000 / mean : 0;
  const timingRisk = ratePerSecond > 3 && cv !== null && cv < 0.08 ? 30 : 0;
  return Object.freeze({ route: current, transitionKey, transitionProbability: probability, transitionRisk, timingCv: cv, ratePerSecond, timingRisk, riskScore: Math.min(60, transitionRisk + timingRisk), history: Object.freeze([...state.routes]) });
}

export function createBlindedIndicator({ masterSecret, ja4 = '', ipPrefix = '' } = {}) {
  if (typeof masterSecret !== 'string' || Buffer.byteLength(masterSecret) < 32) throw new TypeError('masterSecret must be at least 32 bytes');
  if (!ja4 && !ipPrefix) throw new TypeError('at least one indicator input is required');
  const material = `blinded-v1:${String(ja4).slice(0, 128)}:${String(ipPrefix).slice(0, 64)}`;
  return createHmac('sha256', masterSecret).update(material).digest('hex');
}

export function resetBotIntelStateForTests() { actorState.clear(); }

/** A single high-confidence automation indicator must exceed the default clearance ceiling. */
export function calculateAutomationRiskScore({ strongAutomationSignal = false, signalCount = 0, tlsMismatch = false } = {}) {
  const count = Math.max(0, Math.min(7, Math.floor(Number(signalCount) || 0)));
  if (!strongAutomationSignal && count < 2) return 0;
  const base = strongAutomationSignal ? 55 : 45;
  const additional = Math.max(0, count - (strongAutomationSignal ? 1 : 0)) * 5;
  return Math.min(70, base + additional + (tlsMismatch ? 5 : 0));
}
