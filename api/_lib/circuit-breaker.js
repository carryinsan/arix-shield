const circuits = globalThis.__ARIX_CIRCUITS__ ??= new Map();

export class CircuitOpenError extends Error {
  constructor(key, retryAfterMs = 0) {
    super(`Circuit breaker is open for ${key}.`);
    this.name = 'CircuitOpenError';
    this.code = 'ARIX_CIRCUIT_OPEN';
    this.retryAfterMs = Math.max(0, retryAfterMs);
  }
}

function stateFor(key) {
  let state = circuits.get(key);
  if (!state) {
    state = { state: 'CLOSED', failures: 0, openedAt: 0, probe: null, lastError: null };
    circuits.set(key, state);
  }
  return state;
}

function openCircuit(state, now, openMs, error) {
  state.state = 'OPEN';
  state.openedAt = now;
  state.probe = null;
  state.lastError = error ? String(error.message || error).slice(0, 180) : null;
  state.openUntil = now + openMs;
}

/**
 * Shared in-process breaker. It opens after three failures or one operation
 * exceeding the latency budget. A single caller owns the HALF_OPEN probe.
 */
export async function runWithCircuit(key, operation, {
  tripAfterMs = 450,
  openMs = 10000,
  failureThreshold = 3,
  timeoutMs = tripAfterMs,
} = {}) {
  if (typeof operation !== 'function') throw new TypeError('Circuit operation must be a function.');
  const state = stateFor(String(key));
  const now = Date.now();
  if (state.state === 'OPEN') {
    if (now < state.openUntil) throw new CircuitOpenError(key, state.openUntil - now);
    state.state = 'HALF_OPEN';
  }
  if (state.state === 'HALF_OPEN' && state.probe) throw new CircuitOpenError(key, 1000);
  const controller = new AbortController();
  const started = performance.now();
  const timeout = Math.max(50, Math.min(30000, Number(timeoutMs) || tripAfterMs));
  let timer;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort(new Error('Circuit operation exceeded its latency budget.'));
      reject(new Error('Circuit operation timed out.'));
    }, timeout);
  });
  const operationPromise = Promise.resolve().then(() => operation(controller.signal));
  if (state.state === 'HALF_OPEN') state.probe = operationPromise;
  try {
    const result = await Promise.race([operationPromise, timeoutPromise]);
    const elapsed = performance.now() - started;
    if (elapsed > tripAfterMs) {
      openCircuit(state, Date.now(), openMs, new Error(`Slow operation (${Math.round(elapsed)}ms).`));
      throw new CircuitOpenError(key, openMs);
    }
    state.state = 'CLOSED';
    state.failures = 0;
    state.openUntil = 0;
    state.lastError = null;
    return result;
  } catch (error) {
    state.failures += 1;
    state.lastError = String(error?.message || error).slice(0, 180);
    if (state.state === 'HALF_OPEN' || state.failures >= failureThreshold || error?.name === 'AbortError' || /timed out/i.test(String(error?.message || ''))) {
      openCircuit(state, Date.now(), openMs, error);
    }
    throw error;
  } finally {
    clearTimeout(timer);
    if (state.probe === operationPromise) state.probe = null;
  }
}

export function getCircuitState(key) {
  const state = stateFor(String(key));
  return { state: state.state, failures: state.failures, openUntil: state.openUntil || 0, lastError: state.lastError };
}

export function resetCircuit(key) {
  circuits.delete(String(key));
}
