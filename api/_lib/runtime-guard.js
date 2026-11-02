import { monitorEventLoopDelay } from 'node:perf_hooks';
import { getHeapStatistics } from 'node:v8';

export function createRuntimeGuard({ lagThresholdMs = 85, heapThreshold = 0.85, resolution = 10 } = {}) {
  if (!Number.isFinite(lagThresholdMs) || lagThresholdMs < 1 || !Number.isFinite(heapThreshold) || heapThreshold <= 0 || heapThreshold >= 1) throw new TypeError('Invalid runtime guard thresholds');
  const histogram = monitorEventLoopDelay({ resolution: Math.max(1, Math.floor(resolution)) });
  let started = false;
  return Object.freeze({
    start() { if (!started) { histogram.enable(); started = true; } },
    stop() { if (started) { histogram.disable(); started = false; } },
    checkRuntimeHealth({ authenticated = false } = {}) {
      const heap = getHeapStatistics();
      const lagP99Ms = Number(histogram.percentile(99)) / 1e6;
      const heapRatio = heap.heap_size_limit > 0 ? heap.used_heap_size / heap.heap_size_limit : 0;
      const reasons = [];
      if (started && Number.isFinite(lagP99Ms) && lagP99Ms > lagThresholdMs) reasons.push('EVENT_LOOP_LAG');
      if (heapRatio > heapThreshold) reasons.push('HEAP_PRESSURE');
      return Object.freeze({ healthy: reasons.length === 0, shedAnonymous: reasons.length > 0 && !authenticated, preserveAuthenticated: reasons.length > 0 && authenticated, reasons: Object.freeze(reasons), lagP99Ms: Number.isFinite(lagP99Ms) ? lagP99Ms : 0, heapRatio });
    }
  });
}
