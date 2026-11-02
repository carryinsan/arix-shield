import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateAutomationRiskScore } from '../api/_lib/bot-intel.js';

test('one high-confidence automation signal exceeds the default browser-clearance risk ceiling', () => {
  const score = calculateAutomationRiskScore({ strongAutomationSignal: true, signalCount: 1 });
  assert.equal(score, 55);
  assert.ok(score > 50);
});

test('isolated weak browser signals remain zero-risk while correlated signals are challenged', () => {
  assert.equal(calculateAutomationRiskScore({ signalCount: 1 }), 0);
  assert.equal(calculateAutomationRiskScore({ signalCount: 2 }), 55);
  assert.equal(calculateAutomationRiskScore({ strongAutomationSignal: true, signalCount: 1, tlsMismatch: true }), 60);
});
