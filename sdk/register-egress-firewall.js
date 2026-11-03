import { installProcessEgressFirewall } from './process-egress-firewall.js';

// Use with `node --import arixshield/register-egress-firewall app.mjs`.
// It is deliberately inert unless the operator explicitly enables the guard.
export const egressFirewallStatus = installProcessEgressFirewall({
  enabled: process.env.ARIX_PROCESS_EGRESS_FIREWALL === 'true'
});
