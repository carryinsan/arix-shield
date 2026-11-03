import { next } from '@vercel/functions';
import { createEdgeClearanceProxy } from './proxy-core.js';

// Framework-independent Vercel Routing Middleware. The optional clearance
// layer is disabled unless ARIX_EDGE_PROOF_REQUIRED is explicitly "true".
export default createEdgeClearanceProxy({ next });
