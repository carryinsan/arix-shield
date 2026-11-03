// Public request-context surface. Receipt issuance is intentionally internal.
export { SCOPED_RECEIPT, hasScopedDataReceipt, getArixRequestId, runWithArixContext, getArixContext, protectPrismaClient } from './context-internal.js';
