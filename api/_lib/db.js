// Central reviewed database integration surface. Keep application driver imports
// and connection construction here; route handlers should call the scoped runner.
export { withTenantTransaction, verifyDatabaseRlsActive } from './db-guard.js';
export { protectPrismaClient } from '../../sdk/context.js';
