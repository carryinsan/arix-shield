import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const [openApiArg, policyArg, outputArg] = process.argv.slice(2);
if (!openApiArg || !policyArg || !outputArg) {
  process.stderr.write('Usage: node scripts/compile-policy.mjs <openapi.json> <route-policy.json> <output.json>\n');
  process.exit(2);
}
const openapi = JSON.parse(await readFile(resolve(openApiArg), 'utf8'));
const policies = JSON.parse(await readFile(resolve(policyArg), 'utf8'));
if (!openapi?.paths || !policies || typeof policies !== 'object' || Array.isArray(policies)) throw new Error('Invalid OpenAPI document or route policy map');
const operations = [];
for (const [path, pathItem] of Object.entries(openapi.paths)) {
  for (const method of ['get','head','options','post','put','patch','delete','trace']) {
    const operation = pathItem?.[method];
    if (!operation) continue;
    const key = `${method.toUpperCase()} ${path}`;
    const policy = policies[key];
    const explicitlyPublic = policy?.public === true;
    const roles = Array.isArray(policy?.roles) && policy.roles.length > 0;
    const permissions = Array.isArray(policy?.permissions) && policy.permissions.length > 0;
    if (!policy || (!explicitlyPublic && !roles && !permissions)) throw new Error(`POLICY_COVERAGE_MISSING: ${key}`);
    if (explicitlyPublic && (roles || permissions)) throw new Error(`POLICY_AMBIGUOUS_PUBLIC_AND_PROTECTED: ${key}`);
    const mutating = ['POST','PUT','PATCH','DELETE'].includes(method.toUpperCase());
    if (mutating && !explicitlyPublic && policy.tenantIsolated !== true) throw new Error(`TENANT_SCOPE_REQUIRED: ${key}`);
    if (mutating && policy.failOpen === true) throw new Error(`MUTATING_ROUTE_FAIL_OPEN: ${key}`);
    operations.push({ key, public: explicitlyPublic, roles: roles ? [...new Set(policy.roles.map(String))] : [], permissions: permissions ? [...new Set(policy.permissions.map(String))] : [], tenantIsolated: policy.tenantIsolated === true, failOpen: policy.failOpen === true });
  }
}
const covered = new Set(operations.map((item) => item.key));
const stale = Object.keys(policies).filter((key) => !covered.has(key));
const output = { schema: 'arix.route-policy.v1', default: 'deny', generatedAt: 'deterministic', operationCount: operations.length, operations, stalePolicyEntries: stale };
await writeFile(resolve(outputArg), `${JSON.stringify(output, null, 2)}\n`, { mode: 0o600 });
process.stdout.write(`Compiled ${operations.length} explicit route policies (${stale.length} stale policy entries). Default is deny.\n`);
