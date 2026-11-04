# ArixShield v1.4.4 — F-11 to F-13 remediation report

Date: 2026-11-04

## Scope

The uploaded `arix-shield-chat5-audit-final(2).zip` was extracted and reviewed. The three findings in the latest report were checked against the source in that archive. All three defects were reproduced at code/test level and addressed with targeted regression tests.

## F-11 — Authenticated local quota reset by changing the path or method

**Disposition: Confirmed and fixed.**

`buildLocalQuotaDimensions()` previously created the authenticated actor key with the default route binding. The effective quota identity therefore included the method and pathname. A caller that stayed authenticated but changed the path received a fresh local bucket.

Change:

- The authenticated local fallback now creates a single aggregate actor dimension independent of HTTP method and pathname.
- The actor bucket remains namespaced by the configured SDK scope (endpoint/server-key/tenant or project), so different configured projects remain isolated.
- The existing anonymous network-prefix aggregate, anonymous route budget, and verified-device dimension are unchanged.
- Removing per-route allocation for authenticated local fallback prevents authenticated path churn from filling the process-local quota map with unique route keys.

Regression tests:

- Direct limiter test: 10 requests allowed, then 20 calls across changing paths/methods denied; exactly one bucket allocated.
- Node SDK integration: 20 changing paths/methods for the same authenticated identity; 10 allowed and 10 returned 429 at the configured limit of 10.
- Next.js SDK integration: same 10/10 behavior.

Limit: process-local limits are per process/instance, not globally coordinated across serverless instances. Use distributed quota enforcement for service-wide budgets.

## F-12 — PostgreSQL RLS verifier conflates quoted and unquoted identifiers

**Disposition: Confirmed and fixed.**

The original normalizer lowercased the entire expression and removed double quotes. That could conflate a lowercase unquoted column (for example `tenantid`) with a distinct case-sensitive quoted column (for example `"TenantId"`).

Change:

- Policy-expression normalization is now token-aware for identifiers and string literals.
- Unquoted identifiers are case-folded as PostgreSQL does; quoted identifiers retain their exact case. A quoted lowercase identifier remains equivalent to its unquoted lowercase spelling.
- The expected expression uses the same quoted identifier form used by the provisioner.
- The provisioner's existing-policy query also checks `pg_depend` and `pg_attribute` to verify the exact tenant-column attribute number actually referenced by the policy expressions. Missing catalog evidence or a different referenced column fails closed as a policy conflict.

Regression tests:

- Existing lowercase `tenant_id` policy is accepted idempotently.
- A policy on lowercase `tenantid` is rejected when the configured tenant column is case-sensitive `"TenantId"`.
- A policy referencing the exact quoted `"TenantId"` column is accepted idempotently.
- The test asserts that the catalog query includes `pg_depend`, `pg_attribute`, and the configured column parameter.

Limit: tests use a mocked PostgreSQL migration client and verify SQL shape/decision logic. No live PostgreSQL server was available, so deployment-specific catalog behavior must still be exercised against the target PostgreSQL version and schema before production migration.

## F-13 — `arixSafeFetch` ignores configured response byte limits

**Disposition: Confirmed and fixed.**

The process egress firewall forwarded `maxResponseBytes`, but the safe transport accumulated responses against a fixed 8 MiB constant.

Change:

- `arixSafeFetch()` now validates `maxResponseBytes` as an integer from 1 KiB through 8 MiB, defaulting to the prior 8 MiB ceiling.
- The configured value is passed into the pinned HTTPS request path.
- The response reader rejects an oversized declared `Content-Length` before buffering and counts streamed chunks, aborting the response/request as soon as the configured cap is crossed.
- The global hard upper bound remains 8 MiB; configuring a larger value is rejected.

Regression tests:

- Process firewall forwards a configured 1 KiB ceiling to its safe transport.
- Streamed response exactly at 1 KiB is accepted.
- Streamed response above 1 KiB is rejected and the request is destroyed.
- A declared Content-Length above 1 KiB is rejected before reading the stream.
- Invalid below-minimum and above-maximum direct `arixSafeFetch` settings are rejected before network access.

Limit: response streaming behavior and option propagation were tested locally. No external HTTPS server integration was available.

## Verification

The focused regression group passed after the changes. The full repository suite, syntax/import/static checks, manifest verification, production preflight and fresh-extraction tests are recorded in `BUILD-REPORT.md` after this report is packaged.

## Release limitations

- The archive still does not contain a `package-lock.json`; no lockfile was fabricated. `npm ci` and `npm audit --omit=dev --audit-level=low` remain open release gates until a trusted network-connected Node.js 22/npm 10 environment generates and reviews the lockfile.
- No live Vercel deployment, live PostgreSQL migration, external HTTPS destination, or production shared-Redis fault test was performed.
- This report does not claim zero undiscovered vulnerabilities, formal OWASP ASVS certification, or that the project is bug-free.
