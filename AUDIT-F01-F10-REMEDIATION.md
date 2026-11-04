# ArixShield v1.4.4 — F-01 through F-10 remediation report

This report records the code changes and local verification performed for the ten findings in the 4 November 2026 audit. It is not an independent penetration-test certificate and does not establish OWASP ASVS Level 3 compliance.

## Finding dispositions

| ID | Finding | Disposition | Evidence / boundary |
|---|---|---|---|
| F-01 | WAF SQL comment/newline parser differential | Fixed | Canonical whitespace normalization now preserves CR/LF line boundaries so `--` and `#` comments terminate at the same boundary expected by the tokenizer. Regression test covers a newline followed by `UNION SELECT`. |
| F-02 | SQL grammar pre-filter misses boolean/comparison operators | Fixed | Pre-filter now checks `OR`, `AND`, `NOT`, comparison operators, and the additional SQL punctuation used by the grammar scanner. Regression corpus includes `<>`, `>`, `<`, and `!=` numeric boolean forms. |
| F-03 | PostgreSQL tenant guard bypass and raw Prisma/MySQL transaction callbacks | Hardened | PostgreSQL guard rejects Unicode-escaped identifier syntax and SQL-in-string execution helpers; Prisma PostgreSQL transactions verify a non-superuser/non-BYPASSRLS role and expose guarded raw-query methods; MySQL callbacks receive a restricted facade that blocks session-variable mutation and raw transaction/control commands. Live PostgreSQL/MySQL integration tests were not run; MySQL has no native PostgreSQL-style RLS and still requires an application/database design that enforces tenant predicates. |
| F-04 | Java-serialization signatures erased by control-byte normalization | Fixed | Non-SQL rules inspect original string content before canonicalization, then inspect canonical text as well. Regression test covers escaped and raw serialization markers. |
| F-05 | Audit-chain CAS contention prevents automatic containment/alert processing | Fixed | Critical event processing isolates audit append failure; containment is attempted independently, and alert delivery/queueing proceeds with `auditUnavailable` metadata. Regression test injects an audit CAS failure and webhook delivery failure. |
| F-06 | DPoP replay cache window shorter than accepted `iat` window and FIFO eviction | Hardened | Local replay TTLs now cover the full accepted timestamp windows (90 seconds for ±45s request-bound proofs, 120 seconds for ±60s standard proofs). Unexpired entries are not FIFO-evicted; the bounded cache rejects new entries when full. The SDK request path additionally requires the shared control-plane one-use replay consume operation and fails closed when that service is unavailable. The in-process cache is not a cross-instance replay database. |
| F-07 | Duplicate JSON scanner node/depth limit | Not reproduced as a WAF bypass; fail-closed behavior made explicit | On complexity exhaustion, the scanner now returns `limitExceeded` and `inspectRequest` emits `JSON_COMPLEXITY_LIMIT`. The prior WAF path already rejected the malformed/over-complex raw JSON; it did not accept the request. Regression test asserts explicit rejection. |
| F-08 | Repeated capability query IDs and shallow ownership traversal | Fixed | Repeated resource-ID query values are accepted only for explicitly allowlisted array fields, each value is verified and rewritten, and the list is bounded. Ownership mismatch detection now recursively traverses nested objects and arrays with depth/node limits and treats limit exhaustion as a mismatch. Short known-prefixed IDs are recognized. |
| F-09 | Session rotation causes concurrent-request family revocation and global device logout | Fixed | Old cookies are always rejected; a 15-second concurrency grace period prevents in-flight old-cookie requests from revoking the newly rotated family. Replay after grace revokes that family. Routine rotation no longer revokes other device families. |
| F-10 | `Set-Cookie` array joined into one comma-separated header | Fixed | The Vercel response shim appends each `Set-Cookie` array item as a separate header value. Regression test uses `Headers.getSetCookie()` to verify both cookies remain separate. |

## Regression coverage

Added `test/audit-latest-regressions.test.js` and updated the legacy session-rotation regression to match the corrected grace-window semantics. The full suite contains 259 tests across 234 top-level test cases.

The test script and production build test invocation run serially (`--test-concurrency=1`) to avoid worker contention and nondeterministic resource pressure in constrained CI/build environments. This changes test execution scheduling only; it does not skip tests or alter test assertions.

## Verification performed

- `npm run check`: passed after manifest regeneration.
- `npm test`: 259 passed, 0 failed, 0 skipped (serial run).
- Targeted F-01..F-10 regression tests: passed.
- Runtime integrity manifest: 123 source entries; checked locally after regeneration.
- A production build preflight was run with temporary CI-only credentials and a temporary RSA key; these values were not written into the archive. The final source manifest was then regenerated unsigned so the deployer's Vercel build can sign it with the real `ARIX_MASTER_SECRET`.
- Fresh ZIP extraction, syntax/import verification, and the full test suite were run on the packaged copy.

## Remaining release limitations

- No live Vercel production deployment was triggered from this environment.
- No live Upstash, PostgreSQL, MySQL, email, or external webhook integration was available for end-to-end testing.
- The repository still has no `package-lock.json`. An attempt to generate one timed out while contacting the npm registry. Do not treat dependency installation/audit as reproducible until a network-connected Node.js 22/npm 10 environment runs `npm install --package-lock-only`, `npm ci`, and `npm audit --omit=dev --audit-level=low`, then commits the resulting genuine lockfile.
- Local DPoP replay maps are per process; cross-instance replay protection depends on the required shared control-plane one-use consume operation.
- No claim is made that the software is vulnerability-free, that every deployment integration is secure, or that it has achieved a formal security certification.
