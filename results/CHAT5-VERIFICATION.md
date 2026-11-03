# Chat 5 targeted remediation — verification record

Date: 2026-11-03  
Target: ArixShield v1.4.4 consolidated source and final ZIP  
External test pack: ArixShield Brutal Security Test Pack v1.0.0  
Runtime: Node.js v22.16.0, Linux x64

## Findings and changes

1. **Slow-drip request body** — the gateway now applies an explicit monotonic whole-body deadline rather than depending only on Node's socket/request timeout behavior. It stops reading at the configured deadline, closes the affected request, and releases reserved buffered-byte accounting on all completion/error paths.
2. **ZIP local-record aliasing** — ZIP inspection now rejects repeated canonical entry names, repeated local-header offsets, and overlapping local-record byte ranges. A regression fixture with two different central-directory names pointing to one local header is rejected.
3. **Non-finite JSON number** — WAF structure inspection rejects non-finite numeric values, JSON Schema validation rejects them, and raw JSON scanning detects number literals such as `1e309` that overflow JavaScript's finite number range. Finite negative zero remains valid.
4. **Request inspection latency** — WAF canonicalization avoids unnecessary full-buffer decode/normalization work on ordinary text, and SQL grammar pre-screening avoids uppercasing oversized identifiers. Detection logic remains enabled; no rules were disabled to achieve the measurement.
5. **Vercel build ticket-test regression** — canonical base64url checks now reject non-canonical trailing-pad-bit aliases in both payload and signature segments in the Node verifier and framework-independent edge proxy. The test suite uses deterministic byte-equivalent aliases rather than a fixed random-dependent final character.

## Verification performed

- Repository tests after the Vercel ticket-alias correction: **207 passed, 0 failed, 0 skipped** (`npm test`); 10 targeted tests cover the framework-independent Vercel proxy entrypoint and edge-clearance policy; the two canonical-alias targeted tests also passed.
- Static/syntax/import/integrity check against that extracted ZIP: **passed** (`npm run check`): 113 JS/MJS modules syntax-checked, 66 API/SDK imports resolved, static scanner passed, and the 116-file integrity manifest verified.
- External brutal test pack v1.0.0 after the fix, against a clean extraction: final clean-ZIP extraction rerun **30 passed, 0 failed, 0 skipped**; 50,000 soak operations; 12 OS processes in cross-process race scenarios. Latest 256 KiB inspection: **p50 2.41 ms, p99 4.54 ms, max 32.20 ms** against the unchanged 5 ms p99 gate. One preceding local rerun measured 5.05 ms and failed only that performance assertion; the clean-ZIP rerun passed, with no threshold change. Individual maximum samples above 5 ms are reported rather than hidden.
- In the latest clean-extraction external run, the runtime guard observed event-loop lag p99 of **53.90 ms** and raised `EVENT_LOOP_LAG`. The assertion that health reporting preserves authenticated traffic under observed overload passed. This is an observed load/host signal, not a claim that the process stayed within its healthy-lag target.
- ZIP integrity: final archive opened and passed CRC verification; 166 entries, no duplicate paths, includes `proxy.js` and `proxy-core.js`, excludes obsolete root `middleware.js`.

## Repeatability / interpretation

The latency numbers are measurements from one local run on Node.js v22.16.0/Linux x64. They are not a stable latency guarantee; host contention and runtime conditions can change p99 and max values. A passing synthetic p99 does not prove production latency.

The external pack itself states that it is not an independent penetration test, formal verification, ASVS certification, or proof of production resilience. The local run does not exercise a real customer Upstash endpoint, production databases, external identity provider, CDN/WAF, production PKI/mTLS, kernel firewall, WAN traffic, or true distributed Redis atomicity. Passing this pack does **not** establish OWASP ASVS 5.0.0 Level 3 compliance.

No claim is made that software is bug-free or that no undiscovered vulnerability exists. These results are bounded to the code, test versions, runtime, and environment stated above.

## Vercel deployment failure remediation

The provided Vercel logs showed `ERR_MODULE_NOT_FOUND: Cannot find package 'next' imported from /var/task/middleware.js`, followed by `MIDDLEWARE_INVOCATION_FAILED`. The archive no longer contains the legacy root `middleware.js`. It now configures `proxy.js` with Vercel's framework-independent `proxy.entrypoint` and uses the standard `Request` API plus pinned `@vercel/functions@3.10.5` for request continuation. The HMAC clearance domain, HKDF salt/info, payload format, TTL ceiling, audience/path/method checks and fail-closed 403/503 behavior are preserved.

Ten targeted middleware tests passed. This is not a live Vercel deployment test; deployment-time installation of the Vercel helper and routing behavior must still be confirmed by the next production deployment.


## Canonical edge-clearance ticket encoding regression

The Vercel build logs showed 206/207 tests passing; `grounded-hardening.test.js:57` was intermittently accepting a tampered ticket. The cause was non-canonical base64url pad-bit aliases, not a mismatch in the HMAC secret or ticket policy. Both ticket segments now require exact canonical re-encoding in Node and in the edge proxy. New tests assert that equivalent-byte aliases are rejected for the encoded payload and the signature, and the final controlled production build passed all 207 tests.

The final ZIP was extracted to a clean directory and the external pack passed 30/30; the preceding local run's 5.05 ms p99 miss is retained in the verification history to show benchmark variability. Event-loop lag (53.90 ms p99) continues to flag under synthetic pressure. The final archive has not been deployed to the live Vercel project from this environment.
