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

## Verification performed

- Repository tests against a clean extraction of the final ZIP: **207 passed, 0 failed, 0 skipped** (`npm test`); 10 targeted tests cover the framework-independent Vercel proxy entrypoint and edge-clearance policy.
- Static/syntax/import/integrity check against that extracted ZIP: **passed** (`npm run check`): 113 JS/MJS modules syntax-checked, 66 API/SDK imports resolved, static scanner passed, and the 116-file integrity manifest verified.
- External brutal test pack v1.0.0 against a clean extraction of the final ZIP: **30 passed, 0 failed, 0 skipped**; 50,000 soak operations; 12 OS processes in cross-process race scenarios. Latest 256 KiB inspection: **p50 2.48 ms, p99 4.38 ms, max 37.10 ms** against the 5 ms p99 gate. The 5 ms p99 threshold passed by 0.91 ms. Individual maximum samples exceeded 5 ms and are reported rather than hidden.
- In the same final-ZIP external run, the runtime guard observed event-loop lag p99 of **52.07 ms** and raised `EVENT_LOOP_LAG`. The assertion that health reporting preserves authenticated traffic under observed overload passed. This is an observed load/host signal, not a claim that the process stayed within its healthy-lag target.
- ZIP integrity: final archive opened and passed CRC verification; 166 entries, no duplicate paths, includes `proxy.js` and `proxy-core.js`, excludes obsolete root `middleware.js`.

## Repeatability / interpretation

The latency numbers are measurements from one local run on Node.js v22.16.0/Linux x64. They are not a stable latency guarantee; host contention and runtime conditions can change p99 and max values. A passing synthetic p99 does not prove production latency.

The external pack itself states that it is not an independent penetration test, formal verification, ASVS certification, or proof of production resilience. The local run does not exercise a real customer Upstash endpoint, production databases, external identity provider, CDN/WAF, production PKI/mTLS, kernel firewall, WAN traffic, or true distributed Redis atomicity. Passing this pack does **not** establish OWASP ASVS 5.0.0 Level 3 compliance.

No claim is made that software is bug-free or that no undiscovered vulnerability exists. These results are bounded to the code, test versions, runtime, and environment stated above.

## Vercel deployment failure remediation

The provided Vercel logs showed `ERR_MODULE_NOT_FOUND: Cannot find package 'next' imported from /var/task/middleware.js`, followed by `MIDDLEWARE_INVOCATION_FAILED`. The archive no longer contains the legacy root `middleware.js`. It now configures `proxy.js` with Vercel's framework-independent `proxy.entrypoint` and uses the standard `Request` API plus pinned `@vercel/functions@3.10.5` for request continuation. The HMAC clearance domain, HKDF salt/info, payload format, TTL ceiling, audience/path/method checks and fail-closed 403/503 behavior are preserved.

Ten targeted middleware tests passed. This is not a live Vercel deployment test; deployment-time installation of the Vercel helper and routing behavior must still be confirmed by the next production deployment.
