# Chat 5 targeted remediation — verification record

Date: 2026-11-03  
Target: ArixShield v1.4.4 consolidated source  
External test pack: ArixShield Brutal Security Test Pack v1.0.0  
Runtime: Node.js v22.16.0, Linux x64

## Findings and changes

1. **Slow-drip request body** — the gateway now applies an explicit monotonic whole-body deadline rather than depending only on Node's socket/request timeout behavior. It stops reading at the configured deadline, closes the affected request, and releases reserved buffered-byte accounting on all completion/error paths.
2. **ZIP local-record aliasing** — ZIP inspection now rejects repeated canonical entry names, repeated local-header offsets, and overlapping local-record byte ranges. A regression fixture with two different central-directory names pointing to one local header is rejected.
3. **Non-finite JSON number** — WAF structure inspection rejects non-finite numeric values, JSON Schema validation rejects them, and raw JSON scanning detects number literals such as `1e309` that overflow JavaScript's finite number range. Finite negative zero remains valid.
4. **Request inspection latency** — WAF canonicalization avoids unnecessary full-buffer decode/normalization work on ordinary text, and SQL grammar pre-screening avoids uppercasing oversized identifiers. Detection logic remains enabled; no rules were disabled to achieve the measurement.

## Verification performed

- Repository tests: **197 passed, 0 failed** (`npm test`).
- Static/syntax/import/integrity check: **passed** (`npm run check`): 111 JS modules syntax-checked, 66 imports resolved, static scanner passed, integrity manifest verified for 114 tracked source files.
- External brutal test pack on the corrected source tree: **30 passed, 0 failed, 0 skipped**; 50,000 soak operations; 12 OS processes in the cross-process race scenarios. 256 KiB inspection: **p50 2.45 ms, p99 4.23 ms, max 31.94 ms**.
- The final ZIP was extracted and tested as a packaged copy: external pack **30 passed, 0 failed, 0 skipped**. 256 KiB inspection: **p50 2.37 ms, p99 4.31 ms, max 31.26 ms** against the pack's **5 ms p99** gate. Both p99 gates passed; maximum individual samples exceeded 5 ms and are reported rather than hidden.
- Runtime guard observed event-loop lag p99 of **52.04 ms** on the source-tree run and **51.48 ms** on the packaged-copy run, raising its `EVENT_LOOP_LAG` signal in both. The test asserting that health reporting preserves authenticated traffic under observed overload passed in both runs. This is an observed load/host signal, not a claim that the process stayed within the healthy-lag target.

## Repeatability / interpretation

A previous extraction-level run of an earlier packaged candidate passed 29/30 tests; its only failure was the strict local p99 gate at 5.40 ms. The corrected source and final packaged-copy runs both pass, at 4.23 ms and 4.31 ms p99 respectively. This variation demonstrates that the 5 ms microbenchmark gate is host/load-sensitive; the two passing runs do not erase the earlier observed failure.

The external pack itself states that it is not an independent penetration test, formal verification, ASVS certification, or proof of production resilience. The local run does not exercise a real customer Upstash endpoint, production databases, external identity provider, CDN/WAF, production PKI/mTLS, kernel firewall, WAN traffic, or true distributed Redis atomicity. Passing this pack does **not** establish OWASP ASVS 5.0.0 Level 3 compliance.

No claim is made that software is bug-free or that no undiscovered vulnerability exists. These results are bounded to the code, test versions, runtime, and environment stated above.
