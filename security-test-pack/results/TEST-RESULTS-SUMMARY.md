# ArixShield Security Laboratory — Execution Summary

**Date:** 2026-11-02  
**Runtime:** Node.js v22.16.0, Linux x64  
**Scope:** supplied ArixShield v1.4.1 repository, local/in-process tests only

## Results

- Original baseline before adding this pack: **104 passed, 0 failed**.
- Expanded suite after adding this pack: **142 passed, 0 failed**, 117 top-level TAP tests including nested subtests; 4.97 s.
- Seeded fuzzer: **200,000 total vectors** (100,000 adversarial, 100,000 benign), 20 attack families, 7.827 s.
- Adversarial: 100,000 blocked, 0 missed (100% on the generated corpus).
- Benign: 100,000 allowed, 0 rejected (0% false-positive rate on the generated corpus).
- Precision: 100%; recall: 100%; FPR: 0% on the generated corpus.
- Per-request latency: p50 0.03092 ms, p95 0.07604 ms, p99 0.20464 ms, max 19.40238 ms.
- Fuzzer throughput: 25,552 vectors/s.
- Endurance: 456,321 local WAF calls in 15.00 seconds at 16 workers, 30,421 req/s, 0 invariant errors, peak heap 16.0 MiB and RSS 65.6 MiB.

## New test domains

Twenty-five runtime invariant probes; tenant/owner and field-level authorization; 500 tenant query-scope variations; 500 authenticated actor/method decisions; HTTP framing and canonicalization ambiguity corpus; 1,000 concurrent quota attempts; 1,000 concurrent concurrency leases; injected dependency faults; circuit-breaker timeout/abort; guarded Playwright target tests; ASVS ledger generator smoke test.

## Not executed / not proven

No live HTTP parser pair, reverse proxy, production DB/RLS, real Redis cluster, production identity provider, public network, deployed browser farm, multi-region topology, HSM, TLS edge, or multi-hour endurance deployment was available. Browser farm script is included but not run. ASVS full requirement matrix was not generated because the official complete ASVS JSON was not available to the local test runtime; the generator was verified against a fixture. The selected evidence map contains PARTIAL/NOT_ASSESSED states only where evidence supports it.

**Conclusion:** all executed local tests passed. This is strong regression and generated-corpus evidence, but it is not an independent penetration test, a proof of production resilience, or OWASP ASVS 5.0.0 Level 3 certification.
