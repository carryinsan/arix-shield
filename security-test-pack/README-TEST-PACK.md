# ArixShield v1.4.1 — Security Test-Only Pack

This ZIP intentionally contains **tests, test runners, evidence metadata, and captured results only**. It does not contain ArixShield application source, secrets, customer data, or production credentials. The tests import ArixShield modules from the original checkout, so overlay these files into a clean copy of the same ArixShield v1.4.1 repository before running them.

## What ran in this environment

Runtime: Node.js v22.16.0, Linux x64, seed `20261102` for the 200,000-vector lab.

| Run | Observed result |
|---|---:|
| Original repository baseline | 104 passed, 0 failed |
| Expanded suite | 142 passed, 0 failed (117 top-level TAP tests; nested tests included in total) |
| Generated security corpus | 100,000 adversarial + 100,000 benign; 20 adversarial families |
| Adversarial detection in generated corpus | 100,000/100,000 blocked; 0 misses |
| Benign acceptance in generated corpus | 100,000/100,000 allowed; 0 false positives |
| Precision / recall / FPR | 100% / 100% / 0% on this labelled corpus |
| p50 / p95 / p99 request latency | 0.03092 / 0.07604 / 0.20464 ms |
| Maximum observed request latency | 19.40238 ms |
| Corpus throughput | 25,552 vectors/s |
| Endurance run | 456,321 requests in 15 seconds, 16 local workers, 0 invariant errors |
| Endurance throughput | 30,421 requests/s; peak RSS 65.6 MiB |

Full details and machine-readable output are in `results/`.

## Run the test suite

Requires Node.js 22.x and a full ArixShield v1.4.1 source checkout. From the checkout root after overlaying this pack:

```bash
node --test test/*.test.js
```

The TAP transcript in this ZIP is from the same command on the test host; regenerate it with:

```bash
node --test --test-reporter=tap test/*.test.js > results/full-test.tap.txt
```

## Run the 100k + 100k deterministic lab

```bash
node scripts/run-100k-lab.mjs --seed 20261102 --adversarial 100000 --benign 100000 --out-dir results
```

The fuzzer uses a reproducible XorShift128+ seed and randomized per-vector tokens/values. Its adversarial corpus is balanced across 20 categories: SQLi boolean/UNION, XSS, NoSQL, SSRF, SSTI, LDAP, XXE, GraphQL depth, multipart and binary magic mismatch, HTTP/1 framing ambiguity, HTTP/2 forbidden framing, nested encoding, parameter pollution, prototype pollution, unsafe deserialization, prompt injection, image pixel flood, and ZIP expansion ratio. The benign corpus includes code, math, JSON, HTTP/security documentation, punctuation edge cases, and text across Hindi, Gujarati, Arabic, Japanese, Korean, French, Spanish, Portuguese, Russian, Chinese, Thai and Māori.

The precision/recall/FPR values describe only this generated labelled corpus. They are **not** population-wide estimates, proof of no false positives in production, or a substitute for an independently curated corpus. Image and ZIP vectors call the file-inspection helpers directly; they do not execute a production upload pipeline or malware sandbox.

## Run longer endurance tests

```bash
node scripts/run-endurance.mjs --duration-ms 3600000 --concurrency 16
```

The duration is bounded to 24 hours and concurrency to 64. This runner invokes the WAF in-process: it does not create sockets, load a deployed app, or measure network/database/Redis throughput. The recorded 15-second run is a smoke/endurance sample, not a multi-hour soak.

## Optional Playwright browser farm

Install Playwright in the ArixShield checkout if it is not already available, then point the runner only at a local or reserved `.test` staging hostname:

```bash
ARIX_BROWSER_BASE_URL=http://localhost:3000 \
ARIX_BROWSER_WORKERS=8 \
ARIX_BROWSER_ROUTES=/,/login,/dashboard \
node scripts/run-browser-farm.mjs
```

An authenticated Playwright storage-state JSON can be supplied using `ARIX_PLAYWRIGHT_STORAGE_STATE=/secure/path/state.json`. Keep it outside this ZIP and protect it as a credential. The runner is deliberately read-only, limits concurrency to 40, refuses public hosts, blocks cross-origin subresources, and performs GET navigations only. It was **not executed** in this run because no staging app/browser environment was provided.

## ASVS 5.0.0 Level 3 evidence ledger

`docs/asvs-evidence-map.json` maps selected controls to source symbols and test names with explicit `PARTIAL` or `NOT_ASSESSED` statuses. `docs/ASVS-5.0.0-L3-VERIFICATION-MATRIX.md` describes chapter-by-chapter evidence and known gaps. It is an honest partial evidence index, not a complete compliance attestation.

To generate a row for every requirement from OWASP's canonical ASVS 5.0.0 English JSON, obtain that official file from https://asvs.owasp.org/downloads/ and run:

```bash
node scripts/asvs-l3-verifier.mjs \
  --asvs-json /path/to/OWASP_Application_Security_Verification_Standard_5.0.0_en.json \
  --repo-root /path/to/ArixShield \
  --evidence-map docs/asvs-evidence-map.json \
  --out-dir results
```

The verifier was smoke-tested with a small ASVS-shaped fixture. The official complete JSON could not be fetched in the test container, so a complete official requirement-by-requirement matrix was **not generated here**. Unmapped requirements remain `NOT_ASSESSED`, and missing evidence files are surfaced rather than inferred. A passing unit test is supporting evidence only.

ASVS Level 3 is a verification level, not a numeric grade or a product certification. An actual Level 3 assessment must evaluate all applicable requirements, obtain design/configuration/operational evidence, and include the real deployed application and supporting infrastructure.

## Coverage boundaries — read before interpreting the results

- **HTTP parser differential:** the included corpus verifies WAF rejection/canonicalization for ambiguous HTTP metadata. It does not compare two real HTTP stacks (for example, CDN/proxy versus origin parser) with packet-level traffic. That requires the actual ingress and origin versions/configuration.
- **Cross-tenant database:** 500 generated Prisma-like/Mongo query-scope cases plus authenticated owner/peer/foreign-admin/roleless/anonymous workflows are tested against ArixShield authorization helpers. No live customer database, PostgreSQL RLS, ORM adapter, or production tenant dataset was connected.
- **Authenticated attack workflows:** signed capability and authorization paths are exercised in-process with test actors and keys. No production identity provider or real customer session is used.
- **Network failure simulation:** DNS, timeout, reset, 429 and truncated-body errors are injected into circuit-breaker paths. It is not packet loss, TLS interception, NAT, DNS poisoning, or a live network fault-injection run.
- **Browser farm:** guarded Playwright runner is included but was not run against an actual staged UI.
- **Large-scale concurrency:** the 1,000-way quota/lease checks and 16-worker endurance loop run within one Node process using the local adapter. They do not establish cross-process, multi-region, Redis cluster, or DB locking correctness.
- **Long-duration endurance:** a 15-second run was captured. The included runner supports up to 24 hours, but no multi-hour result is claimed.
- **Runtime self-test:** 25 standalone invariant probes are included. The product's scheduled `api/_lib/security-self-test.js` was not changed because this archive is test-only; these probes do not imply the production cron now runs all 25 checks.
- **Threat model:** no public target, third-party system, real credentials, destructive action, or live payload execution is used. High-impact payloads are synthetic test strings or bounded metadata fixtures.

## Files

- `test/` — original ArixShield regression tests plus the added tenant, parser, runtime-invariant, chaos, browser-safety and ASVS-generator tests.
- `scripts/run-100k-lab.mjs` — seeded 200k corpus fuzzer and metrics.
- `scripts/run-endurance.mjs` — configurable local endurance driver.
- `scripts/run-browser-farm.mjs` — optional restricted Playwright farm.
- `scripts/asvs-l3-verifier.mjs` — official JSON-driven ASVS evidence ledger generator.
- `docs/` — selected evidence map and transparent coverage matrix.
- `results/` — exact run artifacts and TAP transcript.

**Do not describe these results as “ASVS Level 3 passed”, “9.8/10 certified”, or a production pentest.** The evidence supports a successful local code-level test run with the boundaries above.
