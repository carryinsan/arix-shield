# ArixShield v1.4.4 Consolidated Verification Summary

**Date:** 2026-11-03  
**Runtime:** Node.js v22.16.0, Linux x64  
**Scope:** Consolidated source tree assembled from the three supplied ArixShield ZIP archives; local repository-level checks only.

## Current release-candidate checks

- `npm test`: **207 passed, 0 failed, 0 skipped** (182 top-level TAP tests; nested tests included in the total), approximately 5.2 seconds on this host.
- `npm run check`: **113 JavaScript/MJS syntax checks, 66 API/SDK imports, the exact runtime dependency allowlist (`@vercel/functions@3.10.5`), static scanner passed; 116-file source-integrity manifest verified**.
- `NODE_ENV=production npm run build`: **controlled build smoke passed** using temporary non-deployable secrets, a generated temporary RSA-3072 clearance key, and a dummy Upstash-shaped HTTPS URL/token. The build signs the manifest for its preflight; after the smoke run, both shipped manifests were regenerated unsigned. Test subprocesses had the dummy Redis URL/token removed. No real Redis endpoint or customer credential was used.
- ZIP integrity: all three supplied source archives passed CRC/integrity checks. The final archive is separately checked after packaging.

## Focused coverage in the merged test suite

The suite exercises API/SDK policy and tenant controls, crypto and key handling, parser and request limits, origin proof/replay protections, edge gateway behavior, egress guard limits, PostgreSQL RLS helper behavior with injected clients, host-attestation logic, gateway admission/configuration boundaries, rate limiting, failure handling, and regression workflows. Tests using injected clients or local in-process adapters do **not** establish that a live customer database, Redis instance, firewall, CDN, or host is correctly configured.

## Not executed / not proven

- No production deployment, customer Upstash endpoint, live PostgreSQL/MySQL/SQLite database, external webhook, customer TLS certificates, or customer identity provider was available.
- No Docker/Podman executable was available on this host; hardened Compose profiles were not launched.
- The final merged gateway's actual TLS handshake and mTLS certificate exchange were not independently rerun against customer PKI. Configuration and negative-startup behavior are covered by local tests; deployer-side handshake validation remains required.
- `npm run audit:verify` was not run because no real signed audit bundle and production signing secret were supplied.
- Strict host attestation cannot be established from this build environment; the test container is not evidence of a hardened production host.
- The historical 100k corpus and endurance reports in `results/` were not rerun on this consolidated v1.4.4 tree. Their original report scope remains applicable only to those earlier runs.
- No independent SAST/SCA/secret scan, DAST, external penetration test, formal ASVS assessment, or infrastructure review was performed as part of this local merge.

**Conclusion:** the consolidated code tree passes its current deterministic regression suite, static checks, and a controlled production-build preflight smoke. This is a strong local release candidate, not proof of zero vulnerabilities, global DDoS resistance, production deployment correctness, or OWASP ASVS 5.0.0 Level 3 compliance.

## Vercel Routing Middleware deployment correction (2026-11-03)

- Removed the legacy root `middleware.js` which imported `NextResponse` from `next/server` despite this project not being a Next.js application.
- Added root `proxy.js` as the configured Vercel Routing Middleware `proxy.entrypoint`, using the standard Web `Request` API and the pinned first-party `@vercel/functions@3.10.5` `next()` helper. No Next.js framework dependency is added.
- Added `proxy-core.js` and 10 targeted tests covering disabled pass-through, static exclusions, missing/short secret fail-closed behavior, malformed/tampered tokens, header and cookie clearance, duplicate-cookie rejection, origin/path/method binding, invalid URLs, and deployment configuration.
- The API runtime-integrity path allowlist was updated to permit the new root proxy modules.
- Verification: 207/207 repository tests; `npm run check` passed (113 JS/MJS syntax checks, 66 API/SDK imports, 116-entry manifest); controlled production-build preflight passed using disposable test-only values.
- Supplied brutal test pack v1.0.0: 30/30 passed against a clean extraction of the final ZIP, with 50,000 soak operations and 12 OS race workers. 256 KiB inspection p50 was 2.48 ms, p99 4.38 ms (5 ms gate), max 37.10 ms. Event-loop lag p99 was 52.07 ms and the runtime guard raised `EVENT_LOOP_LAG`; the assertion preserving authenticated traffic under load passed.

**Deployment limitation:** this is local source/build/test verification. The target Vercel project was not deployed from this environment, so confirm that the next Vercel production deployment installs `@vercel/functions@3.10.5`, recognizes `proxy.entrypoint`, and serves `/` and `/arix-client.js` successfully.
