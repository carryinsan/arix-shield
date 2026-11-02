# OWASP ASVS 5.0.0 Level 3 — ArixShield verification status

**Assessment status: NOT CERTIFIED / NOT FULLY VERIFIED.** This is a transparent repository-level evidence index. The full requirement-by-requirement matrix is generated from OWASP's official 5.0.0 JSON using `scripts/asvs-l3-verifier.mjs`. The official standard contains approximately 350 requirements in 17 chapters; Level 3 assessment includes the applicable requirements across levels, not only rows labelled Level 3.

| Chapter | Topic | Current test evidence in this pack | Main gaps / external evidence needed |
|---|---|---|---|
| V1 | Encoding and Sanitization | Bounded canonicalization, injection signatures, XXE, nested encodings | Output-context encoding, all parser implementations, customer sinks, XPath/CSV/template/regex consumers |
| V2 | Validation and Business Logic | WAF schema/input checks, rate/concurrency limits, injected chaos | End-to-end business transactions, multi-party approval deployment, human-timing workflow integration |
| V3 | Web Frontend Security | Optional restricted Playwright smoke runner; browser target guard | Real browser farm, production CSP/COOP/CORP/HSTS, CSRF/CORS/JSONP/SRI, all browsers and routes |
| V4 | API and Web Service | Request framing, duplicate headers, HTTP/2 metadata, GraphQL limits | Real ingress/proxy/origin parser pairs; external service contracts; production API route inventory |
| V5 | File Handling | Binary magic mismatch, multipart parsing, ZIP expansion ratio, pixel-flood header checks | All upload/download paths, AV/YARA, full parser sandbox, storage quota, metadata stripping, real archive corpus |
| V6 | Authentication | Existing password/MFA/recovery regression tests | External IdP, all flows, credential-stuffing defenses under distributed production traffic, hardware-backed factors |
| V7 | Session Management | Existing session rotation, family revocation, expiry and replay tests | Deployed cookie settings, cross-device flows, session lifecycle across every app and identity provider |
| V8 | Authorization | Tenant/owner query scoping and authenticated actor/method matrix | Actual customer DB/RLS, every route, admin/device-posture controls, live cross-tenant database isolation |
| V9 | Self-contained Tokens | Existing DPoP, JWE, capability binding and replay tests | Independent token review, all issuer/audience/key-rotation paths and production trust configuration |
| V10 | OAuth and OIDC | No OAuth authorization server in the supplied repository; custom DPoP helpers only | OAuth/OIDC client/server, PAR/JAR, PKCE, sender-constrained token deployment, IdP configuration |
| V11 | Cryptography | KMS envelope, AES-GCM, purpose derivation and key-wrap unit tests | HSM isolation, cryptographic module assessment, RNG-under-load and side-channel analysis, key custody |
| V12 | Secure Communication | Safe-fetch URL/IP policy and origin-proof helper tests | Real TLS terminator/cipher/OCSP/ECH/mTLS and service-to-service certificate validation |
| V13 | Configuration | Existing static checks and fail-closed config regression tests | Production infrastructure, HSM/KMS, secret expiry/rotation, exposed-file/version checks |
| V14 | Data Protection | KMS tenant AAD and redaction-related unit tests | Data classification, retention/deletion, client cache/storage, file metadata sanitization, live DB encryption |
| V15 | Secure Coding and Architecture | Input tests, mass-assignment filtering, 1,000-way local concurrency tests | SBOM/SCA/AST taint analysis, sandbox/segmentation, production safe concurrency/TOCTOU/fairness |
| V16 | Security Logging and Error Handling | Audit-chain and circuit-breaker tests in existing suite; injected fault tests | Global last-resort handler, authorization decision completeness, external tamper-resistant storage/SIEM |
| V17 | WebRTC | No WebRTC/TURN/media server in supplied archive | Confirm out of scope, or separately assess TURN, DTLS, SRTP, recording and signaling flood behavior |

## Mapped requirement IDs

The evidence map currently links selected requirements to exact local source symbols and test names. It intentionally marks most items **PARTIAL** or **NOT_ASSESSED**. A local test does not prove control coverage in a customer's app or production infrastructure.

The full enumerator is intentionally data-driven. Obtain the canonical English JSON from the [OWASP ASVS 5.0.0 release downloads](https://asvs.owasp.org/downloads/) or the [OWASP/ASVS v5.0.0 source branch](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0), then run:

```bash
node scripts/asvs-l3-verifier.mjs \
  --asvs-json /path/to/OWASP_Application_Security_Verification_Standard_5.0.0_en.json \
  --repo-root /path/to/ArixShield \
  --out-dir results
```

This emits a row for every requirement, its ASVS level, official requirement statement, mapped evidence files, symbol, test, and remaining caveat. Unmapped requirements remain `NOT_ASSESSED`; missing paths are surfaced. The script does not award compliance automatically.

## Limitations

- No ASVS certification or independent assessment is implied.
- Customer route wiring, actual database authorization/RLS and production tenancy are outside the supplied repository.
- Browser, reverse proxy, TLS, cloud, edge, SIEM, HSM, antivirus, container and multi-region tests require the real staging environment and corresponding infrastructure.
- ArixShield's own build report documents that this package is an application-layer security SDK, not a network-layer DDoS scrubbing service or a universal DB interception layer.
