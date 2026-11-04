# ArixShield security boundaries and verification status

ArixShield is an application-layer SDK and control-plane service. It is not a TLS-terminating reverse proxy, an L3/L4 volumetric DDoS scrubbing network, a database authorization engine, or an independently certified security product.

No source-code change can honestly guarantee zero vulnerabilities, perfect bot detection, or bug-free operation. ArixShield provides configurable enforcement points; customer applications must supply trusted identity, tenant context, authorization policy, database scoping, and correct deployment/runtime configuration.

## Implemented security controls in this package

### Authorization, tenant isolation and BOPLA

- The Node and Next.js SDK adapters evaluate the configured authorization matrix before invoking the protected application handler. Rules can constrain HTTP methods, roles, permissions, authenticated identity, tenant identity and a developer-supplied asynchronous pre-check.
- `mutationTripwire: true` denies unconfigured `POST`, `PUT`, `PATCH` and `DELETE` routes and requires configured mutation rules to declare `tenantIsolated: true`, `requirePreCheck: true`, and a passing pre-check. The pre-check itself may perform a narrowly scoped read; the protected route handler is not run when it fails.
- Optional `allowedWriteFields` policies strip fields that the caller's role cannot write. Optional `restrictedReadFields` policies remove configured fields before JSON responses are serialized.
- `req.arixContext.scopeQuery(...)` and the equivalent Next.js request context helper build tenant-and-owner predicates for Prisma-style and Mongo-style structured queries. Raw SQL strings are intentionally rejected; SQL adapters must use bound parameters.
- These controls are opt-in/configuration-dependent. ArixShield cannot infer the application's real role hierarchy, tenant model, ownership rules, or arbitrary database access. A route can still be insecure if the developer omits policy, supplies untrusted identity, uses raw database access outside the wrapper, or writes a pre-check that does not verify the specific resource.

### Resource capability sealing and identity binding

- Version-2 HMAC capabilities bind a resource identifier to tenant ID, user ID, read/write mode, and resource ID using the existing `ARIX_MASTER_SECRET`.
- The SDK can verify and rewrite recognized resource identifiers in path segments, query parameters and recognized JSON body fields before the route handler executes. Capability sealing is opt-in through `capabilitySealing: true` and must be enabled consistently where identifiers are returned and accepted.
- Resource ID names and opaque string patterns are bounded and intentionally conservative. Custom application-specific ID fields or identifiers that do not match configured patterns are not automatically protected. Capability tokens are defense in depth, not a substitute for record-level ownership predicates.

### Browser clearance, request-bound DPoP and business-flow breadcrumbs

- `/api/shield` can issue a short-lived HMAC-signed clearance ticket (60 seconds) after the browser telemetry / PoW flow. The ticket binds project, browser key thumbprint, risk/fingerprint context, IP prefix where available, nonce and expiry.
- `public/arix-client.js` wraps same-origin `fetch` calls after clearance is obtained. It attaches the clearance ticket and a fresh ES256 DPoP proof bound to the exact target URL, HTTP method and SHA-256 request-body bytes (`ath`). The browser signing key is non-exportable and stored through IndexedDB-backed WebCrypto.
- The SDK validates clearance and DPoP before protected handlers. DPoP JTIs use the shared Redis replay check; sensitive configured one-shot routes additionally consume the clearance nonce atomically. A shared Redis anti-replay check is required for cross-instance replay resistance.
- The optional workflow configuration issues signed ordered-step breadcrumbs tied to project, tenant and actor identity. The next step checks step order, route, timing and a Redis-backed one-use nonce. This is not proof that a human performed the workflow; a real browser automation system can still execute legitimate steps.
- In Express/Node, the JSON parser must preserve the original bytes in `req.rawBody` using the documented `verify` hook. The SDK rejects body-bearing clearance-protected requests when those exact bytes are unavailable. Re-serializing parsed JSON is not an equivalent DPoP check.
- Browser signals (WebGL/canvas digests, interaction summaries, user-agent values and claimed hardware properties) are spoofable risk inputs, not hardware attestation or proof of a human. They must not replace authentication or authorization.
- Browser telemetry uses independent DPoP-thumbprint, trusted-ingress network-prefix (IPv4 `/24`, IPv6 `/64`), and project-wide rate-limit buckets. This counters simple key rotation and constrains aggregate telemetry volume, but cannot stop a distributed proxy network or volumetric traffic before it reaches the hosting platform. Configure `ARIX_BROWSER_NETWORK_RATE_LIMIT_PER_MINUTE` and `ARIX_BROWSER_PROJECT_RATE_LIMIT_PER_MINUTE` for expected peak load and shared-NAT behavior. The `clearance-key` bootstrap action uses these same buckets. New account creation also has a shared service-wide hourly quota in addition to email and ingress-network buckets. The clearance response explicitly reports `humanVerified: false`; `CLEARED` means the DPoP/telemetry flow completed, not that a human was verified.
- New production signups require a single-use, ten-minute email verification code before account/project credentials are created. Configure `ARIX_RESEND_API_KEY` and a verified sender in `ARIX_EMAIL_FROM`. If delivery is not configured, production signup fails closed while existing accounts can still sign in. Existing accounts pre-dating this control are grandfathered; no retroactive mailbox ownership proof is claimed.

### MFA, sessions and server-key lifecycle

- Login controls include client/IP+UA request limiting, IP subnet limiting, per-account failure counters with an atomic 15-minute expiry window, escalating 1–30 second retry backoff, a short account lock and a signed proof-of-work challenge after the configured failure threshold.
- TOTP uses RFC 6238 six-digit HMAC-SHA1 codes; the secret is AES-256-GCM encrypted under a key derived from the existing `ARIX_MASTER_SECRET`. Accepted time-step counters are consumed with Redis `SET NX` to prevent reuse during the accepted window.
- WebAuthn/passkeys use browser WebCrypto credentials and server-side challenge verification. This implementation supports P-256 / ES256 public-key credentials and `fmt: none` registration attestation; other algorithms or attestation formats are not claimed as supported. Challenges are atomically consumed with Redis `GETDEL`, with origin/RP-ID, expiry, user-presence / user-verification and signature-counter checks.
- Sessions have a 30-minute idle timeout and a 24-hour absolute lifetime, with a user session registry and per-session revocation. Session state and cross-instance revocation require shared Redis.
- Server integration key rotation generates a replacement key, prepares a replacement session before committing the project key pointer, and can keep the prior key in a bounded grace window or revoke it immediately. The control plane checks the project's current key hash on each authenticated control-plane action and returns a key epoch for SDK cache invalidation. The replacement key is shown once; operators must update server environment variables.
- These controls require a stable `ARIX_MASTER_SECRET`, working Redis, correctly configured secure origins, and customer-managed recovery processes. A compromised application server or master secret can undermine these protections.

### Request parser and WAF consistency

- Canonicalization applies Unicode NFKC normalization, bounded repeated decoding and structured JSON inspection.
- The WAF detects duplicate JSON sibling keys from raw JSON, duplicate query keys unless an OpenAPI array parameter allows them, duplicate Node raw headers where available, and simultaneous `Content-Length` plus `Transfer-Encoding`.
- Security path normalization rejects encoded path separators and resolves dot segments before route matching.
- OpenAPI request validation supports path/query/header parameters and JSON bodies, local references, and bounded `oneOf`, `anyOf` and `allOf` composition.
- GraphQL lexical inspection bounds nesting depth and alias count and blocks production introspection. XML checks block DTD/entity declarations. PNG, JPEG and PDF signature checks and active SVG content checks run when the raw request body is available. Multipart bodies are parsed with bounded boundary/header handling and at most 16 file parts; supported image/PDF parts are signature-checked, scriptable MIME types are rejected, and missing raw upload bytes are reported.
- These checks do not replace the framework's own parser or the application's schema. The multipart parser is deliberately bounded by the WAF 256 KiB body cap and 16 file parts; it is not a general-purpose streaming upload pipeline, archive-bomb detector or antivirus engine. Large uploads should use a dedicated streaming upload pipeline with per-part limits and independent scanning.

### DNS-pinned outbound fetch and optional global fetch guard

- `arixSafeFetch` accepts credential-free HTTPS URLs, resolves A/AAAA records, rejects private, loopback, link-local, documentation, multicast and other non-public ranges, pins the selected address for the TLS connection, bounds request/response bodies and total time, and rejects cross-origin redirects.
- The default allowed port is 443. Applications may narrow or extend the allowed-port list explicitly; non-standard ports require service-specific review.
- `ARIX_PROCESS_EGRESS_FIREWALL=true` opts the Node SDK into `installProcessEgressFirewall()`, which routes `globalThis.fetch` and Fetch `Request` calls through `arixSafeFetch`. This is a process-global fetch guard, **not** a universal process/kernel firewall. It does not intercept `node:http`, `node:https`, `node:net`, direct TLS/socket clients, native addons, child processes, or traffic from other processes.
- Use host/container egress rules to enforce the remaining transports. The guard intentionally rejects private/loopback addresses and cross-origin redirects; validate that every application fetch dependency uses public HTTPS and does not rely on internal services before enabling it.

### Quotas, concurrency and Redis resilience

- The distributed quota check evaluates actor/account, IP subnet, tenant and normalized endpoint dimensions in one Redis Lua operation. SDKs can reserve up to 15 tokens locally for a short lease; unused leased tokens can reduce utilization conservatively.
- Expensive routes can use a Redis-backed concurrency lease, default maximum 3 per actor, released on response finish/close. Applications should configure TTLs longer than their expected handler duration and ensure streams close cleanly.
- Responses can report actual cost through `X-Arix-Actual-Cost`; the SDK reconciles additional quota weight after the response and records cost telemetry. This is an application-reported value and must not be trusted if untrusted clients can set the header; strip client-provided copies and set it only in trusted server code.
- The Redis/control-plane circuit breaker trips after three failures or an operation reaching 450 ms, opens for 10 seconds and permits one half-open probe. State is process-local, so individual instances can be in different breaker states.
- During control-plane outage, state-changing and other routes fail closed. Designated low-risk documentation/catalog GET routes may use a 25%-capacity local bucket plus a signed stateless PoW challenge. The local bucket is per process and is not globally consistent; this is a reduced-availability fallback, not equivalent to Redis-backed quotas.

## Production requirements

- Node.js 22 runtime and the current SDK/control-plane code deployed together.
- `ARIX_MASTER_SECRET` with at least 32 bytes of high-entropy random material.
- Upstash Redis REST URL/token for sessions, shared anti-replay, distributed quotas, concurrency locks, key lifecycle and other shared state. The in-memory fallback is development-only and not cross-instance.
- Existing server integration key remains server-only. Do not put it in browser code. Browser code uses the separate project live key already provisioned by ArixShield.
- `ARIX_CLEARANCE_KID` and `ARIX_CLEARANCE_PRIVATE_JWK` are required for encrypted browser clearance; generate/rotate them using the existing helper and retain the private JWK as a server secret.
- Trust client IP / TLS headers only when supplied by the hosting platform or a verified ingress. Do not trust arbitrary `X-Forwarded-For` or `X-Real-IP` values from the public internet.

No additional third-party API key is introduced by these changes. Existing optional analytics and threat-intelligence integrations still require their separately documented credentials.

## ASVS 5.0.0 status

This package has not been independently assessed or certified against OWASP ASVS 5.0.0 Level 3. Local unit tests and static import checks are not an ASVS verification. Level 3 assessment requires a requirement-by-requirement review of the applicable controls plus evidence from the deployed application, infrastructure, identity provider, database, secret management, operational processes and penetration testing. ArixShield implements selected controls relevant to authorization, authentication, session management, input validation, API security and communications, but this document does not claim that every Level 3 requirement is satisfied.

Passing local tests is not proof of zero vulnerabilities. Run dependency and container scans, staging tests with the actual Redis/Vercel configuration, application-specific threat modelling, independent penetration testing and a formal ASVS verification before making a compliance claim.


### PostgreSQL tenant RLS helpers and host attestation

- `provisionPostgresTenantRls(client, tables)` applies `ENABLE` and `FORCE ROW LEVEL SECURITY` plus an `AS RESTRICTIVE` tenant policy only to a caller-supplied allowlist. It verifies tenant columns, refuses superuser/BYPASSRLS migration roles, serializes provisioning with a transaction-scoped advisory lock and verifies the resulting flags. Use it in a controlled migration with a dedicated migration connection; it is not automatically executed at API cold start because the repository has no customer database connection or authoritative table inventory.
- `withPostgresTenantTransaction(pool, callback)` requires trusted ArixShield AsyncLocalStorage tenant/user identity, opens a transaction, confirms the connected role is neither superuser nor BYPASSRLS, and sets transaction-local `arix.tenant_id` / `arix.user_id`. The callback must use the supplied query-only client. Do not close over an unwrapped pool, and ensure all tenant-owned tables have been provisioned and tested. PostgreSQL RLS is defense in depth, not a substitute for parameterized queries or application authorization.
- `ARIX_REQUIRE_HARDENED_HOST=true` enables a Linux process attestation check for non-root UID, `NoNewPrivs: 1`, and zero effective capabilities. This check reports process-visible state only; it does not attest the kernel, Docker daemon, host firewall, seccomp profile, ingress provider, or database role. `edge/docker-compose.hardened.yml` shows no-new-privileges, cap-drop, read-only rootfs, resource bounds and inbound mTLS.
