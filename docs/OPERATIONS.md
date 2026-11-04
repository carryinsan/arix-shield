# Account signup verification

Production signup requires an email delivery provider. Configure `ARIX_RESEND_API_KEY` and `ARIX_EMAIL_FROM` (a sender/domain verified with Resend) before allowing new registrations. A registration temporarily reserves the normalized email for ten minutes, sends a six-digit single-use code, and creates the account and project only after the code is verified. The email index is atomically changed from the pending reservation to the permanent owner ID; failure cleanup deletes only a reservation still owned by that registration. The API key is server-only. If delivery is not configured or Resend is unavailable, signup fails closed and removes its pending reservation; existing accounts and sign-in continue to work. No verification code is returned in the API response or written to logs. `ARIX_REQUIRE_EMAIL_VERIFICATION=true` enables the same behavior in development/staging.

Browser visitor telemetry is rate-limited independently by DPoP thumbprint, trusted ingress network prefix (IPv4 `/24`, IPv6 `/64`), and project total. Defaults are 3,600 requests/minute/network and 60,000 requests/minute/project. The project cap is bounded at 100,000/minute. Adjust `ARIX_BROWSER_NETWORK_RATE_LIMIT_PER_MINUTE` and `ARIX_BROWSER_PROJECT_RATE_LIMIT_PER_MINUTE` to match expected peak traffic; account for carrier-grade NAT and corporate egress concentration. `clearance-key` bootstrap requests consume the same buckets as telemetry requests. Signup also has a shared service-wide cap of 10,000 requests/hour (`ARIX_SIGNUP_GLOBAL_LIMIT_PER_HOUR`, bounded at 100,000), in addition to per-email and trusted-network limits. These limits constrain telemetry and Redis cost; they do not stop volumetric traffic before it reaches Vercel and do not make client-provided automation signals trustworthy.
# ArixShield production operations

This release preserves the existing Vercel API routes and project-key formats. Existing application route handlers can remain in place; install the SDK wrapper/middleware for request inspection, optional capability sealing, outbound response checks, and final status reporting.

## 1. Required production services and secrets

- Node.js 22 runtime.
- Upstash Redis REST URL and token. The local in-memory fallback is for development only; it is not shared between Vercel instances and cannot provide distributed enforcement.
- A strong `ARIX_MASTER_SECRET` containing at least 32 random bytes.
- `CRON_SECRET` configured in Vercel and used by the cron endpoints.
- A Vercel project deployment of this repository.
- For new production account registrations, `ARIX_RESEND_API_KEY` and `ARIX_EMAIL_FROM` set to a verified Resend sender. Signup fails closed without these settings; existing account sign-in is unaffected.

Generate secrets locally and do not commit them:

```sh
openssl rand -base64 48
```

Copy `.env.example` into Vercel Project Settings → Environment Variables. Never commit `.env`, private JWK values, server keys, or provider credentials. Resend is used only to deliver signup verification mail; it is not required for sign-in or other runtime operations.

## 1A. Password security and step-up verification

New password records use Node.js `crypto.scrypt` (N=32768, r=8, p=3; 32-byte output; bounded 64 MiB maxmem). Historical PBKDF2-HMAC-SHA-256 records remain verifiable and are upgraded to scrypt after a successful full login. Password policy always checks the bundled curated common/contextual-password denylist. The optional Have I Been Pwned k-anonymity range lookup sends only a five-hex-character SHA-1 prefix (never the password), has a 400 ms timeout, and is disabled with `ARIX_HIBP_LOOKUP=false`. If it is unavailable or disabled, the curated offline checks remain active and the password must also meet a 52-bit Shannon-distribution heuristic. That heuristic is not a dictionary-attack model. The bundled list is not a 250,000-entry breach corpus and cannot identify every previously leaked password.

Users can change passwords from the dashboard using the current password; TOTP is also required when enabled. Password changes revoke other sessions and issue a fresh session to the current browser. Every actual security-policy change (including enforcement mode, rate limits, protection toggles, automatic containment, and incident webhook destination) and every origin allowlist change requires fresh password re-authentication plus the enrolled second factor: TOTP when enabled, or a one-time origin-bound WebAuthn assertion for passkey-only accounts. Accounts without an enrolled second factor can re-authenticate with their password; this avoids demanding an impossible factor while still proving current password knowledge. Policy transitions are appended to the tamper-evident audit chain; raw webhook URLs are not included in the audit metadata.

## 2. Browser clearance encryption and bot signals

Generate a per-deployment RSA-3072 key pair (minimum 128-bit classical security strength):

```sh
npm run generate:clearance-keys
```

Set the printed `ARIX_CLEARANCE_KID` and `ARIX_CLEARANCE_PRIVATE_JWK` values as server-only environment variables. The public key is returned by the authenticated `/api/shield` `clearance-key` action. Rotate the pair by generating a new one and deploying it; existing clearance material must be re-issued.

The browser sends encrypted telemetry containing coarse browser flags, a seeded canvas/WebGL pixel digest, optional WebGL renderer/hardware hints, prototype-integrity status, and a bounded summary derived from recent pointer/touch movement. Raw pointer coordinates are kept only in the browser's short rolling sample and are not uploaded. The server binds the supplied signal object into its short-lived HMAC-signed SHA-256 PoW challenge.

These are risk signals, not proof of a physical GPU or a human operator. A custom client can fabricate telemetry; Vercel JA3/JA4 headers are useful only when supplied by a trusted ingress and do not create a universal browser classifier. Do not use these signals instead of authentication, authorization, or step-up verification for sensitive operations.

## 3. Request body limits and WAF configuration

The SDK defaults to a 32 KiB JSON body limit. Routes that legitimately require larger bodies can raise `maxBodyBytes` up to 262144 (256 KiB). The Next.js adapter reads the stream in bounded chunks and cancels on overflow before parsing. The Vercel `/api/shield` control plane has a separate 36,000-byte body cap.

Example Node/Express integration:

```js
import { createArixShield } from 'arixshield/node';

// Mount this after your application's authentication middleware has populated req.user/req.auth.
app.use(createArixShield({
  endpoint: process.env.ARIXSHIELD_ENDPOINT,
  serverKey: process.env.ARIXSHIELD_SERVER_KEY,
  mode: 'ENFORCE',
  maxBodyBytes: 32768,
  maxLeafBytes: 4096,
  schema: checkoutSchema,
  openapiDocument,
  shadowApiCatalog: true,
  getIdentity: (req) => `${req.user?.id || 'anonymous'}:${req.user?.tenantId || 'default'}`,
  requestDlp: true,
  responseDlp: true,
  responseOwnershipGuard: true,
  getOwnershipIdentity: (req) => req.user?.id ?? req.auth?.userId,
  abuseProtection: true,
  forensicReplay: true,
  reportAllRequests: true
}));
```

Example Next.js App Router integration (replace `getAuthenticatedUser` with your existing verified server-side session/authentication function; never trust an unverified user-ID header):

```js
import { withArixShield } from 'arixshield/next';

async function handler(request) {
  return Response.json({ ok: true });
}

export const GET = withArixShield(handler, {
  endpoint: process.env.ARIXSHIELD_ENDPOINT,
  serverKey: process.env.ARIXSHIELD_SERVER_KEY,
  mode: 'ENFORCE',
  maxBodyBytes: 32768,
  maxLeafBytes: 4096,
  abuseProtection: true,
  openapiDocument,
  shadowApiCatalog: true,
  getIdentity: async (request) => (await getAuthenticatedUser(request)).id,
  getOwnershipIdentity: async (request) => (await getAuthenticatedUser(request)).id,
  responseOwnershipGuard: true,
  requestDlp: true,
  reportAllRequests: true,
  waitUntil: globalThis.waitUntil
});
```

For a route that genuinely accepts a larger JSON request, set `maxBodyBytes` on that route to the smallest appropriate value, never above 262144. Avoid broad free-text allowlists. `allowedLongFields` is for known fields whose purpose and downstream handling are understood. Use an explicit schema/OpenAPI operation to lock application-specific properties and types; automatic schema inference is intentionally not enabled.

If using Express body parsers, configure their own `limit` consistently with the ArixShield route limit. Middleware cannot undo memory already allocated by an upstream parser.

## 4. BOLA/IDOR safeguards

ArixShield now tracks resource IDs reported in final `200`, `403`, and `404` outcomes. Successful sequential IDs and high distinct-ID velocity can trigger enumeration backoff. This requires server-side SDK outcome reporting (`reportAllRequests`, abuse protection, or another option that enables outcome reporting).

The outbound ownership guard is opt-in (`responseOwnershipGuard: true`) and checks conventional `userId`, `ownerId`, `accountId`, `customerId`, and related fields. Provide a stable authenticated identity through `getOwnershipIdentity` (synchronous in Node; async or sync in Next.js) that returns the same owner value used in response records. The guard cannot detect ownership leaks in payloads with no comparable owner field, and it does not replace a database query constraint such as `WHERE id = ? AND owner_id = ?`.

Capability sealing is an optional stronger guard. Enable `capabilitySealing: true` on both the response-producing and request-protecting SDK integration. Version-2 HMAC capabilities bind recognized IDs to tenant, user and read/write permission mode using the existing `ARIX_MASTER_SECRET`. The request adapter verifies and rewrites recognized IDs in path segments, query parameters and JSON body fields before the handler runs. Supply a stable authenticated user and tenant context; do not derive either from an unverified client header. Validate all route shapes and update clients/links to use sealed IDs before enabling this for production routes. If your application uses opaque string IDs, configure `capabilityIdPattern` narrowly. Custom ID fields and IDs outside the configured patterns still require application-specific mapping and normal ownership checks. Capability sealing is not a replacement for scoped database queries.

The optional Knuth reserved-ID trap is disabled by default. Set `ARIX_RESERVED_TRAP_ID_SPACE=true` only when your database permanently reserves every integer ID satisfying `(id * 2654435761) % 97 === 0` and can prove that no real record can receive one. This identifies approximately one integer in 97; it does not guarantee a hit within a few dozen probes. Enabling it without reserving the ID space can ban legitimate users who access a real record.


## 4A. Route authorization, tenant scoping and BOPLA

The SDK evaluates configured route authorization before calling the protected handler. Supply verified context through `getAuthorizationContext` (`userId`, `tenantId`, roles and permissions). Use `authorization.routes` for method/path rules, roles, permissions, `tenantIsolated`, and an application-specific `preCheck`. Enable `mutationTripwire: true` to deny unconfigured mutating routes and require tenant isolation plus a pre-check on configured mutations. Do not use a generic pre-check that always returns true.

The optional `allowedWriteFields` role map strips fields that a caller cannot write. `restrictedReadFields` strips fields that the caller cannot read from JSON responses. The request context exposes `scopeQuery` to compose tenant and owner predicates for Prisma-style and Mongo-style structured queries. The Node SDK also exports `runWithArixContext`, `getArixContext`, and `protectPrismaClient`: the Prisma wrapper scopes supported model operations to the verified AsyncLocalStorage tenant/user context, blocks raw SQL and unsupported/nested operations, and fails closed when context is absent. Replace the application client reference with the returned protected client at startup; an unwrapped client reference, other ORM/driver, database console, background job without explicit context, or raw SQL outside the wrapper remains outside this enforcement boundary. Database-native RLS remains the stronger independent control.

See [SECURITY-UPGRADES.md](SECURITY-UPGRADES.md) for complete Node and Next.js configuration examples, raw-body DPoP integration, workflow configuration, safe outbound fetch and account security behavior.

## 5. Abuse snapshots, quotas, and Redis outage behavior

- Project policy and currently active actor-ban hashes are fetched together and cached by SDKs for up to 30 seconds. If the index exceeds the bounded snapshot size, the SDK falls back to a direct abuse check instead of using a partial snapshot.
- The control plane filters expired bans out of snapshots and prunes stale ban-index members. New bans may take up to 30 seconds to reach SDK instances using a valid cached snapshot.
- Distributed quota checks can lease up to 15 tokens for a scope. Remaining tokens are consumed locally and expire after at most 15 seconds; the lease reserves quota centrally, so unused tokens may reduce utilization but are not an allowance increase.
- When the Node or Next.js SDK is configured with `globalRateLimit: false`, or without a control-plane endpoint, its normal local fallback uses a bounded, process-local multi-dimensional token bucket. Anonymous requests share an IPv4 `/24` or IPv6 `/64` network bucket across methods and routes, plus a per-network/method/path bucket; a verified anonymous DPoP proof adds a device bucket. The random request ID remains for telemetry/abuse correlation and is never a quota identity. The aggregate network default is 10 times the base route limit; tune with `anonymousNetworkRateLimitPerMinute` (bounded to 100,000/minute). The store holds at most 10,000 live dimensions, prunes expired entries, does not evict live counters, and admits multi-dimensional charges atomically. A denied request does not allocate attacker-chosen route/device counters.
- The fallback obtains the client address from the trusted Vercel `x-real-ip` ingress value or the Node socket peer; self-hosted deployments behind a proxy must provide `getClientIp` that reads only a verified proxy/ingress value after untrusted forwarding headers have been stripped. Missing/invalid addresses share an `unknown` bucket. A `/24` or `/64` can contain multiple people behind NAT, so the local network quota is intentionally an abuse-friction control and may need tuning for shared networks.
- These SDK local counters are per process/worker and reset on process restart; they are not globally coordinated, cannot prevent a client from distributing requests across many serverless instances, and are not equivalent to the Redis/control-plane path. Use the distributed quota path for production-wide quota enforcement.
- DPoP is bound to the exact request URL, method and raw request-body bytes. A bounded in-memory ring is an early replay filter; Redis `SET NX` is required for cross-instance replay protection. The Node/Express adapter requires the raw-body capture hook shown in `docs/SECURITY-UPGRADES.md`.
- Event/audit/analytics writes use a durable Upstash Redis pipeline. They are not queued only in process memory and are not promised to survive without Redis.

When Redis is unavailable, the default SDK behavior is fail-closed with `503` rather than silently bypassing a distributed limit. `failOpen: true` is a compatibility override that uses a process-local bucket; it is not global, can be bypassed across new instances, and should not be used where strict quota/security enforcement is required. A signed client-carried counter cannot provide globally consistent rate limits while the shared anti-replay store is unavailable, so the proposed stateless ratchet is not advertised as implemented.

## 6. Pre-body request validation and key epochs

The `/api/shield` control-plane validates the existing ArixShield API-key header format, content-length syntax/limit, and Origin syntax before reading the request body. Header shape is not authentication; the key is resolved and authenticated by the control plane. IP threat-feed matches are not used for pre-body rejection. Server key mappings are checked against the committed project key hash on each control-plane action; key-epoch headers allow SDK instances to invalidate local policy, snapshot and quota leases when they observe a new epoch. Worker-side cached policy can remain up to 30 seconds between refreshes, so this is not instantaneous fleet-wide revocation.

## 7. Threat feed worker

`/api/cron/threat-feeds` refreshes bounded public feeds from Spamhaus DROP, FireHOL Level 1, and the Tor bulk exit-node API. It optionally adds AbuseIPDB when `ARIX_ABUSEIPDB_API_KEY` is configured. Feed downloads have byte caps and timeouts; invalid/empty responses are not installed. Successful data retains its original 48-hour freshness expiry; Redis keeps the snapshot through an additional seven-day grace period so the runtime can mark feeds stale and decay their confidence. The feed is evaluated with an in-process IPv4/IPv6 prefix trie.

The default `threatFeedEnabled` project policy is on. Feed matches, ASN context, and subnet correlation contribute to risk telemetry, but a shared IP/subnet/ASN match alone does not hard-block a visitor. Enforcement decisions in the SDK require actor-specific correlation (or independent WAF, authentication, authorization, and quota findings). Review feed hits before enabling ENFORCE mode in high false-positive environments. Googlebot and Bingbot are checked through reverse DNS plus forward confirmation. Provider source networks are not guessed; configure verified provider CIDRs in `ARIX_TRUSTED_PROVIDER_CIDRS_JSON` using official current ranges and maintain them yourself.

## 7A. Confidence scoring, incident alerts and real-time audit chain

Reputation telemetry combines feed confidence, datacenter ASN context, verified crawler/provider allow signals, and rolling actor/subnet behavior. Shared IP, subnet, ASN, and threat-feed matches are context only: the current `check-reputation` enforcement action is derived from actor-specific correlation, so one listed carrier/office/campus address cannot block unrelated visitors. Fresh Spamhaus DROP matches remain visible as high-confidence network telemetry; FireHOL/Tor and datacenter ASN observations are lower-confidence context. Feeds older than 24 hours are confidence-decayed and shown in the dashboard. Configure provider CIDRs from verified provider sources; do not copy example/test ranges into production.

Security events are appended to a Redis-backed HMAC-SHA256 chain using the existing `ARIX_MASTER_SECRET`. The Redis Lua compare-and-set script is the distributed serialization point. The local fallback is for tests/development, not cross-instance production security. The dashboard audit witness uses browser IndexedDB and trust-on-first-use; keep separate evidence exports and protect administrator endpoints. It is not independent WORM storage.

An optional project `alertWebhookUrl` can receive critical incident events over HTTPS. Requests are signed with an HMAC derived from the existing master secret; do not put a shared API key in the webhook URL. Only enable automatic containment after testing the project policy. The current supported automatic transition is DRY_RUN to ENFORCE; external credential rotation is not automatic.

## 7B. Production integrity manifest

The build checker hashes repository `.js`, `.mjs`, and `.html` files into the canonical `docs/INTEGRITY-MANIFEST.json` and writes an identical runtime copy to `api/_integrity-manifest.json`. The static check fails if those two copies differ. The source archive does not contain a production signature or master secret. The committed Vercel build command runs `npm run build`, which regenerates and verifies the manifest using the configured `ARIX_MASTER_SECRET`; production builds fail before deployment if the secret is missing or shorter than 32 bytes. The production build preflight also requires an independent `CRON_SECRET` (at least 32 bytes), a credential-free HTTPS Upstash REST root URL plus its existing server-side token, and a valid RSA private JWK of at least 3072 bits identified by `ARIX_CLEARANCE_KID`. It signs the manifest, re-runs static gates and executes all deterministic tests. It does not connect to Upstash or validate live deployment resources. For a local release build, provide the existing production values through the environment and run:

```sh
# Export the existing production values in trusted CI, then run:
NODE_ENV=production npm run build
```

The production runtime checks manifest coverage and hashes for every `api/**/*.js` and `api/**/*.mjs` route/shared module, rejects API symlinks and missing/extra API source entries, verifies the manifest signature, required master-secret length, RSA-3072 clearance private JWK strength, and HTTPS headers. The canonical manifest lives at `docs/INTEGRITY-MANIFEST.json`; `npm run integrity:update` maintains an identical API-bundled mirror at `api/_integrity-manifest.json`. Vercel API functions include `api/**/*`, so the runtime manifest and all API source files travel together. Regenerate older 2048-bit clearance keys with `npm run generate:clearance-keys` and update both public/private key environment values before deploying this release. Do not commit the master secret or generated private JWK. The static scanner is a dependency-free lexical gate, not a full AST SAST engine; supplement it with independent SAST/SCA/DAST and penetration testing.

## 8. OpenAPI and Zod schema integration

Pass a parsed OpenAPI v3 document (JavaScript object) through `openapiDocument` and set `strictOpenApi: true` to validate operation path/query/header parameters and JSON request bodies. `compileOpenApiRequestSchema(document, method, path)` remains available for body validation. This package does not parse YAML files: parse YAML in your build step and pass the resulting object. Local `$ref` references and bounded `oneOf`, `anyOf` and `allOf` composition are supported; remote and recursive references are rejected.

## 9. ClickHouse / Tinybird analytics

The SDK sends sanitized request-outcome events to the control plane. It does not store request bodies, authorization headers, cookies, or raw payloads in analytics. Configure one external sink:

### ClickHouse

Set `ARIX_CLICKHOUSE_URL`, `ARIX_CLICKHOUSE_DATABASE`, `ARIX_CLICKHOUSE_USER`, `ARIX_CLICKHOUSE_PASSWORD`, and `ARIX_CLICKHOUSE_TABLE`. Create the table using `docs/clickhouse-schema.sql`. The insertion client uses JSONEachRow. Ensure the table column names match the DDL.

### Tinybird

Set `ARIX_TINYBIRD_INGEST_URL` to your Events API ingest endpoint and `ARIX_TINYBIRD_TOKEN` to a write token. Set `ARIX_TINYBIRD_QUERY_URL` to a query endpoint that returns a JSON object with `requests`, `blocked`, `p50`, `p95`, `p99`, `client4xx`, and `server5xx` fields. Query endpoint is a user-created Tinybird pipe; this project does not create hosted resources on your behalf.

`/api/cron/analytics-flush` drains a bounded queue. If the sink rejects a batch, events are requeued (up to configured retention). The dashboard can still show live Redis counters if the analytics sink is not configured, but long-term query panels remain unavailable. No synthetic demo metrics are generated.

## 10. Audit root anchoring

The audit subsystem hashes security events and builds a SHA-256 Merkle root. To anchor roots in GitHub, set `ARIX_AUDIT_GITHUB_TOKEN`, `ARIX_AUDIT_GITHUB_OWNER`, `ARIX_AUDIT_GITHUB_REPO`, and optionally `ARIX_AUDIT_GITHUB_PATH` / `ARIX_AUDIT_GITHUB_BRANCH`. The token requires repository Contents write access. `/api/cron/audit-anchor` commits JSONL root records. Without those settings, pending entries remain queued; this is not immutable public-ledger storage or SOC 2 certification.

A Git commit is tamper-evident history when repository protections and token security are correctly configured, but it is not equivalent to an external WORM ledger. Use a separately administered immutable store for stronger evidence custody.

## 11. GitHub secret scanning webhook

Configure a GitHub App or repository webhook to POST to `/api/github-webhook` with `ARIX_GITHUB_WEBHOOK_SECRET` as the matching webhook secret. Subscribe to `secret_scanning_alert` (and optionally `secret_scanning_scan`). The endpoint verifies `X-Hub-Signature-256` over the raw request body, caps payload size, and never logs raw secret values.

GitHub's standard alert payload may contain only metadata, not the detected secret. If a raw value is not included, ArixShield cannot safely derive which local key should be revoked; the webhook records an action-required event and the owner must rotate/revoke the credential at its provider. GitHub Secret Scanning Partner access is a separate enrollment process.

## 12. Cron scheduling and Vercel plans

The committed `vercel.json` uses daily cron schedules compatible with Vercel Hobby's daily cadence. Pro/Enterprise users can increase analytics and audit flush cadence after confirming plan limits and external database capacity. Cron endpoints require `Authorization: Bearer $CRON_SECRET`.

## 13. Verification

```sh
npm run check
npm test
```

Passing local checks is not a deployment test, external-provider integration test, third-party penetration test, or proof of zero vulnerabilities. Run the checks after every change and validate on a staging deployment with real Upstash credentials and representative application routes before production enforcement.


### Optional Node AsyncLocalStorage + Prisma scope adapter

New Node SDK exports `runWithArixContext`, `getArixContext`, and `protectPrismaClient`. The middleware establishes an AsyncLocalStorage context only from `getAuthorizationContext` / `getAuthContext` values returned by application authentication middleware (plus a trusted, static tenant configuration) before calling the downstream handler. The `getIdentity` fallback is deliberately not accepted as proof of a database user identity; if no trusted context user is present, Prisma operations fail closed. To use the optional Prisma adapter, wrap the only Prisma client reference at server startup and keep the raw client private:

```js
import { PrismaClient } from '@prisma/client';
import { protectPrismaClient } from 'arixshield/node';

const prisma = protectPrismaClient(new PrismaClient(), {
  tenantField: 'tenantId',
  ownerField: 'ownerId'
});
```

Adjust the field names (or configure `modelPolicies`) to match the actual Prisma schema. The adapter automatically scopes its supported read, update, delete, create, createMany and upsert operations to the current tenant and user. It rejects raw SQL, nested relation writes, Prisma extensions and unknown client/delegate operations. Unsupported operation errors are deliberate: use a separately reviewed repository method only after proving tenant isolation. This adapter does not intercept an unwrapped client, a different ORM/driver, background jobs or code that runs outside the SDK middleware. Do not derive the ALS context from request-body fields; the user and tenant must already have been authenticated and authorized. Add database-native RLS where supported.

Stable identity values returned by `getIdentity` should not contain IP addresses. The SDK strips a matching trailing client-IP suffix for continuity across network handoffs; it does not make a browser-supplied identity authenticated.


## v1.4.3: optional egress guard, PostgreSQL RLS and host hardening

### Node fetch guard

Set `ARIX_PROCESS_EGRESS_FIREWALL=true` before importing the Node SDK to route global `fetch` calls through `arixSafeFetch`. It allows credential-free HTTPS to globally routable addresses on approved ports (443 by default), pins DNS, caps bodies and rejects cross-origin redirects. Test all required external and internal destinations first. It does not intercept `node:http`, `node:https`, raw sockets, other processes or native modules; configure outbound firewall policy separately. The Upstash REST endpoint remains supported when it is public HTTPS and resolves only to public addresses.

### PostgreSQL tenant RLS

Use `provisionPostgresTenantRls(migrationClient, [{ schema: 'public', table: 'orders', tenantColumn: 'tenant_id' }])` from a controlled migration job, with a complete reviewed tenant-table allowlist. It enables and forces RLS, adds a restrictive tenant policy, and verifies the table flags. The migration role must own the listed tables but must not be a superuser or `BYPASSRLS` role. Existing conflicting policies stop the migration. A restrictive policy is combined with the table's existing permissive access policies; where no permissive policy exists, PostgreSQL's default is deny.

Wrap application queries using `withPostgresTenantTransaction(pool, callback)` inside `runWithArixContext()` so the helper sets `arix.tenant_id` and `arix.user_id` transaction-locally from trusted server-side context. The callback must use only its supplied query facade, not a separately imported pool/client. Ensure every tenant-owned table has the restrictive policy and test inserts, reads, updates, deletes, joins, background jobs and admin paths using the actual runtime role. This helper is PostgreSQL-specific and does not intercept unwrapped Prisma/pg/mysql/Mongo clients.

### Edge client mTLS and Linux runtime attestation

For inbound mTLS, configure `EDGE_TLS_CERT_FILE`, `EDGE_TLS_KEY_FILE`, `EDGE_TLS_CLIENT_CA_FILE`, and `EDGE_REQUIRE_CLIENT_CERT=true`. Rotate certificates using an independently managed CA and test every upstream client before enforcement. The `edge/docker-compose.hardened.yml` example enables read-only rootfs, UID/GID 65532, dropped Linux capabilities, `no-new-privileges`, resource limits and required client certificates. The example does not create firewall rules or supply certificates.

`npm run attest:host` reports the current Linux process UID, `NoNewPrivs` and `CapEff`; `npm run attest:host:strict` exits non-zero if any required control is absent. `ARIX_REQUIRE_HARDENED_HOST=true` makes the API runtime integrity check fail closed on missing controls. Do not enable that setting on a serverless provider until a live deployment proves the controls are present. This is not host/kernel attestation and does not verify seccomp, nftables, cloud ingress or database RLS.


### Optional host ingress firewall bootstrap

`scripts/bootstrap-host.mjs` previews a dedicated nftables input-chain table and does not mutate the host by default. Set explicit comma-separated `ARIX_BOOTSTRAP_EDGE_CIDRS` and `ARIX_BOOTSTRAP_SSH_CIDRS`, review the preview, confirm out-of-band console access, then run `npm run provision:host -- --apply-firewall` from a trusted administrative session. It restricts only the configured SSH/edge TCP ports; it is not a complete host firewall or outbound egress policy. The apply path uses an idempotent atomic nftables batch and a boot-time systemd unit. Validate the installed nftables version, systemd behavior, CIDRs and recovery path on the target host before production use.
