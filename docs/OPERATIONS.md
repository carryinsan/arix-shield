# ArixShield production operations

This release preserves the existing Vercel API routes and project-key formats. Existing application route handlers can remain in place; install the SDK wrapper/middleware for request inspection, optional capability sealing, outbound response checks, and final status reporting.

## 1. Required production services and secrets

- Node.js 22 runtime.
- Upstash Redis REST URL and token. The local in-memory fallback is for development only; it is not shared between Vercel instances and cannot provide distributed enforcement.
- A strong `ARIX_MASTER_SECRET` containing at least 32 random bytes.
- `CRON_SECRET` configured in Vercel and used by the cron endpoints.
- A Vercel project deployment of this repository.

Generate secrets locally and do not commit them:

```sh
openssl rand -base64 48
```

Copy `.env.example` into Vercel Project Settings → Environment Variables. Never commit `.env`, private JWK values, server keys, or provider credentials. No new third-party API key is required by the security additions in this release.

## 2. Browser clearance encryption and bot signals

Generate a per-deployment RSA-2048 key pair:

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
  getIdentity: (req, { ip }) => `${req.user?.id || 'anonymous'}:${req.user?.tenantId || 'default'}:${ip}`,
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
  getIdentity: async (request, { ip }) => `${(await getAuthenticatedUser(request)).id}:${ip}`,
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

Capability sealing is an optional stronger guard. Enable `capabilitySealing: true` on both the response-producing and request-protecting SDK integration. The SDK seals recognized ID properties in outgoing JSON using the existing `ARIX_MASTER_SECRET` and the stable authenticated owner identity (a 128-bit truncated HMAC tag), then verifies and strips sealed IDs on the next request. Every numeric/UUID resource-like path segment must be sealed, including IDs in nested paths. Supply `getOwnershipIdentity` explicitly in both SDKs; the Node SDK callback must be synchronous, while the Next.js callback may be async. Do not derive ownership from an unverified client header. Validate all route shapes and update clients/links to use sealed IDs before enabling this for production routes. If your application uses opaque string IDs (for example, cuid/nanoid), configure `capabilityIdPattern` with a developer-owned `RegExp` that matches only resource-ID segments on the protected routes (for example, your app's exact CUID format). Avoid broad patterns that can match static route names. Query-string IDs are not covered by path sealing. Custom ID field names can be configured only by extending the code or mapping to recognized ID fields; all application authorization checks must remain in place.

The optional Knuth reserved-ID trap is disabled by default. Set `ARIX_RESERVED_TRAP_ID_SPACE=true` only when your database permanently reserves every integer ID satisfying `(id * 2654435761) % 97 === 0` and can prove that no real record can receive one. This identifies approximately one integer in 97; it does not guarantee a hit within a few dozen probes. Enabling it without reserving the ID space can ban legitimate users who access a real record.

## 5. Abuse snapshots, quotas, and Redis outage behavior

- Project policy and currently active actor/IP ban hashes are fetched together and cached by SDKs for up to 30 seconds. If the index exceeds the bounded snapshot size, the SDK falls back to a direct abuse check instead of using a partial snapshot.
- The control plane filters expired bans out of snapshots and prunes stale ban-index members. New bans may take up to 30 seconds to reach SDK instances using a valid cached snapshot.
- Distributed quota checks can lease up to 15 tokens for a scope. Remaining tokens are consumed locally and expire after at most 15 seconds; the lease reserves quota centrally, so unused tokens may reduce utilization but are not an allowance increase.
- DPoP uses an in-memory ring as an early replay filter and still checks Redis for cross-instance replay protection.
- Event/audit/analytics writes use a durable Upstash Redis pipeline. They are not queued only in process memory and are not promised to survive without Redis.

When Redis is unavailable, the default SDK behavior is fail-closed with `503` rather than silently bypassing a distributed limit. `failOpen: true` is a compatibility override that uses a process-local bucket; it is not global, can be bypassed across new instances, and should not be used where strict quota/security enforcement is required. A signed client-carried counter cannot provide globally consistent rate limits while the shared anti-replay store is unavailable, so the proposed stateless ratchet is not advertised as implemented.

## 6. Optional pre-body threat-feed block

`ARIX_PREBODY_THREAT_FEED_BLOCK=true` enables a local in-memory threat-feed IP rejection before the `/api/shield` control-plane reads a request body. It is off by default. Enable only after verifying that feeds are loaded, up to date, and appropriate for your false-positive tolerance. This check uses the request IP value supplied by the trusted deployment ingress; do not expose the function directly behind an untrusted proxy that lets clients supply `x-real-ip`.

The pre-body path also validates the existing ArixShield API-key header format, content-length syntax/limit, and Origin syntax. It does not treat header shape as authentication; the key is still resolved and authenticated by the control plane. Its worker-local API-key/project cache may delay key revocation by up to 3 seconds on that instance.

## 7. Threat feed worker

`/api/cron/threat-feeds` refreshes bounded public feeds from Spamhaus DROP, FireHOL Level 1, and the Tor bulk exit-node API. It optionally adds AbuseIPDB when `ARIX_ABUSEIPDB_API_KEY` is configured. Feed downloads have byte caps and timeouts; invalid/empty responses are not installed. Successful data is stored in Redis with a 48-hour expiry and evaluated with an in-process IPv4/IPv6 prefix trie.

The default `threatFeedEnabled` project policy is on, but no IP is blocked until a feed has been loaded and the relevant enforcement action is enabled. Review feed hits before enabling ENFORCE mode in high false-positive environments. Googlebot and Bingbot are checked through reverse DNS plus forward confirmation. Provider source networks are not guessed; configure verified provider CIDRs in `ARIX_TRUSTED_PROVIDER_CIDRS_JSON` using official current ranges and maintain them yourself.

## 8. OpenAPI and Zod schema integration

Pass a parsed OpenAPI v3 document (JavaScript object) or a Zod-like schema with `.safeParse()` to the SDK `schema` option. `compileOpenApiRequestSchema(document, method, path)` returns a validator for an operation's JSON request body. This package does not parse YAML files: parse YAML in your build step and pass the resulting object. Local `$ref` references are supported; remote references and recursive references are rejected. Unsupported OpenAPI composition keywords are not silently evaluated.

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
