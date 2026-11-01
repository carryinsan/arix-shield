# ArixShield production operations

This release keeps the existing Vercel API routes and API-key formats. Existing app route handlers do not need to be moved behind a reverse proxy. For advanced per-request outcomes (BOLA/IDOR, brute-force ratios, geo-velocity, route cataloguing and forensic replay), install the updated SDK middleware/wrapper so the final HTTP status is reported back to ArixShield.

## 1. Required production services

- Node.js 22 runtime.
- Upstash Redis REST URL and token. The local in-memory fallback is for development only; it is not shared between Vercel instances and is not a production distributed limiter.
- A strong `ARIX_MASTER_SECRET` of at least 32 random bytes.
- `CRON_SECRET` configured in Vercel and used by the three cron endpoints.
- A Vercel project deployment of this repository.

Example secret generation (run locally; do not commit values):

```sh
openssl rand -base64 48
```

Copy `.env.example` into Vercel Project Settings → Environment Variables. Never commit `.env` or private JWK values.

## 2. Browser clearance encryption

Generate a per-deployment RSA-2048 key pair:

```sh
npm run generate:clearance-keys
```

Set the printed `ARIX_CLEARANCE_KID` and `ARIX_CLEARANCE_PRIVATE_JWK` values as server-only environment variables. The public key is returned by the authenticated `/api/shield` `clearance-key` action; it is not necessary to publish a separate environment variable. Rotate the key by generating a new pair and deploying it. Existing clearance material will need to be re-issued.

The browser telemetry payload intentionally contains only coarse boolean / screen signals. It does not collect canvas pixel hashes, WebGL renderer strings, precise pointer coordinates, typed text, WebRTC candidates, LAN addresses, or audio/video data.

## 3. Threat feed worker

`/api/cron/threat-feeds` refreshes bounded public feeds from Spamhaus DROP, FireHOL Level 1, and the Tor bulk exit-node API. It optionally adds AbuseIPDB when `ARIX_ABUSEIPDB_API_KEY` is set. Feed downloads have a fixed byte cap and timeout; invalid/empty feed responses are not installed. Successful data is stored in Redis with a 48-hour expiry and evaluated with an in-process IPv4/IPv6 prefix trie.

The default `threatFeedEnabled` project policy is on, but no IP is blocked until a non-empty feed has been loaded. Review feed hits before enabling ENFORCE mode in high false-positive environments. Googlebot and Bingbot are checked through reverse DNS plus forward confirmation. GitHub, Stripe, and OpenAI source networks are not guessed; configure verified provider CIDRs explicitly in `ARIX_TRUSTED_PROVIDER_CIDRS_JSON` using official current provider ranges and maintain them yourself.

## 4. Distributed quotas and behavior telemetry

The SDK applies local fast-path limits and (when configured) a shared Upstash distributed token bucket. A short-lived local block cache reduces repeat calls after a shared deny. Local in-memory counters are not a substitute for Redis in multi-instance deployments.

To enable abuse reporting, turn on the dashboard policy switches and use the SDK middleware/wrapper. BOLA detection counts distinct resource IDs only after the application reports 403/404 outcomes; it does not infer authorization failure from sequential-looking URLs alone. Credential backoff uses reported 401 outcomes. Use `getIdentity(req)` / `getIdentity(request)` to create a composite quota dimension from authenticated user, tenant, API key, JWT subject, and/or session fingerprint. Use `getRateLimitWeight(req, context)` to debit weighted quotas (for example, estimated LLM tokens); weights are clamped to the configured project capacity. Geo-velocity requires reliable edge geo headers or explicitly supplied geo data; the SDK does not derive precise location from browser fingerprints.

## 5. OpenAPI and Zod schema integration

Pass a parsed OpenAPI v3 document (JavaScript object) or a Zod-like schema with `.safeParse()` to the SDK `schema` option. `compileOpenApiRequestSchema(document, method, path)` returns a validator for an operation's JSON request body. This package does not parse YAML files: parse YAML in your build step and pass the resulting object. Local `$ref` references are supported; remote references and recursive references are rejected. Unsupported OpenAPI composition keywords are not silently evaluated.

## 6. ClickHouse / Tinybird analytics

The SDK sends sanitized, asynchronous request outcome events to the control plane. It does not store request bodies, authorization headers, cookies, or raw payloads in analytics. Configure one external sink:

### ClickHouse

Set `ARIX_CLICKHOUSE_URL`, `ARIX_CLICKHOUSE_DATABASE`, `ARIX_CLICKHOUSE_USER`, `ARIX_CLICKHOUSE_PASSWORD`, and `ARIX_CLICKHOUSE_TABLE`. Create the table using `docs/clickhouse-schema.sql`. The insertion client uses JSONEachRow. Ensure the table column names match the DDL.

### Tinybird

Set `ARIX_TINYBIRD_INGEST_URL` to your Events API ingest endpoint and `ARIX_TINYBIRD_TOKEN` to a write token. Set `ARIX_TINYBIRD_QUERY_URL` to a query endpoint that returns a JSON object with `requests`, `blocked`, `p50`, `p95`, `p99`, `client4xx`, and `server5xx` fields. Query endpoint is a user-created Tinybird pipe; this project does not create hosted resources on your behalf.

`/api/cron/analytics-flush` drains a bounded queue. If the sink rejects a batch, events are requeued (up to configured retention). The dashboard can still show live Redis counters if the analytics sink is not configured, but long-term query panels remain unavailable. This is real source data, not generated demo metrics.

## 7. Audit root anchoring

The audit subsystem hashes security events and builds a SHA-256 Merkle root. To anchor roots in GitHub, set `ARIX_AUDIT_GITHUB_TOKEN`, `ARIX_AUDIT_GITHUB_OWNER`, `ARIX_AUDIT_GITHUB_REPO`, and optionally `ARIX_AUDIT_GITHUB_PATH` / `ARIX_AUDIT_GITHUB_BRANCH`. The token requires repository Contents write access. `/api/cron/audit-anchor` commits JSONL root records. Without those settings, pending entries remain queued; there is no claim of immutable public-ledger storage or SOC 2 certification.

A Git commit is tamper-evident history when repository protections and token security are correctly configured, but it is not equivalent to an external WORM ledger. Use a separately administered immutable store for stronger evidence custody.

## 8. GitHub secret scanning webhook

Configure a GitHub App or repository webhook to POST to `/api/github-webhook` with `ARIX_GITHUB_WEBHOOK_SECRET` as the matching webhook secret. Subscribe to `secret_scanning_alert` (and optionally `secret_scanning_scan`). The endpoint verifies `X-Hub-Signature-256` over the raw request body, caps payload size, and never logs raw secret values.

GitHub's standard alert payload may contain only metadata, not the detected secret. If a raw value is not included, ArixShield cannot safely derive which local key should be revoked; the webhook records an action-required event and the owner must rotate/revoke the credential at its provider. GitHub Secret Scanning Partner access is a separate enrollment process and is not granted by installing this receiver.

## 9. Cron scheduling and Vercel plans

The committed `vercel.json` uses daily cron schedules compatible with Vercel Hobby's daily cadence. Vercel Pro/Enterprise users can increase analytics and audit flush cadence to once per minute after confirming plan limits and external database capacity. The cron endpoints require `Authorization: Bearer $CRON_SECRET`.

## 10. SDK integration

### Node / Express

```js
import { createArixShield } from 'arixshield/node';
app.use(createArixShield({ endpoint: process.env.ARIXSHIELD_ENDPOINT, serverKey: process.env.ARIXSHIELD_SERVER_KEY, mode: 'ENFORCE', schema: checkoutSchema, openapiDocument, shadowApiCatalog: true, getIdentity: (req, { ip }) => `${req.user?.id || 'anonymous'}:${req.user?.tenantId || 'default'}:${ip}`, getRateLimitWeight: (req) => Math.max(1, Math.ceil(Number(req.body?.estimatedTokens || 1) / 1000)), requestDlp: true, responseDlp: true, abuseProtection: true, forensicReplay: true, reportAllRequests: true }));
```

### Next.js App Router

```js
import { withArixShield } from 'arixshield/next';
async function handler(request) { return Response.json({ ok: true }); }
export const GET = withArixShield(handler, { endpoint: process.env.ARIXSHIELD_ENDPOINT, serverKey: process.env.ARIXSHIELD_SERVER_KEY, mode: 'ENFORCE', abuseProtection: true, openapiDocument, shadowApiCatalog: true, getIdentity: (request, { ip }) => `${request.headers.get('x-user-id') || 'anonymous'}:${ip}`, getRateLimitWeight: (request, { body }) => Math.max(1, Math.ceil(Number(body?.estimatedTokens || 1) / 1000)), requestDlp: true, reportAllRequests: true, waitUntil: globalThis.waitUntil });
```

Do not pass server keys to browsers. Existing customers who only use the browser SDK can continue to use their current route setup; advanced response-outcome analysis requires server-side SDK reporting. Add only app-owned unused paths to optional honeypot routes. Canary rows are opt-in synthetic records; filter them from user views. Watermarking modifies safe display-text fields only.

## 11. Verification

```sh
npm run check
npm test
```

Passing these tests is not a third-party penetration test or proof of zero vulnerabilities.
