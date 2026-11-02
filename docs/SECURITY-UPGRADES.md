# Security upgrades — integration guide

This guide documents the enforcement options implemented in the SDK. It is not safe to enable the options with placeholder identities; connect them to the application's verified authentication and tenant model first.

## 1. Express / Node.js integration

Install application authentication before the SDK so identity and roles come from a verified server-side session. Preserve the exact bytes parsed by Express because browser DPoP signs those bytes, not a later JSON serialization:

```js
import express from 'express';
import { createArixShield } from './sdk/node.js';

const app = express();
app.use(authenticateUser); // Your verified server-side authentication middleware.
app.use(express.json({
  limit: '32kb',
  verify: (req, res, buffer) => { req.rawBody = Buffer.from(buffer); }
}));

app.use(createArixShield({
  endpoint: process.env.ARIXSHIELD_ENDPOINT,
  serverKey: process.env.ARIX_SECRET_KEY, // Server-only integration key.
  mode: 'ENFORCE',
  globalRateLimit: true,
  rateLimitPerMinute: 120,
  getIdentity: (req) => req.user?.id,
  getAuthorizationContext: (req) => ({
    userId: req.user?.id,
    tenantId: req.user?.tenantId,
    roles: req.user?.roles || [],
    permissions: req.user?.permissions || []
  }),
  authorization: {
    routes: [
      {
        method: 'PATCH',
        path: '/api/orders/:id',
        roles: ['customer', 'admin'],
        tenantIsolated: true,
        requirePreCheck: true,
        preCheck: async ({ request, context }) => {
          const order = await prisma.order.findFirst({
            where: { id: request.params.id, tenantId: context.tenantId, ownerId: context.userId },
            select: { id: true }
          });
          return Boolean(order);
        }
      }
    ],
    allowedWriteFields: {
      customer: ['shippingAddress', 'customerNote'],
      admin: ['shippingAddress', 'customerNote', 'status']
    },
    restrictedReadFields: {
      customer: ['passwordHash', 'internalNotes', 'fraudScore']
    }
  },
  mutationTripwire: true,
  capabilitySealing: true,
  botProtection: { paths: ['/api/login', '/api/signup', '/api/checkout'], singleUse: true },
  workflow: {
    enabled: true,
    workflows: [{
      id: 'checkout-v1',
      steps: [
        { method: 'GET', path: '/api/products' },
        { method: 'POST', path: '/api/cart' },
        { method: 'POST', path: '/api/checkout' }
      ],
      minStepMs: 1500,
      maxAgeMs: 600000
    }]
  },
  maxConcurrency: 3
}));
```

The sample `preCheck` is deliberately application-specific. Route-level middleware is recommended where `request.params` must be available before the handler. If your router does not populate route parameters before the SDK middleware, parse and validate the route identifier from the normalized path or mount the middleware after route matching but before the handler.

`mutationTripwire: true` denies unlisted mutating routes. Every allowed mutation must define a route rule with `tenantIsolated: true`, `requirePreCheck: true`, and a successful rule-level or global `preCheck`. Test all write routes before enabling this in production.

## 2. Query-layer scoping

The helper requires the context supplied by `getAuthorizationContext` and returns structured predicates. For Prisma:

```js
const scopedArgs = req.arixContext.scopeQuery(
  { where: { id: req.params.id }, select: { id: true, status: true } },
  { adapter: 'prisma', tenantField: 'tenantId', ownerField: 'ownerId' }
);
const order = await prisma.order.findFirst(scopedArgs);
```

For MongoDB:

```js
const scopedFilter = req.arixContext.scopeQuery(
  { _id: orderId },
  { adapter: 'mongo', tenantField: 'tenantId', ownerField: 'ownerId' }
);
const order = await db.collection('orders').findOne(scopedFilter);
```

This helper cannot intercept arbitrary SQL, direct ORM calls or raw driver usage. Use parameterized SQL and add equivalent tenant/owner predicates in your repository layer for every query and mutation. Do not assume that importing `scopeQuery` automatically scopes the whole application.

## 3. Next.js App Router

Use `protectRequest` or `withArixShield` before the route handler. Derive the identity and tenant from a verified session/token on the server, not a caller-supplied header. The Next.js adapter captures the original request body bytes from the incoming `Request` stream and uses them for DPoP binding.

```js
import { protectRequest } from './sdk/next.js';

export async function PATCH(request, { params }) {
  const session = await getVerifiedSession(request);
  const decision = await protectRequest(request, {
    endpoint: process.env.ARIXSHIELD_ENDPOINT,
    serverKey: process.env.ARIX_SECRET_KEY,
    mode: 'ENFORCE',
    getIdentity: () => session.user.id,
    getAuthorizationContext: () => ({
      userId: session.user.id,
      tenantId: session.tenant.id,
      roles: session.user.roles,
      permissions: session.user.permissions
    }),
    mutationTripwire: true,
    authorization: {
      routes: [{
        method: 'PATCH', path: '/api/orders/:id', roles: ['customer', 'admin'],
        tenantIsolated: true, requirePreCheck: true,
        preCheck: async ({ context }) => Boolean(await orderRepository.canEdit({
          orderId: (await params).id, userId: context.userId, tenantId: context.tenantId
        }))
      }]
    }
  });
  if (!decision.allowed) return decision.response;
  return Response.json({ ok: true });
}
```

The function signatures vary slightly with the caller's framework version; confirm the exact Next.js route context shape for the installed version. The application must still perform scoped reads/writes in its own data layer.

## 4. Browser clearance and DPoP

Include the existing browser client script on the application origin after configuring its project live key:

```html
<script src="https://YOUR-ARIXSHIELD-ORIGIN/arix-client.js"
        data-arix-key="ARIX_LIVE_PROJECT_IDENTIFIER"
        data-arix-protect="/api/login,/api/signup,/api/checkout"
        defer></script>
```

The client obtains clearance through the control plane, then wraps same-origin `fetch` calls to the default sensitive paths (`/login`, `/signup`, `/checkout`, `/otp`, `/ai`) and any comma-separated paths in `data-arix-protect`, adding `X-Arix-Clearance` and `X-Arix-PoP`. Keep `data-arix-protect` aligned with the SDK's `botProtection.paths` when using custom routes. It also propagates `X-Arix-Flow` on workflow routes. The script cannot protect calls made through other clients, direct server-to-server calls, or requests that bypass `fetch`; enforce credentials and authorization on every route independently.

The Node/Express adapter requires `req.rawBody` for body-bearing requests to routes that require clearance. Do not replace the original bytes with `JSON.stringify(req.body)` for DPoP validation. The browser's clearance ticket is short-lived and one-shot behavior is backed by shared Redis nonce consumption on configured sensitive routes.

## 5. Capability sealing and property-level rules

Enable `capabilitySealing: true` only after both response and request paths are integrated. The SDK seals recognized resource IDs in JSON responses and validates recognized IDs in path, query and JSON body input. Ensure the same authenticated user and tenant identity are supplied to both sides. For opaque IDs, configure a narrowly targeted `capabilityIdPattern`; do not use a pattern that matches ordinary route names.

`allowedWriteFields` and `restrictedReadFields` accept a role-to-field-list map. Field paths may use dot notation. A write allowlist strips all properties not listed for the caller's role when that role policy is configured. An output restricted-field list removes the named fields. Define explicit schemas as well; BOPLA filtering is not a replacement for business validation.

## 6. OpenAPI, parser and upload checks

Pass a parsed OpenAPI document through `openapiDocument` and set `strictOpenApi: true` to validate declared operations, path/query/header parameters and JSON body schema. The validator handles local `$ref` plus bounded `oneOf`, `anyOf` and `allOf`; remote and recursive schema references are not accepted.

The WAF canonicalizes Unicode with NFKC, rejects duplicate raw JSON keys, duplicate query keys unless defined as an array parameter, duplicate raw headers when the Node adapter exposes them, and Content-Length/Transfer-Encoding combinations. It also includes bounded GraphQL/XML/upload checks. The bounded multipart parser inspects up to 16 file parts within the 256 KiB WAF body cap, validates supported PNG/JPEG/PDF signatures, and rejects configured scriptable MIME types. It is not a general-purpose streaming upload service, malware scanner or archive decompression guard; use a dedicated pipeline for large files and inspect every part independently.

## 7. Safe outbound fetch

Use the exported `arixSafeFetch` for any URL derived from a user-controlled webhook, import, preview or callback target:

```js
import { arixSafeFetch } from './sdk/node.js';

const response = await arixSafeFetch(userProvidedUrl, {
  method: 'GET',
  timeoutMs: 8000,
  maxRedirects: 2,
  allowedPorts: [443]
});
```

The helper rejects non-HTTPS URLs and non-public resolved destinations, pins the chosen DNS result to the TLS connection and revalidates redirects. It is not a process-wide network sandbox; route all untrusted outbound requests through it and review every allowed port.

## 8. MFA, sessions and key rotation UI

Login attempts are limited by client/IP+UA, subnet and account. Five failed account attempts in 15 minutes trigger proof-of-work and an atomic escalating retry delay capped at 30 seconds. The dashboard's Account security panel supports TOTP enrollment/confirmation/disable, passkey enrollment/removal, session listing/revocation and server-key rotation. TOTP codes are single-use per accepted time step; removal/disable/rotation requires password re-authentication and TOTP when enabled. WebAuthn support in this implementation is limited to P-256 ES256 and `none` attestation. Browser support requires HTTPS (localhost is allowed for development).

The existing `ARIX_MASTER_SECRET` is used to derive the TOTP encryption key and sign capability/clearance material. No new external API key is required. Shared sessions, one-time challenges, replay protection, quota enforcement and key lifecycle require the existing Upstash Redis configuration. Store the generated replacement `ARIX_SECRET_...` key only in the server environment; the UI displays it once.

## 9. Quota and outage behavior

Global quotas use actor/account, source subnet, tenant and normalized endpoint dimensions in a single distributed check, with a short conservative local token lease. AI-like routes acquire a distributed concurrency lease (default max 3 per actor); server code may set `X-Arix-Actual-Cost` to trigger post-response reconciliation. Strip any client-provided header and only set this header from trusted server-side cost accounting.

The Redis/control-plane circuit breaker opens after three failures or a request reaching 450 ms, for 10 seconds, then allows one half-open probe. During outage, mutations fail closed. Only designated docs/catalog GET routes can use the 25% local quota plus HMAC PoW fallback. This fallback is process-local and not globally coordinated.

## 10. Deployment checklist

1. Set a stable, high-entropy `ARIX_MASTER_SECRET` (at least 32 bytes) and existing Upstash Redis REST URL/token.
2. Keep server integration keys and private clearance JWKs in server-only environment variables.
3. Mount authentication before the Node SDK, preserve raw Express bytes, and configure real role/tenant context.
4. Inventory every mutation and configure an authorization rule plus ownership pre-check before enabling `mutationTripwire`.
5. Apply tenant/owner predicates in every database repository method. Review raw SQL and background jobs separately.
6. Test clearance from a real browser and ensure the client script covers the protected same-origin API calls.
7. Test TOTP/passkeys, session revocation, key rotation, Redis outage and expired/replayed challenges in staging.
8. Run dependency, static, dynamic and penetration tests against the deployed configuration. Do not claim ASVS Level 3 compliance until the applicable ASVS 5.0.0 requirements are independently verified with evidence.
