# ArixShield independent edge gateway

This is a runnable, dependency-free Node.js 22 reverse proxy. It accepts HTTP/1.1 requests, enforces bounded request size/concurrency/timeouts, rejects ambiguous framing and duplicate security-sensitive headers, strips client-supplied forwarding and ArixShield origin headers, and signs the exact method, request-target, client address and raw body with an Ed25519 key before forwarding to the configured HTTPS origin. The origin adapter verifies that proof and consumes its nonce in shared Redis before invoking an API route.

## Required deployment topology

```text
Internet
  -> managed CDN / volumetric DDoS scrubbing / L3-L7 load balancer
  -> ArixShield edge gateway (this service; TLS enabled here or terminated by a private trusted load balancer)
  -> HTTPS origin (firewall allows only gateway egress; origin lock enabled)
  -> ArixShield API
```

The gateway is an application reverse proxy; it is **not** a global traffic-scrubbing network and cannot absorb a saturated ISP link, SYN flood, or upstream bandwidth attack. A provider with network-layer DDoS protection is still mandatory. Do not expose the origin directly. Restrict the origin firewall/security group to the gateway's egress addresses and require the proof verifier below. If the gateway runs behind a TLS terminator, keep its listener on a private network and set `EDGE_TRUSTED_TLS_TERMINATOR=true`; otherwise provide `EDGE_TLS_CERT_FILE` and `EDGE_TLS_KEY_FILE`.

## Configure

Generate an Ed25519 key pair once in a trusted secret-management environment. Keep the PEM private key only on the gateway; set the matching public PEM as `ARIX_ORIGIN_PUBLIC_KEY` only on the origin. Do not commit either key. No API key is added.

```sh
node -e "const c=require('node:crypto');const {publicKey,privateKey}=c.generateKeyPairSync('ed25519');require('node:fs').writeFileSync('edge-origin-private.pem',privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});require('node:fs').writeFileSync('edge-origin-public.pem',publicKey.export({type:'spki',format:'pem'}),{mode:0o644})"
```

Gateway environment:

- `EDGE_UPSTREAM_URL=https://your-origin.example` (HTTPS required)
- `EDGE_ORIGIN_PRIVATE_KEY_FILE=/run/secrets/edge-origin-private.pem`
- `EDGE_TLS_CERT_FILE` and `EDGE_TLS_KEY_FILE`, or a private trusted TLS terminator
- `EDGE_TRUSTED_PROXY_CIDRS` only when a known load balancer/CDN sits directly in front
- `EDGE_CLIENT_IP_HEADER` must name the single-IP header written by that trusted proxy (default `x-forwarded-for`; comma-separated chains are rejected)
- Optional bounds: `EDGE_MAX_BODY_BYTES` (1 MiB default, maximum 10 MiB), `EDGE_MAX_CONCURRENT_REQUESTS` (256 default), `EDGE_MAX_BUFFERED_BYTES` (32 MiB default)

Origin environment:

- `ARIX_ORIGIN_PUBLIC_KEY` = matching public PEM
- `ARIX_ORIGIN_LOCK_REQUIRED=true`
- `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` for shared atomic nonce replay prevention
- Disable the platform's request body parser on API routes so the adapter can verify the exact raw bytes (`api.bodyParser=false`). The repository's routes now declare this setting.

The signed proof expires after 30 seconds by default and nonce consumption fails closed when Redis is missing or unavailable. Every gateway instance uses the same signing key, while nonce uniqueness is enforced at the origin by shared Redis. Use a key-rotation window only with a deliberately staged dual-key verifier; the current verifier accepts one configured public key.

## Run

```sh
node edge/gateway.mjs
```

The Dockerfile runs as the unprivileged `node` user. Mount the private key and TLS material as read-only secrets. Add resource limits, a private container network, an upstream egress allowlist, a health check, central logs and an external managed DDoS provider in the deployment platform. The in-memory connection/backpressure limits are per process and are not distributed rate limits.

## Operational limits

- This proxy buffers each request body before signing it; the configured aggregate buffer cap is enforced to bound memory. Raise limits only after load testing and matching origin limits.
- It uses Node's strict HTTP/1 parser. The browser/API deployment must use the same effective canonical request-target and body bytes at the origin.
- It does not implement HTTP/2, WebSockets, arbitrary TCP tunnelling, global rate coordination, managed bot challenges, global scrubbing, or a network firewall.
- TLS, origin firewalling, DNS, certificate rotation, autoscaling, observability, DDoS scrubbing and multi-region failover must be configured and tested in the actual hosting account.


## Timeout and connection behavior

The upstream deadline is absolute per request, in addition to the idle-socket timeout; a slow-drip response cannot hold a request slot forever. A downstream disconnect aborts the corresponding upstream request. The gateway destroys its keep-alive upstream agent when the listener closes.
