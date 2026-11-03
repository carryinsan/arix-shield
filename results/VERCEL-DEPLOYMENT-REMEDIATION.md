# Vercel middleware invocation failure — remediation

Date: 2026-11-03  
Target: ArixShield v1.4.4 consolidated release  
Observed production deployment: `dpl_BrByVRS6epaRPipe3Sdeb6kKxKGe`

## Root cause

The deployed root `middleware.js` statically imported `NextResponse` from `next/server`. The ArixShield project is a framework-independent Vercel project and does not declare or use the Next.js runtime. Vercel therefore failed to resolve `next` while loading the middleware; this occurred before any request or optional edge-clearance check ran.

## Changes made

1. Deleted the legacy `middleware.js` file so Vercel no longer attempts to load the invalid Next.js-based middleware entrypoint.
2. Added root `proxy.js` and configured `vercel.json` with `proxy.entrypoint: "proxy.js"` and an explicit matcher excluding static/image/favicon/robots/sitemap paths.
3. Added the exact, pinned first-party dependency `@vercel/functions@3.10.5`. The handler uses its documented `next()` helper to continue normal routing; no Next.js framework package or external API key is required.
4. Moved the edge-clearance verification into `proxy-core.js` and converted it to the standard Web `Request` API (`new URL(request.url)` and bounded `Cookie` header parsing).
5. Preserved the HMAC ticket signing contract and policy: same domain separator, HKDF salt/info, key derivation, payload version, five-minute maximum lifetime, audience, path-prefix boundary, optional method allowlist, nonce shape, and fail-closed responses. Duplicate clearance cookie names are rejected as ambiguous.
6. Updated the runtime integrity path allowlist and repository check to enforce the configured `proxy.entrypoint`, default export, exact helper dependency, and removal of the obsolete root middleware.

## Verification

- Repository suite: **207 passed, 0 failed, 0 skipped**.
- New Vercel middleware tests: **10 passed**.
- `npm run check`: passed; 113 JS/MJS syntax checks, 66 API/SDK imports, static checks, 116-file integrity manifest.
- Controlled `npm run build` preflight: passed with disposable local test-only secrets and a generated temporary RSA-3072 key. No real production credentials were used.
- Supplied brutal security pack v1.0.0: **30 passed, 0 failed, 0 skipped** on a clean extraction of the final ZIP, with 50,000 soak operations and 12 OS race workers. Inspection p99 for a 256 KiB payload was **4.38 ms** against the pack's 5 ms threshold; p50 was 2.48 ms and max sample 37.10 ms. This run was executed against a clean extraction of the final ZIP. Runtime event-loop p99 lag was 52.07 ms and correctly raised the `EVENT_LOOP_LAG` signal.

## Deployment instructions

Deploy from the directory containing `package.json` and `vercel.json` as the Vercel project root. Do not set the Framework Preset to Next.js. The Vercel build must install the declared dependency from `package.json`. Keep the existing production secrets and customer infrastructure configuration unchanged. After deployment, verify that `/` and `/arix-client.js` no longer log `ERR_MODULE_NOT_FOUND` or `MIDDLEWARE_INVOCATION_FAILED`.

## Scope and limitations

The source code and local tests were verified here, but no deployment was made to the user's Vercel project. Vercel's platform-level routing behavior and dependency installation in the live project remain to be confirmed by deployment. This report does not assert zero undiscovered defects, independent penetration-test certification, or OWASP ASVS 5.0.0 Level 3 compliance.
