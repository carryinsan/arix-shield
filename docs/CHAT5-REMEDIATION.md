# Chat 5 targeted remediation and verification notes

This archive applies four targeted corrections to the supplied ArixShield v1.4.4 consolidated tree. The archive name is `arix-shield-chat5.zip`; the internal package version remains `1.4.4` to avoid presenting this narrowly scoped patch as a separately versioned upstream release.

## Findings addressed

| Finding | Change | Regression evidence |
|---|---|---|
| Slow-drip request body exceeded the configured request deadline | `edge/gateway.mjs` now enforces a monotonic, whole-body deadline while reading, not merely an idle timeout. A timed-out/oversized/aborted read pauses the request, releases its reserved buffer bytes, returns a bounded error and closes the connection. | External brutal test: one byte every 200 ms with a 1-second timeout returned after about 1.0 seconds; gateway disconnect and upstream timeout tests also run. |
| Distinct ZIP central-directory entries could alias one local record | `api/_lib/file-security.js` rejects duplicate canonical names, reused local-header offsets, and overlapping local-record/data-descriptor intervals. | Source regression verifies two distinct central names cannot point at one local header; external ZIP suite exercises aliased local offsets. |
| JSON `1e309` overflowed to `Infinity` and passed WAF inspection | `api/_lib/waf-engine.js` rejects non-finite numeric values in parsed structures and schema validation. Its raw JSON scanner now validates numeric token grammar and detects values that overflow JavaScript's finite number range. Finite `-0` remains accepted by the WAF layer. | Source regressions cover parsed object, raw JSON text, root-level `Infinity`, schema validation, and finite negative zero; external protocol parser suite covers overflow and `-0`. |
| 256 KiB WAF inspection missed the 5 ms p99 target | The text canonicalizer now avoids decode/comment/concatenation work when sentinel syntax is absent. SQL prefiltering skips uppercase conversion for giant identifiers that cannot equal any recognized SQL keyword/function. Detection rules remain in the inspection path. | External 120-sample 256 KiB benchmark is run unchanged with the test pack's 5 ms p99 budget; measured results are recorded in the final test report. |

## Verification scope

The supplied external test pack is executed against this source tree without changing its thresholds or assertions. The repository test suite, syntax/import/static integrity checks, and integrity manifests are also regenerated and checked. Results are local to the recorded Node.js/runtime/host and are not a substitute for production ingress tests, an independent penetration test, or OWASP ASVS 5.0.0 Level 3 certification.

No claim is made that software is bug-free or vulnerability-free. External services, deployed TLS/mTLS certificates, Redis, databases, cloud ingress, and customer-specific routes are outside the local test environment.
