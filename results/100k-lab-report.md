# ArixShield 100k security lab results

- Generated: 2026-11-02T14:53:25.492Z
- Node: v22.16.0 (linux/x64)
- Seed: `0x4152495853484945`
- Vectors: **100,000 adversarial + 100,000 benign**
- Duration: **13.174 s**

## Measured results

| Metric | Result |
|---|---:|
| True positives / blocked adversarial | 100000 |
| False negatives / missed adversarial | 0 |
| True negatives / allowed benign | 100000 |
| False positives / rejected benign | 0 |
| Precision | 100.00000% |
| Recall | 100.00000% |
| False-positive rate | 0.00000% |
| p50 per-request latency | 0.03901 ms |
| p95 per-request latency | 0.14866 ms |
| p99 per-request latency | 0.39466 ms |
| Max per-request latency | 355.19002 ms |
| Throughput | 15182 vectors/s |

## Attack categories

| Category | Vectors | Blocked | Missed |
|---|---:|---:|---:|
| binary-magic | 5000 | 5000 | 0 |
| graphql | 5000 | 5000 | 0 |
| http-smuggling | 5000 | 5000 | 0 |
| http2-smuggling | 5000 | 5000 | 0 |
| image | 5000 | 5000 | 0 |
| ldap | 5000 | 5000 | 0 |
| multipart-magic | 5000 | 5000 | 0 |
| nested-encoding | 5000 | 5000 | 0 |
| nosql | 5000 | 5000 | 0 |
| parameter-pollution | 5000 | 5000 | 0 |
| prompt-injection | 5000 | 5000 | 0 |
| prototype-pollution | 5000 | 5000 | 0 |
| sqli-boolean | 5000 | 5000 | 0 |
| sqli-union | 5000 | 5000 | 0 |
| ssrf | 5000 | 5000 | 0 |
| ssti | 5000 | 5000 | 0 |
| unsafe-deserialization | 5000 | 5000 | 0 |
| xss | 5000 | 5000 | 0 |
| xxe | 5000 | 5000 | 0 |
| zip | 5000 | 5000 | 0 |

## Miss samples

```json
{
  "misses": [],
  "falsePositiveSamples": []
}
```

## Scope and limitations

- All checks are local/in-process; this is not a live network, browser, database, or cloud-provider test.
- Precision/recall describe this generated corpus and these explicit labels only; they are not population-wide production estimates.
- The image and ZIP helper vectors exercise library inspectors directly, not the full upload pipeline or a production malware sandbox.
- Parser differential cases are simulated request metadata; no real HTTP/1.1, HTTP/2, proxy, or origin parser pair is deployed here.

This report is a reproducible local test run, not an ASVS certification, penetration-test attestation, production block-rate guarantee, or proof of zero vulnerabilities.
