# Security boundaries and non-goals

ArixShield is a hybrid application-layer SDK and telemetry/control-plane product. It is not a volumetric DDoS scrubbing network, an Anycast BGP network, or a TLS termination proxy. It cannot inspect raw TCP handshakes or reconstruct native JA3/JA4 from a request after a hosting platform terminates TLS. It should not be positioned as a replacement for upstream DDoS protection.

This release intentionally does **not** implement the following proposed mechanisms:

- **Reverse-Slowloris / connection tarpit:** deliberately holding open connections can exhaust both customer and provider resources. Serverless billing semantics vary; no $0 cost guarantee exists.
- **Decompression bombs / parser starvation payloads:** deliberately sending tiny compressed data that expands into gigabytes is a denial-of-service weapon and is not appropriate defensive middleware.
- **Prompt-injection exfiltration:** injecting instructions intended to make third-party agents disclose their hidden system prompts, API keys, or tool configuration is not a legitimate security control. Detection and containment should not collect unrelated secrets.
- **WebRTC/STUN or cross-origin probing to deanonymize visitors:** this can reveal private LAN/network information and is not performed.
- **Automatic abuse reporting to third-party providers:** this release does not submit accusations or takedown requests without operator review and evidence validation.

Implemented safer alternatives include short-lived PoW challenges, verified source allowlisting, bounded synthetic honeypot responses, throttling/backoff, revocation hooks, sanitized forensics, signed browser proof-of-possession, and Merkle-hashed audit evidence.

## Known implementation limits

- The WAF remains JavaScript-based. There is no compiled Rust/libinjection WebAssembly module in this release. The CIDR engine uses an in-memory binary prefix trie built from validated feeds, not a Wasm Bloom filter.
- The dashboard includes a real-event 2D correlation canvas; it is not a 3D WebGL globe or a full React Flow attacker graph. Correlation is an investigative hint, not proof that IPs belong to one actor.
- Browser telemetry is deliberately minimized; it does not collect canvas/WebGL hardware fingerprinting or detailed behavioral recordings.
- Threat source allowlists are only as current as the configured provider ranges and feed refreshes. No feed can guarantee zero false positives or complete coverage.
- ClickHouse/Tinybird, AbuseIPDB, GitHub webhook delivery, and GitHub audit anchoring require external accounts, current credentials, schema/pipe setup, and correct provider permissions.
- The standard GitHub secret-scanning webhook may not deliver the raw secret. In that case ArixShield can log metadata but cannot automatically match and revoke a key by value.
- Distributed guarantees require Upstash Redis. The local mock is development-only and is not shared by serverless function instances.
- Geo-velocity accuracy depends on trustworthy location metadata. IP geolocation is approximate and can be wrong for VPNs, mobile carriers, and corporate egress.
- Request replay is intentionally sanitized; raw bodies, cookies and authorization headers are never retained.

No software can be represented as completely vulnerability-free. Run a dependency audit, provider configuration review, threat-model review, and independent penetration test before marketing this as an enterprise security control.
