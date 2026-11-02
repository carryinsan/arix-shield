# Durable state and deployment contract

ArixShield's serverless control plane uses the configured Upstash Redis REST service for distributed counters, rate-limit Lua scripts, nonce replay protection, session indexes, audit-chain serialization, and customer record storage. The customer `arix:user:*` and `arix:project:*` JSON records are envelope-encrypted by `api/_lib/redis.js`; this does not mean that all Redis keys are encrypted or that Redis itself is a consensus cluster.

## Production requirements

- Configure both `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`. A partial/malformed configuration fails closed. No process-local fallback is suitable for production.
- Use a managed Redis deployment with documented persistence, backups, TLS, access controls, network policy, monitoring, and a tested restore procedure. Confirm the provider's actual durability/failover semantics; this repository does not implement Raft, quorum, multi-region consensus, or a distributed WAL.
- Set the existing `ARIX_MASTER_SECRET` to at least 32 random bytes. For independently managed KEKs, use `ARIX_CUSTOMER_RECORD_KEKS_JSON` with canonical base64 32-byte keys and a selected `ARIX_CUSTOMER_RECORD_KEK_VERSION`. Keep all old KEKs available until every record and backup using that version has been migrated.
- Set `ARIX_CUSTOMER_RECORD_ENCRYPTION_REQUIRED=true` after migration/compatibility verification. Legacy records are upgraded on first read using Redis compare-and-set; the migration preserves an existing TTL. Monitor migration errors and test restore with the same KEK set.
- Restrict Redis credentials to the application, rotate credentials through the provider's secret-management workflow, and avoid logging command payloads or customer data.

## What is not supplied

This directory intentionally does not claim to contain a replicated database, Raft implementation, autonomous failover controller, WORM audit vault, external KMS/HSM, or live customer state. Those require an operated backend and provider-level evidence. Do not replace the managed state provider with a local `Map` or claim cross-instance durability from development tests.
