CREATE TABLE IF NOT EXISTS arixshield_events
(
    timestamp DateTime64(3, 'UTC'),
    project_id String,
    event_type LowCardinality(String),
    blocked UInt8,
    status UInt16,
    latency_ms UInt32,
    route String,
    method LowCardinality(String),
    ip String,
    country LowCardinality(String),
    city String,
    asn String,
    actor_hash String,
    details String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (project_id, timestamp, event_type)
TTL timestamp + INTERVAL 90 DAY;
