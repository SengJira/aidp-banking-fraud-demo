CREATE SCHEMA IF NOT EXISTS banking_iceberg.banking
WITH (
    location = 's3://aidp-s3ds/warehouse/banking'
);

-- 1. Payment Transactions
CREATE TABLE IF NOT EXISTS banking_iceberg.banking.payment_transactions (
    event_id            VARCHAR,
    event_type          VARCHAR,
    timestamp           TIMESTAMP(6),
    transaction_id      VARCHAR,
    account_id          VARCHAR,
    amount              DOUBLE,
    currency            VARCHAR,
    channel             VARCHAR,
    merchant_category   VARCHAR,
    status              VARCHAR,
    city                VARCHAR,
    country             VARCHAR,
    latitude            DOUBLE,
    longitude           DOUBLE,
    is_international    BOOLEAN,
    customer_tier       VARCHAR,
    risk_score          DOUBLE,
    ingested_at         TIMESTAMP(6),
    event_date          DATE
)
WITH (
    format = 'PARQUET',
    partitioning = ARRAY['event_date', 'city'],
    sorted_by = ARRAY['timestamp DESC NULLS LAST'],
    location = 's3://aidp-s3ds/warehouse/banking/payment_transactions'
);

-- 2. Payment Aggregates
CREATE TABLE IF NOT EXISTS banking_iceberg.banking.payment_agg (
    window_start        TIMESTAMP(6),
    window_end          TIMESTAMP(6),
    city                VARCHAR,
    channel             VARCHAR,
    merchant_category   VARCHAR,
    txn_count           BIGINT,
    total_amount        DOUBLE,
    avg_amount          DOUBLE,
    max_amount          DOUBLE,
    approved_count      BIGINT,
    declined_count      BIGINT,
    intl_count          BIGINT,
    avg_risk_score      DOUBLE,
    event_date          DATE
)
WITH (
    format = 'PARQUET',
    partitioning = ARRAY['event_date', 'city'],
    location = 's3://aidp-s3ds/warehouse/banking/payment_agg'
);

-- 3. Fraud Alerts
CREATE TABLE IF NOT EXISTS banking_iceberg.banking.fraud_alerts (
    event_id        VARCHAR,
    event_type      VARCHAR,
    timestamp       TIMESTAMP(6),
    account_id      VARCHAR,
    fraud_type      VARCHAR,
    ml_scroe        DOUBLE,
    action          VARCHAR,
    case_id         VARCHAR,
    event_date      DATE
)
WITH (
    format = 'PARQUET',
    partitioning = ARRAY['event_date', 'fraud_type'],
    location = 's3://aidp-s3ds/warehouse/banking/fraud_alerts'
);

-- 4. AML Alerts
CREATE TABLE IF NOT EXISTS banking_iceberg.banking.aml_alerts (
    event_id        VARCHAR,
    event_type      VARCHAR,
    timestamp       TIMESTAMP(6),
    account_id      VARCHAR,
    alert_type      VARCHAR,
    risk_band       VARCHAR,
    sar_required    BOOLEAN,
    total_amount_7d DOUBLE,
    event_date      DATE
)
WITH (
    format = 'PARQUET',
    partitioning = ARRAY['event_date', 'risk_band'],
    location = 's3://aidp-s3ds/warehouse/banking/aml_alerts'
);

-- 5. Customer Events
CREATE TABLE IF NOT EXISTS banking_iceberg.banking.customer_events (
    event_id        VARCHAR,
    event_type      VARCHAR,
    timestamp       TIMESTAMP(6),
    account_id      VARCHAR,
    channel         VARCHAR,
    auth_method     VARCHAR,
    login_success   BOOLEAN,
    event_date      DATE
)
WITH (
    format = 'PARQUET',
    partitioning = ARRAY['event_date'],
    location = 's3://aidp-s3ds/warehouse/banking/customer_events'
);



SELECT * FROM "banking_iceberg"."banking"."payment_transactions" LIMIT 10;

select count(*) from "banking_iceberg"."banking"."payment_transactions";

SELECT * FROM "banking_iceberg"."banking"."fraud_alerts" LIMIT 10;