-- 06 - Federated match-quality validation
--
-- Proves the two sides really do join, and quantifies the intentionally
-- unmatched share. The Kafka generator sends a configurable percentage of
-- events (default 1%) with account IDs that are absent from MySQL, so a
-- healthy demo shows roughly 99% matched and ~1% unmatched. 100% would mean
-- the data-quality path is untested; a very low number means the account-ID
-- formats have diverged.
--
-- Counting is done on DISTINCT account_id, so a customer with many
-- transactions does not skew the percentage.

WITH payment_accounts AS (
    SELECT DISTINCT account_id
    FROM js_financial_ice.banking.payment_transactions
    WHERE event_date >= current_date - INTERVAL '1' DAY
),
fraud_accounts AS (
    SELECT DISTINCT account_id
    FROM js_financial_ice.banking.fraud_alerts
    WHERE event_date >= current_date - INTERVAL '1' DAY
),
customer_event_accounts AS (
    SELECT DISTINCT account_id
    FROM js_financial_ice.banking.customer_events
    WHERE event_date >= current_date - INTERVAL '1' DAY
),
master AS (
    SELECT account_id
    FROM js_mysql_customer360.customer360.customers
)
SELECT
    'payment_transactions'                                      AS iceberg_source,
    COUNT(*)                                                    AS total_accounts,
    COUNT_IF(m.account_id IS NOT NULL)                          AS matched_accounts,
    COUNT_IF(m.account_id IS NULL)                              AS unmatched_accounts,
    ROUND(100.0 * COUNT_IF(m.account_id IS NOT NULL) / COUNT(*), 2) AS match_percentage
FROM payment_accounts p
LEFT JOIN master m ON m.account_id = p.account_id

UNION ALL
SELECT
    'fraud_alerts',
    COUNT(*),
    COUNT_IF(m.account_id IS NOT NULL),
    COUNT_IF(m.account_id IS NULL),
    ROUND(100.0 * COUNT_IF(m.account_id IS NOT NULL) / COUNT(*), 2)
FROM fraud_accounts f
LEFT JOIN master m ON m.account_id = f.account_id

UNION ALL
SELECT
    'customer_events',
    COUNT(*),
    COUNT_IF(m.account_id IS NOT NULL),
    COUNT_IF(m.account_id IS NULL),
    ROUND(100.0 * COUNT_IF(m.account_id IS NOT NULL) / COUNT(*), 2)
FROM customer_event_accounts e
LEFT JOIN master m ON m.account_id = e.account_id

ORDER BY iceberg_source;


-- ---------------------------------------------------------------------------
-- Event-level match rate (weighted by volume rather than distinct accounts).
-- This is the number the validation script checks against the 95% threshold.
-- ---------------------------------------------------------------------------
SELECT
    'payment_transactions'                                          AS iceberg_source,
    COUNT(*)                                                        AS total_events,
    COUNT_IF(c.account_id IS NOT NULL)                              AS matched_events,
    ROUND(100.0 * COUNT_IF(c.account_id IS NOT NULL) / COUNT(*), 2) AS match_percentage
FROM js_financial_ice.banking.payment_transactions p
LEFT JOIN js_mysql_customer360.customer360.customers c
    ON c.account_id = p.account_id
WHERE p.timestamp >= current_timestamp - INTERVAL '1' HOUR

UNION ALL
SELECT
    'fraud_alerts',
    COUNT(*),
    COUNT_IF(c.account_id IS NOT NULL),
    ROUND(100.0 * COUNT_IF(c.account_id IS NOT NULL) / COUNT(*), 2)
FROM js_financial_ice.banking.fraud_alerts f
LEFT JOIN js_mysql_customer360.customer360.customers c
    ON c.account_id = f.account_id
WHERE f.timestamp >= current_timestamp - INTERVAL '1' HOUR

ORDER BY iceberg_source;


-- ---------------------------------------------------------------------------
-- Show the unmatched accounts themselves - the data-quality exception list.
-- These are the deliberately "unknown" accounts injected by the generator.
-- ---------------------------------------------------------------------------
SELECT
    p.account_id                    AS unmatched_account_id,
    COUNT(*)                        AS event_count,
    ROUND(SUM(p.amount), 2)         AS total_amount,
    MIN(p.timestamp)                AS first_seen,
    MAX(p.timestamp)                AS last_seen
FROM js_financial_ice.banking.payment_transactions p
LEFT JOIN js_mysql_customer360.customer360.customers c
    ON c.account_id = p.account_id
WHERE c.account_id IS NULL
  AND p.timestamp >= current_timestamp - INTERVAL '1' HOUR
GROUP BY p.account_id
ORDER BY event_count DESC
LIMIT 25;


-- ---------------------------------------------------------------------------
-- Guard against the classic federated-join bug: a duplicated join key on the
-- MySQL side silently multiplies every SUM/COUNT.
-- Expect duplicate_account_ids = 0.
-- ---------------------------------------------------------------------------
SELECT
    COUNT(*)                              AS customer_rows,
    COUNT(DISTINCT account_id)            AS distinct_account_ids,
    COUNT(*) - COUNT(DISTINCT account_id) AS duplicate_account_ids
FROM js_mysql_customer360.customer360.customers;
