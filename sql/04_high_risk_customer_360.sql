-- 04 - High-risk Customer 360
--
-- High-risk or PEP customers, with their fraud activity and payment exposure
-- side by side.
--
-- IMPORTANT - avoiding inflated totals
-- ------------------------------------
-- Joining customers -> payments -> fraud_alerts in one FROM clause produces a
-- many-to-many fan-out: a customer with 20 payments and 3 alerts yields 60
-- rows, so SUM(amount) would report 3x the real exposure.
--
-- Each Iceberg source is therefore pre-aggregated to ONE ROW PER account_id in
-- its own CTE, and only then joined to the customer table. Every join below is
-- 1:1, so the totals are correct.

WITH payment_exposure AS (
    -- One row per account.
    SELECT
        account_id,
        COUNT(*)                                    AS payment_count,
        ROUND(SUM(amount), 2)                       AS total_payment_amount,
        ROUND(AVG(amount), 2)                       AS average_payment_amount,
        COUNT_IF(is_international)                  AS international_payment_count,
        MAX(timestamp)                              AS latest_payment_at
    FROM js_financial_ice.banking.payment_transactions
    WHERE event_date >= current_date - INTERVAL '7' DAY
    GROUP BY account_id
),
fraud_exposure AS (
    -- One row per account.
    SELECT
        account_id,
        COUNT(*)                                    AS fraud_alert_count,
        MAX(ml_score)                               AS max_fraud_score,
        ROUND(AVG(ml_score), 4)                     AS avg_fraud_score,
        COUNT_IF(action = 'BLOCK_AND_ALERT')        AS blocked_alert_count,
        MAX(timestamp)                              AS latest_fraud_alert_at
    FROM js_financial_ice.banking.fraud_alerts
    WHERE event_date >= current_date - INTERVAL '7' DAY
    GROUP BY account_id
)
SELECT
    -- Customer profile: MySQL
    c.customer_id,
    c.account_id,
    c.full_name,
    c.customer_tier,
    c.city,
    c.risk_rating,
    c.kyc_status,
    c.pep_flag,
    c.sanctions_screening_status,
    -- Fraud activity: Iceberg
    COALESCE(f.fraud_alert_count, 0)                AS fraud_alert_count,
    f.max_fraud_score,
    COALESCE(f.blocked_alert_count, 0)              AS blocked_alert_count,
    -- Payment exposure: Iceberg
    COALESCE(p.payment_count, 0)                    AS payment_count,
    COALESCE(p.total_payment_amount, 0)             AS total_payment_amount,
    COALESCE(p.international_payment_count, 0)      AS international_payment_count,
    -- Most recent activity across both event streams
    GREATEST(
        COALESCE(f.latest_fraud_alert_at, TIMESTAMP '1970-01-01 00:00:00 UTC'),
        COALESCE(p.latest_payment_at,     TIMESTAMP '1970-01-01 00:00:00 UTC')
    )                                               AS most_recent_event_at
FROM js_mysql_customer360.customer360.customers c
LEFT JOIN payment_exposure p ON p.account_id = c.account_id
LEFT JOIN fraud_exposure   f ON f.account_id = c.account_id
WHERE (c.risk_rating = 'HIGH' OR c.pep_flag = 1)
  -- Only customers that actually transacted or triggered an alert.
  AND (f.account_id IS NOT NULL OR p.account_id IS NOT NULL)
ORDER BY
    f.max_fraud_score DESC NULLS LAST,
    total_payment_amount DESC
LIMIT 100;
