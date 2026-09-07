-- 03 - Customer Fraud 360
--
-- Enriches real-time Iceberg fraud alerts with the MySQL customer profile that
-- the fraud pipeline itself does not hold: tier, KYC status and PEP flag.
-- This is the operational value of federation - the analyst sees who the
-- customer is without the streaming pipeline ever joining to master data.
--
--   MySQL   js_mysql_customer360.customer360.customers
--     |     account_id
--   Iceberg js_financial_ice.banking.fraud_alerts
--
-- This is a detail (row-level) query, so no aggregation and no fan-out risk.

SELECT
    c.customer_id,
    c.account_id,
    c.full_name,
    c.customer_tier,
    c.city,
    c.risk_rating           AS customer_risk_rating,
    c.kyc_status,
    c.pep_flag,
    f.timestamp             AS alert_timestamp,
    f.fraud_type,
    f.ml_score,
    f.action,
    f.case_id
FROM js_mysql_customer360.customer360.customers c
JOIN js_financial_ice.banking.fraud_alerts f
    ON c.account_id = f.account_id
WHERE f.timestamp >= current_timestamp - INTERVAL '24' HOUR
ORDER BY f.ml_score DESC, f.timestamp DESC
LIMIT 100;
