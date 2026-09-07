-- 01 - MySQL catalog validation
--
-- Run these first, in order, after the AIDP administrator has created the
-- js_mysql_customer360 catalog. Each statement is independent: run them one at
-- a time in the AIDP SQL editor or via the Trino CLI.
--
-- Catalog: js_mysql_customer360  (MySQL 8.0, read-only user starburst_ro)
-- Target : js_mysql_customer360.customer360.customers

-- 1. Is the catalog registered and reachable?
--    Expect: customer360, information_schema, performance_schema
SHOW SCHEMAS FROM js_mysql_customer360;

-- 2. Is the customers table visible through the connector?
--    Expect: customers
SHOW TABLES FROM js_mysql_customer360.customer360;

-- 3. Did the master data load?
--    Expect: 10000
SELECT COUNT(*) AS customer_count
FROM js_mysql_customer360.customer360.customers;

-- 4. Column types as mapped by the MySQL connector. Useful when a join fails:
--    account_id must be a character type on both sides.
DESCRIBE js_mysql_customer360.customer360.customers;

-- 5. The join key must be unique, or every downstream aggregate is inflated.
--    Expect: total_rows = distinct_accounts = 10000, duplicate_accounts = 0
SELECT
    COUNT(*)                                        AS total_rows,
    COUNT(DISTINCT account_id)                      AS distinct_accounts,
    COUNT(*) - COUNT(DISTINCT account_id)           AS duplicate_accounts
FROM js_mysql_customer360.customer360.customers;

-- 6. Account-ID format and range. Both sides must use ACC-TH-<8 digits>.
SELECT
    MIN(account_id)   AS first_account,
    MAX(account_id)   AS last_account,
    COUNT_IF(REGEXP_LIKE(account_id, '^ACC-TH-\d{8}$')) AS well_formed_accounts
FROM js_mysql_customer360.customer360.customers;

-- 7. Sanity-check the reference distributions the demo queries rely on.
SELECT
    customer_tier,
    risk_rating,
    COUNT(*) AS customers
FROM js_mysql_customer360.customer360.customers
GROUP BY customer_tier, risk_rating
ORDER BY customers DESC;

-- 8. Confirm the Iceberg side is present and streaming.
SELECT
    'payment_transactions' AS iceberg_table,
    COUNT(*)               AS row_count,
    MAX(timestamp)         AS newest_event
FROM js_financial_ice.banking.payment_transactions
UNION ALL
SELECT 'fraud_alerts', COUNT(*), MAX(timestamp)
FROM js_financial_ice.banking.fraud_alerts
UNION ALL
SELECT 'customer_events', COUNT(*), MAX(timestamp)
FROM js_financial_ice.banking.customer_events
UNION ALL
SELECT 'aml_alerts', COUNT(*), MAX(timestamp)
FROM js_financial_ice.banking.aml_alerts;

-- 9. The smallest possible proof of a cross-catalog join: one row combining a
--    MySQL column with an Iceberg column.
SELECT
    c.account_id,
    c.full_name        AS mysql_customer_name,
    c.customer_tier    AS mysql_tier,
    p.transaction_id   AS iceberg_transaction,
    p.amount           AS iceberg_amount,
    p.timestamp        AS iceberg_timestamp
FROM js_mysql_customer360.customer360.customers c
JOIN js_financial_ice.banking.payment_transactions p
    ON c.account_id = p.account_id
WHERE p.event_date >= current_date - INTERVAL '1' DAY
LIMIT 5;
