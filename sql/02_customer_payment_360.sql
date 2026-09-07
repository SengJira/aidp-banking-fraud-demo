-- 02 - Customer Payment 360
--
-- Joins MySQL Customer 360 master data directly to Iceberg payment
-- transactions. No data is copied: Starburst reads the customer rows from
-- MySQL and the transactions from Iceberg, then performs the join itself.
--
--   MySQL   js_mysql_customer360.customer360.customers
--     |     account_id
--   Iceberg js_financial_ice.banking.payment_transactions
--
-- Filtering on event_date lets the Iceberg reader prune partitions
-- (payment_transactions is partitioned by event_date, city).

SELECT
    c.customer_id,
    c.account_id,
    c.full_name,
    c.city                              AS customer_city,
    c.customer_tier,
    c.risk_rating,
    COUNT(p.transaction_id)             AS transaction_count,
    ROUND(SUM(p.amount), 2)             AS total_transaction_amount,
    ROUND(AVG(p.amount), 2)             AS average_transaction_amount,
    MAX(p.timestamp)                    AS latest_transaction
FROM js_mysql_customer360.customer360.customers c
JOIN js_financial_ice.banking.payment_transactions p
    ON c.account_id = p.account_id
WHERE p.event_date >= current_date - INTERVAL '7' DAY
GROUP BY
    c.customer_id,
    c.account_id,
    c.full_name,
    c.city,
    c.customer_tier,
    c.risk_rating
ORDER BY total_transaction_amount DESC
LIMIT 100;
