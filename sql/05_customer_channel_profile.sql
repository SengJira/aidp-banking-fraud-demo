-- 05 - Customer channel profile
--
-- Compares the channel a customer SAYS they prefer (MySQL master data) with
-- the channels they ACTUALLY use (Iceberg payments) and how they authenticate
-- (Iceberg customer_events logins).
--
-- Three sources, three grains. Payments and logins are both many-per-account,
-- so joining them directly would multiply rows (20 payments x 8 logins = 160
-- rows). Each is collapsed to ONE ROW PER account_id in its own CTE first, so
-- every join to the customer table is 1:1 and no count is inflated.

WITH payment_channel AS (
    SELECT
        account_id,
        COUNT(*)                                                AS payment_count,
        -- Most-used payment channel: the window function below counts uses per
        -- (account, channel), so MAX_BY picks the channel with the highest count
        -- without needing a self-join or a second GROUP BY pass.
        MAX_BY(channel, channel_uses)                           AS top_payment_channel,
        ROUND(SUM(amount), 2)                                   AS total_payment_amount
    FROM (
        SELECT
            account_id,
            channel,
            amount,
            COUNT(*) OVER (PARTITION BY account_id, channel)    AS channel_uses
        FROM js_financial_ice.banking.payment_transactions
        WHERE event_date >= current_date - INTERVAL '7' DAY
    )
    GROUP BY account_id
),
login_behaviour AS (
    SELECT
        account_id,
        COUNT(*)                                                AS login_attempts,
        COUNT_IF(login_success)                                 AS successful_logins,
        COUNT_IF(NOT login_success)                             AS failed_logins,
        COUNT_IF(new_device)                                    AS new_device_logins,
        MAX_BY(channel, channel_uses)                           AS top_login_channel,
        ARRAY_JOIN(ARRAY_AGG(DISTINCT auth_method), ', ')       AS auth_methods_used
    FROM (
        SELECT
            account_id,
            channel,
            auth_method,
            login_success,
            new_device,
            COUNT(*) OVER (PARTITION BY account_id, channel)    AS channel_uses
        FROM js_financial_ice.banking.customer_events
        WHERE event_type = 'CUSTOMER_LOGIN'
          AND event_date >= current_date - INTERVAL '7' DAY
    )
    GROUP BY account_id
)
SELECT
    -- Stated preference: MySQL
    c.customer_id,
    c.account_id,
    c.full_name,
    c.customer_tier,
    c.city,
    c.preferred_channel                             AS stated_preferred_channel,
    -- Observed payment behaviour: Iceberg
    pc.top_payment_channel                          AS actual_top_payment_channel,
    COALESCE(pc.payment_count, 0)                   AS payment_count,
    COALESCE(pc.total_payment_amount, 0)            AS total_payment_amount,
    -- Observed login behaviour: Iceberg
    lb.top_login_channel                            AS actual_top_login_channel,
    COALESCE(lb.login_attempts, 0)                  AS login_attempts,
    COALESCE(lb.successful_logins, 0)               AS successful_logins,
    COALESCE(lb.failed_logins, 0)                   AS failed_logins,
    COALESCE(lb.new_device_logins, 0)               AS new_device_logins,
    lb.auth_methods_used,
    -- Does behaviour match the stated preference?
    CASE
        WHEN pc.top_payment_channel IS NULL THEN 'NO_PAYMENT_ACTIVITY'
        WHEN pc.top_payment_channel = c.preferred_channel THEN 'MATCHES_PREFERENCE'
        ELSE 'DIFFERS_FROM_PREFERENCE'
    END                                             AS channel_alignment
FROM js_mysql_customer360.customer360.customers c
LEFT JOIN payment_channel  pc ON pc.account_id = c.account_id
LEFT JOIN login_behaviour  lb ON lb.account_id = c.account_id
WHERE pc.account_id IS NOT NULL OR lb.account_id IS NOT NULL
ORDER BY payment_count DESC, login_attempts DESC
LIMIT 100;
