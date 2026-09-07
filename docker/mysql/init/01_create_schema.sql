-- Customer 360 master data for the AIDP federated-query demo.
--
-- This file is intentionally free of credentials. User creation and grants live
-- in 02_create_starburst_reader.sh, which reads passwords from the container
-- environment so no secret is ever written to a SQL file or into Git.
--
-- Runs once, via /docker-entrypoint-initdb.d, when the data volume is empty.

CREATE DATABASE IF NOT EXISTS customer360
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_0900_ai_ci;

USE customer360;

-- All PII-shaped columns hold masked, synthetic values only. See
-- scripts/generate_customer360.py: national IDs, phone numbers and e-mail
-- addresses are fabricated, and e-mail uses the reserved .invalid TLD
-- (RFC 6761) so no address can ever resolve to a real mailbox.
CREATE TABLE IF NOT EXISTS customers (
    customer_id                VARCHAR(32)    NOT NULL,
    account_id                 VARCHAR(32)    NOT NULL,
    full_name                  VARCHAR(128)   NOT NULL,
    national_id_masked         VARCHAR(32)    NOT NULL,
    date_of_birth              DATE           NULL,
    age_group                  VARCHAR(16)    NULL,
    gender                     VARCHAR(16)    NULL,
    email                      VARCHAR(128)   NULL,
    mobile_number_masked       VARCHAR(32)    NULL,
    city                       VARCHAR(64)    NULL,
    province                   VARCHAR(64)    NULL,
    country                    CHAR(2)        NOT NULL DEFAULT 'TH',
    postal_code                VARCHAR(16)    NULL,
    customer_tier              VARCHAR(16)    NOT NULL,
    occupation                 VARCHAR(64)    NULL,
    annual_income              DECIMAL(14, 2) NULL,
    risk_rating                VARCHAR(16)    NOT NULL,
    kyc_status                 VARCHAR(16)    NOT NULL,
    pep_flag                   TINYINT(1)     NOT NULL DEFAULT 0,
    sanctions_screening_status VARCHAR(32)    NOT NULL DEFAULT 'CLEAR',
    account_open_date          DATE           NULL,
    preferred_channel          VARCHAR(32)    NULL,
    marketing_consent          TINYINT(1)     NOT NULL DEFAULT 0,
    created_at                 TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                 TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP
                                              ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (customer_id),
    -- account_id is the federated join key against the Iceberg tables, so it
    -- must be unique: a duplicate would multiply every aggregate downstream.
    UNIQUE KEY uk_customers_account_id (account_id)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = 'Synthetic Customer 360 master data - AIDP federated demo';

-- Indexes backing the demo's filter and GROUP BY predicates. The MySQL
-- connector can push simple equality filters down to these.
CREATE INDEX idx_customers_city          ON customers (city);
CREATE INDEX idx_customers_tier          ON customers (customer_tier);
CREATE INDEX idx_customers_risk_rating   ON customers (risk_rating);
CREATE INDEX idx_customers_kyc_status    ON customers (kyc_status);
CREATE INDEX idx_customers_pep_flag      ON customers (pep_flag);
-- Composite index for the "high-risk or PEP" screening query.
CREATE INDEX idx_customers_risk_pep      ON customers (risk_rating, pep_flag);
