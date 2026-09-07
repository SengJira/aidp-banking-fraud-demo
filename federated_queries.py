"""Allowlisted federated (MySQL + Iceberg) questions for the Customer 360 page.

Why this module looks different from :mod:`fraud_queries`
--------------------------------------------------------
``fraud_queries`` compiles single-table questions into a DataFrame IR. Federated
questions need CTEs, multi-source joins and window functions, which that IR
deliberately does not express. Rather than widen it (and its safety surface),
each federated question here is a **fixed, reviewed SQL template**.

Safety properties are unchanged:

* Templates are constants in this file. User text is never concatenated in.
* The only substitutions are ``{hours}``, ``{limit}``, ``{score}`` and
  ``{account_id}``. The first three are validated numerics reused from
  :mod:`fraud_queries`; ``account_id`` is *rebuilt* from 8 extracted digits
  (``f"ACC-TH-{digits}"``), so no user-supplied character ever reaches the SQL.
* Every rendered statement is re-checked by ``fraud_queries.assert_read_only``.

Each question also records which output columns come from MySQL and which come
from Iceberg, so the UI can prove the join really did cross catalogs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from fraud_queries import (
    UnsupportedQuestionError,
    assert_read_only,
    normalize_question,
    validate_hours,
    validate_limit,
    validate_score_threshold,
)

#: Catalog names. Overridable so the demo still works if an administrator
#: registers the MySQL catalog under a different name.
MYSQL_CATALOG = "js_mysql_customer360"
MYSQL_SCHEMA = "customer360"
ICEBERG_CATALOG = "js_financial_ice"
ICEBERG_SCHEMA = "banking"

CUSTOMERS = f"{MYSQL_CATALOG}.{MYSQL_SCHEMA}.customers"
PAYMENTS = f"{ICEBERG_CATALOG}.{ICEBERG_SCHEMA}.payment_transactions"
FRAUD = f"{ICEBERG_CATALOG}.{ICEBERG_SCHEMA}.fraud_alerts"
CUSTOMER_EVENTS = f"{ICEBERG_CATALOG}.{ICEBERG_SCHEMA}.customer_events"
AML = f"{ICEBERG_CATALOG}.{ICEBERG_SCHEMA}.aml_alerts"

#: The demo's account-ID contract, enforced on both sides of the join.
ACCOUNT_ID_RE = re.compile(r"^ACC-TH-(\d{8})$")
#: Used to *extract* an account from free text before canonical reconstruction.
ACCOUNT_IN_TEXT_RE = re.compile(r"acc[-\s_]?th[-\s_]?(\d{8})", re.IGNORECASE)

DEFAULT_FEDERATED_HOURS = 24
DEFAULT_FEDERATED_LIMIT = 100


class InvalidAccountError(UnsupportedQuestionError):
    """Raised when an account-scoped question has no valid ACC-TH-######## id."""


def canonical_account_id(text: str) -> str:
    """Extract an account ID from free text and rebuild it canonically.

    Only the 8 matched digits survive; the returned value is constructed as
    ``f"ACC-TH-{digits}"``, so no user-supplied character can reach the SQL even
    though the question itself is free text.
    """
    match = ACCOUNT_IN_TEXT_RE.search(text or "")
    if not match:
        raise InvalidAccountError(
            "That question needs an account ID in the form ACC-TH-######## "
            "(8 digits), for example: Show the Customer 360 profile for account "
            "ACC-TH-10000001.",
            ["Show the Customer 360 profile for account ACC-TH-10000001."],
        )
    digits = match.group(1)
    if not digits.isdigit() or len(digits) != 8:  # defence in depth
        raise InvalidAccountError(
            "Account ID must be ACC-TH- followed by exactly 8 digits."
        )
    return f"ACC-TH-{digits}"


@dataclass(frozen=True)
class FederatedQuestion:
    """One allowlisted cross-catalog question."""

    name: str
    example: str
    description: str
    sql_template: str
    #: Output columns sourced from MySQL Customer 360.
    mysql_columns: tuple[str, ...]
    #: Output columns sourced from the Iceberg banking tables.
    iceberg_columns: tuple[str, ...]
    narrative: str
    required: tuple[tuple[str, ...], ...] = ()
    boost: tuple[str, ...] = ()
    excludes: tuple[str, ...] = ()
    chart: str | None = None
    chart_x: str | None = None
    chart_y: str | None = None
    needs_account: bool = False
    default_limit: int = DEFAULT_FEDERATED_LIMIT

    def render(
        self,
        hours: int | None = None,
        limit: int | None = None,
        score: float | None = None,
        account_id: str | None = None,
    ) -> str:
        """Render the template with validated parameters and re-check safety."""
        sql = self.sql_template.format(
            hours=validate_hours(hours, DEFAULT_FEDERATED_HOURS),
            limit=validate_limit(limit, self.default_limit),
            score=validate_score_threshold(score),
            account_id=account_id or "",
        )
        return assert_read_only(sql)


# --------------------------------------------------------------------------- #
# The 10 federated questions
# --------------------------------------------------------------------------- #
FEDERATED_QUESTIONS: tuple[FederatedQuestion, ...] = (
    FederatedQuestion(
        name="top_customers_by_payment",
        example="Who are the customers with the highest payment amount?",
        description="Ranks MySQL customers by their Iceberg payment volume.",
        required=(
            ("highest", "top", "largest", "most", "biggest"),
            ("payment", "payments", "spend", "amount", "transaction"),
        ),
        boost=("customers", "customer", "total", "value"),
        excludes=("fraud", "channel", "device", "unmatched", "city"),
        mysql_columns=(
            "customer_id",
            "account_id",
            "full_name",
            "customer_city",
            "customer_tier",
            "risk_rating",
        ),
        iceberg_columns=(
            "transaction_count",
            "total_transaction_amount",
            "average_transaction_amount",
            "latest_transaction",
        ),
        chart="bar",
        chart_x="full_name",
        chart_y="total_transaction_amount",
        narrative="customers ranked by total payment value",
        sql_template=f"""
SELECT
    c.customer_id,
    c.account_id,
    c.full_name,
    c.city                          AS customer_city,
    c.customer_tier,
    c.risk_rating,
    COUNT(p.transaction_id)         AS transaction_count,
    ROUND(SUM(p.amount), 2)         AS total_transaction_amount,
    ROUND(AVG(p.amount), 2)         AS average_transaction_amount,
    MAX(p.timestamp)                AS latest_transaction
FROM {CUSTOMERS} c
JOIN {PAYMENTS} p ON c.account_id = p.account_id
WHERE p.timestamp >= current_timestamp - INTERVAL '{{hours}}' HOUR
GROUP BY c.customer_id, c.account_id, c.full_name, c.city, c.customer_tier, c.risk_rating
ORDER BY total_transaction_amount DESC
LIMIT {{limit}}
""",
    ),
    FederatedQuestion(
        name="high_risk_with_fraud",
        example="Show high-risk customers with recent fraud alerts.",
        description="HIGH risk-rated MySQL customers that triggered Iceberg fraud alerts.",
        required=(("high risk", "high-risk", "risky"),),
        boost=("fraud", "alert", "alerts", "recent", "customers"),
        excludes=("pep", "platinum", "exposure", "channel", "device", "city"),
        mysql_columns=(
            "customer_id",
            "account_id",
            "full_name",
            "customer_tier",
            "city",
            "risk_rating",
            "kyc_status",
        ),
        iceberg_columns=(
            "alert_timestamp",
            "fraud_type",
            "ml_score",
            "action",
            "case_id",
        ),
        chart="bar",
        chart_x="fraud_type",
        chart_y="ml_score",
        narrative="high-risk customers with fraud alerts in the selected window",
        sql_template=f"""
SELECT
    c.customer_id,
    c.account_id,
    c.full_name,
    c.customer_tier,
    c.city,
    c.risk_rating,
    c.kyc_status,
    f.timestamp                     AS alert_timestamp,
    f.fraud_type,
    f.ml_score,
    f.action,
    f.case_id
FROM {CUSTOMERS} c
JOIN {FRAUD} f ON c.account_id = f.account_id
WHERE c.risk_rating = 'HIGH'
  AND f.timestamp >= current_timestamp - INTERVAL '{{hours}}' HOUR
ORDER BY f.ml_score DESC, f.timestamp DESC
LIMIT {{limit}}
""",
    ),
    FederatedQuestion(
        name="platinum_with_fraud",
        example="Which Platinum customers have fraud alerts?",
        description="Fraud alerts restricted to the PLATINUM tier held only in MySQL.",
        required=(("platinum",),),
        boost=("fraud", "alert", "alerts", "customers", "tier"),
        excludes=(),
        mysql_columns=(
            "customer_id",
            "account_id",
            "full_name",
            "customer_tier",
            "city",
            "annual_income",
            "risk_rating",
        ),
        iceberg_columns=(
            "fraud_alert_count",
            "max_ml_score",
            "latest_alert_at",
            "blocked_count",
        ),
        chart="bar",
        chart_x="full_name",
        chart_y="fraud_alert_count",
        narrative="PLATINUM-tier customers with fraud alerts",
        sql_template=f"""
WITH fraud_by_account AS (
    SELECT
        account_id,
        COUNT(*)                                AS fraud_alert_count,
        MAX(ml_score)                           AS max_ml_score,
        MAX(timestamp)                          AS latest_alert_at,
        COUNT_IF(action = 'BLOCK_AND_ALERT')    AS blocked_count
    FROM {FRAUD}
    WHERE timestamp >= current_timestamp - INTERVAL '{{hours}}' HOUR
    GROUP BY account_id
)
SELECT
    c.customer_id,
    c.account_id,
    c.full_name,
    c.customer_tier,
    c.city,
    c.annual_income,
    c.risk_rating,
    f.fraud_alert_count,
    f.max_ml_score,
    f.latest_alert_at,
    f.blocked_count
FROM {CUSTOMERS} c
JOIN fraud_by_account f ON f.account_id = c.account_id
WHERE c.customer_tier = 'PLATINUM'
ORDER BY f.max_ml_score DESC, f.fraud_alert_count DESC
LIMIT {{limit}}
""",
    ),
    FederatedQuestion(
        name="pep_high_fraud",
        example="Show PEP customers with high fraud scores.",
        description="Politically-exposed persons (a MySQL-only flag) with high ml_score alerts.",
        required=(("pep", "politically exposed", "politically-exposed"),),
        boost=("fraud", "score", "high", "customers", "sanctions"),
        excludes=(),
        mysql_columns=(
            "customer_id",
            "account_id",
            "full_name",
            "pep_flag",
            "sanctions_screening_status",
            "kyc_status",
            "customer_tier",
            "city",
        ),
        iceberg_columns=(
            "alert_timestamp",
            "fraud_type",
            "ml_score",
            "action",
            "case_id",
        ),
        chart="bar",
        chart_x="fraud_type",
        chart_y="ml_score",
        narrative="politically-exposed customers with high-scoring fraud alerts",
        sql_template=f"""
SELECT
    c.customer_id,
    c.account_id,
    c.full_name,
    c.pep_flag,
    c.sanctions_screening_status,
    c.kyc_status,
    c.customer_tier,
    c.city,
    f.timestamp                     AS alert_timestamp,
    f.fraud_type,
    f.ml_score,
    f.action,
    f.case_id
FROM {CUSTOMERS} c
JOIN {FRAUD} f ON c.account_id = f.account_id
WHERE c.pep_flag = 1
  AND f.ml_score >= {{score}}
  AND f.timestamp >= current_timestamp - INTERVAL '{{hours}}' HOUR
ORDER BY f.ml_score DESC, f.timestamp DESC
LIMIT {{limit}}
""",
    ),
    FederatedQuestion(
        name="channel_comparison",
        example="Compare customer preferred channels with actual payment channels.",
        description="Stated MySQL preference vs observed Iceberg payment channel.",
        required=(("channel", "channels"),),
        boost=("compare", "preferred", "actual", "payment", "profile"),
        excludes=("device",),
        mysql_columns=("stated_preferred_channel", "customers"),
        iceberg_columns=("actual_top_payment_channel", "payment_count", "total_amount"),
        chart="bar",
        chart_x="comparison",
        chart_y="customers",
        narrative="how stated channel preference compares with actual payment behaviour",
        sql_template=f"""
WITH payment_channel AS (
    SELECT
        account_id,
        MAX_BY(channel, channel_uses)   AS top_payment_channel,
        COUNT(*)                        AS payment_count,
        SUM(amount)                     AS total_amount
    FROM (
        SELECT account_id, channel, amount,
               COUNT(*) OVER (PARTITION BY account_id, channel) AS channel_uses
        FROM {PAYMENTS}
        WHERE timestamp >= current_timestamp - INTERVAL '{{hours}}' HOUR
    )
    GROUP BY account_id
)
SELECT
    c.preferred_channel                                     AS stated_preferred_channel,
    p.top_payment_channel                                   AS actual_top_payment_channel,
    c.preferred_channel || ' -> ' || p.top_payment_channel  AS comparison,
    COUNT(*)                                                AS customers,
    SUM(p.payment_count)                                    AS payment_count,
    ROUND(SUM(p.total_amount), 2)                           AS total_amount
FROM {CUSTOMERS} c
JOIN payment_channel p ON p.account_id = c.account_id
GROUP BY c.preferred_channel, p.top_payment_channel
ORDER BY customers DESC
LIMIT {{limit}}
""",
    ),
    FederatedQuestion(
        name="new_device_customers",
        example="Show customers using a new device.",
        description="MySQL customer profile for Iceberg logins flagged new_device.",
        required=(("new device", "new_device", "unknown device", "device"),),
        boost=("customers", "login", "logins", "using"),
        excludes=(),
        mysql_columns=(
            "customer_id",
            "account_id",
            "full_name",
            "customer_tier",
            "city",
            "risk_rating",
            "preferred_channel",
        ),
        iceberg_columns=(
            "new_device_logins",
            "total_logins",
            "failed_logins",
            "latest_login_at",
            "auth_methods",
        ),
        chart="bar",
        chart_x="full_name",
        chart_y="new_device_logins",
        narrative="customers who logged in from a previously unseen device",
        sql_template=f"""
WITH device_logins AS (
    SELECT
        account_id,
        COUNT_IF(new_device)                                AS new_device_logins,
        COUNT(*)                                            AS total_logins,
        COUNT_IF(NOT login_success)                         AS failed_logins,
        MAX(timestamp)                                      AS latest_login_at,
        ARRAY_JOIN(ARRAY_AGG(DISTINCT auth_method), ', ')   AS auth_methods
    FROM {CUSTOMER_EVENTS}
    WHERE event_type = 'CUSTOMER_LOGIN'
      AND timestamp >= current_timestamp - INTERVAL '{{hours}}' HOUR
    GROUP BY account_id
    HAVING COUNT_IF(new_device) > 0
)
SELECT
    c.customer_id,
    c.account_id,
    c.full_name,
    c.customer_tier,
    c.city,
    c.risk_rating,
    c.preferred_channel,
    d.new_device_logins,
    d.total_logins,
    d.failed_logins,
    d.latest_login_at,
    d.auth_methods
FROM {CUSTOMERS} c
JOIN device_logins d ON d.account_id = c.account_id
ORDER BY d.new_device_logins DESC, d.latest_login_at DESC
LIMIT {{limit}}
""",
    ),
    FederatedQuestion(
        name="fraud_by_customer_city",
        example="Which cities have the most fraud alerts?",
        description="Fraud alerts grouped by the customer's MySQL city of residence.",
        required=(("city", "cities", "province", "location", "region"),),
        boost=("fraud", "alerts", "most", "where"),
        excludes=(),
        mysql_columns=("customer_city", "province", "customers_affected"),
        iceberg_columns=(
            "fraud_alert_count",
            "avg_ml_score",
            "max_ml_score",
            "blocked_count",
        ),
        chart="bar",
        chart_x="customer_city",
        chart_y="fraud_alert_count",
        narrative="fraud alert volume by the customer's registered city",
        sql_template=f"""
SELECT
    c.city                              AS customer_city,
    c.province,
    COUNT(DISTINCT c.account_id)        AS customers_affected,
    COUNT(*)                            AS fraud_alert_count,
    ROUND(AVG(f.ml_score), 4)           AS avg_ml_score,
    MAX(f.ml_score)                     AS max_ml_score,
    COUNT_IF(f.action = 'BLOCK_AND_ALERT') AS blocked_count
FROM {CUSTOMERS} c
JOIN {FRAUD} f ON c.account_id = f.account_id
WHERE f.timestamp >= current_timestamp - INTERVAL '{{hours}}' HOUR
GROUP BY c.city, c.province
ORDER BY fraud_alert_count DESC
LIMIT {{limit}}
""",
    ),
    FederatedQuestion(
        name="high_risk_exposure",
        example="Show payment and fraud exposure for high-risk customers.",
        description="Payments and fraud pre-aggregated separately, then joined 1:1.",
        required=(("exposure", "payment and fraud", "fraud and payment"),),
        boost=("high risk", "high-risk", "pep", "customers", "total"),
        excludes=(),
        mysql_columns=(
            "customer_id",
            "account_id",
            "full_name",
            "customer_tier",
            "city",
            "risk_rating",
            "pep_flag",
            "kyc_status",
        ),
        iceberg_columns=(
            "fraud_alert_count",
            "max_fraud_score",
            "payment_count",
            "total_payment_amount",
            "international_payment_count",
            "most_recent_event_at",
        ),
        chart="bar",
        chart_x="full_name",
        chart_y="total_payment_amount",
        narrative="payment and fraud exposure for high-risk or PEP customers",
        sql_template=f"""
WITH payment_exposure AS (
    SELECT
        account_id,
        COUNT(*)                        AS payment_count,
        ROUND(SUM(amount), 2)           AS total_payment_amount,
        COUNT_IF(is_international)      AS international_payment_count,
        MAX(timestamp)                  AS latest_payment_at
    FROM {PAYMENTS}
    WHERE timestamp >= current_timestamp - INTERVAL '{{hours}}' HOUR
    GROUP BY account_id
),
fraud_exposure AS (
    SELECT
        account_id,
        COUNT(*)                        AS fraud_alert_count,
        MAX(ml_score)                   AS max_fraud_score,
        MAX(timestamp)                  AS latest_fraud_alert_at
    FROM {FRAUD}
    WHERE timestamp >= current_timestamp - INTERVAL '{{hours}}' HOUR
    GROUP BY account_id
)
SELECT
    c.customer_id,
    c.account_id,
    c.full_name,
    c.customer_tier,
    c.city,
    c.risk_rating,
    c.pep_flag,
    c.kyc_status,
    COALESCE(f.fraud_alert_count, 0)            AS fraud_alert_count,
    f.max_fraud_score,
    COALESCE(p.payment_count, 0)                AS payment_count,
    COALESCE(p.total_payment_amount, 0)         AS total_payment_amount,
    COALESCE(p.international_payment_count, 0)  AS international_payment_count,
    GREATEST(
        COALESCE(f.latest_fraud_alert_at, TIMESTAMP '1970-01-01 00:00:00 UTC'),
        COALESCE(p.latest_payment_at,     TIMESTAMP '1970-01-01 00:00:00 UTC')
    )                                           AS most_recent_event_at
FROM {CUSTOMERS} c
LEFT JOIN payment_exposure p ON p.account_id = c.account_id
LEFT JOIN fraud_exposure   f ON f.account_id = c.account_id
WHERE (c.risk_rating = 'HIGH' OR c.pep_flag = 1)
  AND (p.account_id IS NOT NULL OR f.account_id IS NOT NULL)
ORDER BY f.max_fraud_score DESC NULLS LAST, total_payment_amount DESC
LIMIT {{limit}}
""",
    ),
    FederatedQuestion(
        name="unmatched_events",
        example="How many banking events do not match a customer record?",
        description="Data-quality view of Iceberg accounts absent from MySQL.",
        required=(
            (
                "unmatched",
                "do not match",
                "dont match",
                "not match",
                "missing",
                "orphan",
                "no customer record",
                "data quality",
            ),
        ),
        boost=("events", "how many", "customer record", "banking"),
        excludes=(),
        mysql_columns=("matched_events",),
        iceberg_columns=(
            "iceberg_source",
            "total_events",
            "unmatched_events",
            "match_percentage",
        ),
        chart="bar",
        chart_x="iceberg_source",
        chart_y="unmatched_events",
        narrative="banking events whose account_id has no Customer 360 record",
        sql_template=f"""
SELECT
    'payment_transactions'                                          AS iceberg_source,
    COUNT(*)                                                        AS total_events,
    COUNT_IF(c.account_id IS NOT NULL)                              AS matched_events,
    COUNT_IF(c.account_id IS NULL)                                  AS unmatched_events,
    ROUND(100.0 * COUNT_IF(c.account_id IS NOT NULL) / COUNT(*), 2) AS match_percentage
FROM {PAYMENTS} p
LEFT JOIN {CUSTOMERS} c ON c.account_id = p.account_id
WHERE p.timestamp >= current_timestamp - INTERVAL '{{hours}}' HOUR
UNION ALL
SELECT
    'fraud_alerts',
    COUNT(*),
    COUNT_IF(c.account_id IS NOT NULL),
    COUNT_IF(c.account_id IS NULL),
    ROUND(100.0 * COUNT_IF(c.account_id IS NOT NULL) / COUNT(*), 2)
FROM {FRAUD} f
LEFT JOIN {CUSTOMERS} c ON c.account_id = f.account_id
WHERE f.timestamp >= current_timestamp - INTERVAL '{{hours}}' HOUR
UNION ALL
SELECT
    'customer_events',
    COUNT(*),
    COUNT_IF(c.account_id IS NOT NULL),
    COUNT_IF(c.account_id IS NULL),
    ROUND(100.0 * COUNT_IF(c.account_id IS NOT NULL) / COUNT(*), 2)
FROM {CUSTOMER_EVENTS} e
LEFT JOIN {CUSTOMERS} c ON c.account_id = e.account_id
WHERE e.timestamp >= current_timestamp - INTERVAL '{{hours}}' HOUR
ORDER BY iceberg_source
""",
    ),
    FederatedQuestion(
        name="customer_profile_lookup",
        example="Show the Customer 360 profile for account ACC-TH-10000001.",
        description="Single-customer 360 view: MySQL profile plus Iceberg activity.",
        required=(
            ("profile", "customer 360", "customer360", "account", "look up", "lookup"),
        ),
        boost=("show", "for account", "acc-th"),
        excludes=("unmatched", "highest", "platinum", "pep"),
        needs_account=True,
        mysql_columns=(
            "customer_id",
            "account_id",
            "full_name",
            "customer_tier",
            "city",
            "province",
            "risk_rating",
            "kyc_status",
            "pep_flag",
            "sanctions_screening_status",
            "preferred_channel",
            "account_open_date",
            "annual_income",
            "occupation",
            "age_group",
        ),
        iceberg_columns=(
            "payment_count",
            "total_payment_amount",
            "latest_payment_at",
            "fraud_alert_count",
            "max_fraud_score",
            "login_count",
            "new_device_logins",
            "aml_alert_count",
        ),
        narrative="the full Customer 360 profile for one account",
        sql_template=f"""
WITH pay AS (
    SELECT account_id, COUNT(*) AS payment_count,
           ROUND(SUM(amount), 2) AS total_payment_amount,
           MAX(timestamp) AS latest_payment_at
    FROM {PAYMENTS}
    WHERE account_id = '{{account_id}}'
      AND timestamp >= current_timestamp - INTERVAL '{{hours}}' HOUR
    GROUP BY account_id
),
fr AS (
    SELECT account_id, COUNT(*) AS fraud_alert_count, MAX(ml_score) AS max_fraud_score
    FROM {FRAUD}
    WHERE account_id = '{{account_id}}'
      AND timestamp >= current_timestamp - INTERVAL '{{hours}}' HOUR
    GROUP BY account_id
),
lg AS (
    SELECT account_id, COUNT(*) AS login_count, COUNT_IF(new_device) AS new_device_logins
    FROM {CUSTOMER_EVENTS}
    WHERE account_id = '{{account_id}}' AND event_type = 'CUSTOMER_LOGIN'
      AND timestamp >= current_timestamp - INTERVAL '{{hours}}' HOUR
    GROUP BY account_id
),
aml AS (
    SELECT account_id, COUNT(*) AS aml_alert_count
    FROM {AML}
    WHERE account_id = '{{account_id}}'
      AND timestamp >= current_timestamp - INTERVAL '{{hours}}' HOUR
    GROUP BY account_id
)
SELECT
    c.customer_id, c.account_id, c.full_name, c.customer_tier, c.city, c.province,
    c.risk_rating, c.kyc_status, c.pep_flag, c.sanctions_screening_status,
    c.preferred_channel, c.account_open_date, c.annual_income, c.occupation, c.age_group,
    COALESCE(pay.payment_count, 0)          AS payment_count,
    COALESCE(pay.total_payment_amount, 0)   AS total_payment_amount,
    pay.latest_payment_at,
    COALESCE(fr.fraud_alert_count, 0)       AS fraud_alert_count,
    fr.max_fraud_score,
    COALESCE(lg.login_count, 0)             AS login_count,
    COALESCE(lg.new_device_logins, 0)       AS new_device_logins,
    COALESCE(aml.aml_alert_count, 0)        AS aml_alert_count
FROM {CUSTOMERS} c
LEFT JOIN pay ON pay.account_id = c.account_id
LEFT JOIN fr  ON fr.account_id  = c.account_id
LEFT JOIN lg  ON lg.account_id  = c.account_id
LEFT JOIN aml ON aml.account_id = c.account_id
WHERE c.account_id = '{{account_id}}'
LIMIT {{limit}}
""",
    ),
)

FEDERATED_BY_NAME = {q.name: q for q in FEDERATED_QUESTIONS}
FEDERATED_SUGGESTIONS = tuple(q.example for q in FEDERATED_QUESTIONS)


@dataclass
class FederatedMatch:
    """Explainable outcome of federated intent matching."""

    question: FederatedQuestion
    score: int
    matched_terms: list[str] = field(default_factory=list)
    runners_up: list[tuple[str, int]] = field(default_factory=list)

    @property
    def explanation(self) -> str:
        terms = ", ".join(f"'{t}'" for t in self.matched_terms) or "no keywords"
        return (
            f"Matched federated intent '{self.question.name}' (score {self.score}) on {terms}. "
            "Starburst executes the join across both catalogs."
        )


def _matches(text: str, term: str) -> bool:
    if " " in term or "-" in term or "_" in term:
        return term in text
    return re.search(rf"(?:^|\s){re.escape(term)}(?:$|\s)", text) is not None


def match_federated_question(question: str) -> FederatedMatch:
    """Map free text to exactly one allowlisted federated question."""
    from fraud_queries import _DESTRUCTIVE_HINTS

    text = normalize_question(question)
    if not text:
        raise UnsupportedQuestionError(
            "Please enter a question.", FEDERATED_SUGGESTIONS
        )

    # Refuse anything that is already SQL. Catalog and table names appear in the
    # question keywords, so a pasted statement could otherwise score a match.
    # Note "show" alone is NOT a SQL marker here - most supported questions
    # legitimately begin with "Show ..." - so only SHOW <object> forms count.
    if re.match(
        r"^\s*(?:select|with|explain|describe|desc|values|insert|update|delete|merge)\b"
        r"|^\s*show\s+(?:catalogs|schemas|tables|columns|create|stats)\b",
        question or "",
        re.IGNORECASE,
    ):
        raise UnsupportedQuestionError(
            "This application does not execute SQL supplied by the user. Ask a question "
            "in plain language instead - the federated SQL is generated from a fixed, "
            "reviewed template.",
            FEDERATED_SUGGESTIONS,
        )

    for hint in _DESTRUCTIVE_HINTS:
        if hint.strip() in text.split() or hint in text:
            raise UnsupportedQuestionError(
                "This request looks like it is trying to modify data. The federated "
                "page is strictly read-only and never executes user-supplied SQL.",
                FEDERATED_SUGGESTIONS,
            )

    scored: list[tuple[int, int, FederatedQuestion, list[str]]] = []
    for candidate in FEDERATED_QUESTIONS:
        if any(_matches(text, term) for term in candidate.excludes):
            continue
        matched: list[str] = []
        satisfied = True
        for group in candidate.required:
            hit = next((term for term in group if _matches(text, term)), None)
            if hit is None:
                satisfied = False
                break
            matched.append(hit)
        if not satisfied:
            continue
        score = 10 * len(matched)
        for term in candidate.boost:
            if _matches(text, term):
                score += 3
                matched.append(term)
        # An explicit ACC-TH-######## is a very strong signal for the lookup.
        if candidate.needs_account and ACCOUNT_IN_TEXT_RE.search(question or ""):
            score += 12
            matched.append("an ACC-TH account id")
        scored.append((score, len(candidate.required), candidate, matched))

    if not scored:
        raise UnsupportedQuestionError(
            "That federated question is not supported yet. The Customer 360 page uses "
            "an explainable keyword matcher over a fixed set of cross-catalog questions.",
            FEDERATED_SUGGESTIONS,
        )

    scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
    best = scored[0]
    return FederatedMatch(
        question=best[2],
        score=best[0],
        matched_terms=best[3],
        runners_up=[(s[2].name, s[0]) for s in scored[1:4]],
    )


def build_federated_sql(
    question_text: str,
    hours: int | None = None,
    limit: int | None = None,
    score: float | None = None,
) -> tuple[FederatedMatch, str]:
    """Match a question and render its validated, read-only federated SQL."""
    match = match_federated_question(question_text)
    account_id = (
        canonical_account_id(question_text) if match.question.needs_account else None
    )
    sql = match.question.render(
        hours=hours, limit=limit, score=score, account_id=account_id
    )
    return match, sql


def summarize_federated(question: FederatedQuestion, rows: list[dict]) -> str:
    """Plain-language interpretation that names both catalogs explicitly."""
    if not rows:
        return (
            f"No rows matched: there are currently no {question.narrative}. "
            "Widen the time range in the sidebar, or check that the Kafka generator "
            "and Spark streaming jobs are running."
        )
    lead = rows[0]
    parts = [
        f"{len(rows)} row(s) returned for {question.narrative}.",
        "Starburst performed this join across two catalogs: customer attributes "
        f"({', '.join(question.mysql_columns[:3])}...) were read from MySQL "
        f"({MYSQL_CATALOG}), and the transaction/alert attributes "
        f"({', '.join(question.iceberg_columns[:3])}...) from Iceberg "
        f"({ICEBERG_CATALOG}). No data was copied between them.",
    ]
    if question.chart_y and question.chart_y in lead:
        value = lead.get(question.chart_y)
        label = lead.get(question.chart_x) if question.chart_x in lead else None
        if isinstance(value, (int, float)):
            parts.insert(
                1, f"Top result: {label} with {question.chart_y}={value:,.2f}."
            )
    return " ".join(parts)
