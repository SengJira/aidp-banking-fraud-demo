"""Unit tests for intent matching, query safety and credential hygiene.

These tests are fully offline: no AIDP connection is required.
"""

from __future__ import annotations

import io
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fraud_queries as fq
from aidp_connection import (
    REDACTED,
    AidpConfigError,
    Secret,
    SecretRedactingFilter,
    classify_error,
    load_config,
)
from schema_inspector import (
    EXPECTED_COLUMNS,
    SchemaValidationError,
    assert_allowlisted,
    qualified_name,
    quote_identifier,
)

CATALOG = "js_financial_ice"
SCHEMA = "banking"

SUPPORTED = [
    ("How many fraud alerts occurred in the last hour?", "fraud_count_last_hour"),
    ("Show fraud alerts by fraud type.", "fraud_by_type"),
    ("Show fraud alerts by action.", "fraud_by_action"),
    ("Which accounts have the highest fraud scores?", "top_accounts_by_score"),
    ("Show the latest high-risk fraud alerts.", "latest_high_risk"),
    ("What is the average fraud score by fraud type?", "avg_score_by_type"),
    (
        "How many alerts were blocked, flagged for review, or required step-up authentication?",
        "action_outcome_counts",
    ),
    ("Show fraud trends by hour.", "fraud_trend_by_hour"),
    ("Show the ten most recent fraud alerts.", "recent_fraud_alerts"),
    ("How many AML alerts exist by risk band?", "aml_by_risk_band"),
    ("Show successful and failed customer logins.", "login_outcomes"),
    ("How many customer logins used a new device?", "new_device_logins"),
]


# --------------------------------------------------------------------------- #
# Intent matching
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("question,expected", SUPPORTED)
def test_supported_questions_map_to_expected_intent(question, expected):
    match = fq.match_intent(question)
    assert match.intent.name == expected, (
        f"{question!r} -> {match.intent.name} (runners up: {match.runners_up})"
    )


@pytest.mark.parametrize("question,expected", SUPPORTED)
def test_intent_examples_are_self_consistent(question, expected):
    """Every registered example must match its own intent."""
    assert fq.match_intent(fq.INTENTS_BY_NAME[expected].example).intent.name == expected


def test_all_registered_intents_are_covered_by_tests():
    assert {name for _, name in SUPPORTED} == set(fq.INTENTS_BY_NAME)


@pytest.mark.parametrize(
    "question",
    [
        "",
        "   ",
        "what is the weather in bangkok",
        "who is the ceo",
        "tell me a joke",
        "SELECT * FROM js_financial_ice.banking.fraud_alerts",
        "show me the customer email addresses",
    ],
)
def test_unsupported_questions_are_rejected(question):
    with pytest.raises(fq.UnsupportedQuestionError):
        fq.match_intent(question)


def test_rejection_offers_suggestions():
    with pytest.raises(fq.UnsupportedQuestionError) as excinfo:
        fq.match_intent("what is the meaning of life")
    assert len(excinfo.value.suggestions) == len(fq.INTENTS)


@pytest.mark.parametrize(
    "question",
    [
        "drop table js_financial_ice.banking.fraud_alerts",
        "DELETE FROM fraud_alerts WHERE 1=1",
        "truncate table fraud_alerts",
        "insert into fraud_alerts values (1)",
        "update fraud_alerts set ml_score = 0",
        "grant all on banking to public",
        "show fraud alerts by fraud type; drop table fraud_alerts",
    ],
)
def test_destructive_requests_are_rejected(question):
    with pytest.raises(fq.UnsupportedQuestionError) as excinfo:
        fq.match_intent(question)
    assert "read-only" in str(excinfo.value).lower() or excinfo.value.suggestions


def test_match_result_is_explainable():
    match = fq.match_intent("Show fraud trends by hour.")
    assert match.matched_terms
    assert "fraud_trend_by_hour" in match.explanation


# --------------------------------------------------------------------------- #
# Generated SQL safety
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("question,expected", SUPPORTED)
def test_generated_sql_is_read_only_select(question, expected):
    _, plan = fq.build_plan(question)
    sql = fq.render_sql(plan, CATALOG, SCHEMA)
    assert sql.lstrip().lower().startswith("select")
    assert ";" not in sql
    assert "--" not in sql and "/*" not in sql
    # assert_read_only is the authoritative gate and raises on any DML/DDL keyword.
    fq.assert_read_only(sql)


@pytest.mark.parametrize(
    "statement",
    [
        "DROP TABLE x",
        "DELETE FROM x",
        "SELECT 1; DROP TABLE x",
        "SELECT 1 -- comment",
        "SELECT 1 /* comment */",
        "INSERT INTO x VALUES (1)",
        "UPDATE x SET y = 1",
        "CREATE TABLE y AS SELECT 1",
        "GRANT SELECT ON x TO y",
        "CALL system.runtime.kill_query('x')",
    ],
)
def test_assert_read_only_rejects_dangerous_statements(statement):
    with pytest.raises(fq.UnsafeQueryError):
        fq.assert_read_only(statement)


def test_generated_sql_uses_fully_qualified_quoted_names():
    _, plan = fq.build_plan("Show fraud alerts by fraud type.")
    sql = fq.render_sql(plan, CATALOG, SCHEMA)
    assert '"js_financial_ice"."banking"."fraud_alerts"' in sql


def test_last_hour_uses_the_required_interval_predicate():
    _, plan = fq.build_plan("How many fraud alerts occurred in the last hour?")
    sql = fq.render_sql(plan, CATALOG, SCHEMA)
    assert "\"timestamp\" >= current_timestamp - INTERVAL '1' HOUR" in sql
    # The "last hour" question ignores the sidebar time range by design.
    plan_wide = fq.build_plan_for_intent("fraud_count_last_hour", hours=72)
    assert plan_wide.filters[0].value == 1


def test_recent_alerts_order_by_timestamp_desc_with_limit():
    _, plan = fq.build_plan("Show the ten most recent fraud alerts.")
    assert plan.order_by == (("timestamp", "desc"),)
    assert plan.limit == 10
    sql = fq.render_sql(plan, CATALOG, SCHEMA)
    assert 'ORDER BY "timestamp" DESC' in sql
    assert "LIMIT 10" in sql


def test_high_risk_default_threshold_is_085():
    _, plan = fq.build_plan("Show the latest high-risk fraud alerts.")
    score_filter = next(f for f in plan.filters if f.column == "ml_score")
    assert score_filter.op == "gte"
    assert score_filter.value == 0.85
    assert '"ml_score" >= 0.85' in fq.render_sql(plan, CATALOG, SCHEMA)


def test_detail_queries_always_carry_a_limit():
    for question, _ in SUPPORTED:
        _, plan = fq.build_plan(question)
        if plan.kind == "scalar":
            continue
        assert f"LIMIT {plan.limit}" in fq.render_sql(plan, CATALOG, SCHEMA)


# --------------------------------------------------------------------------- #
# Threshold and limit validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "value,expected", [(None, 0.85), (0.0, 0.0), (1.0, 1.0), ("0.5", 0.5)]
)
def test_valid_score_thresholds(value, expected):
    assert fq.validate_score_threshold(value) == expected


@pytest.mark.parametrize(
    "value", [-0.1, 1.1, 2, 100, "high", float("nan"), float("inf")]
)
def test_invalid_score_thresholds_rejected(value):
    with pytest.raises(ValueError):
        fq.validate_score_threshold(value)


@pytest.mark.parametrize(
    "value,expected", [(None, 100), (1, 1), (500, 500), (1000, 1000)]
)
def test_valid_limits(value, expected):
    assert fq.validate_limit(value) == expected


@pytest.mark.parametrize("value", [0, -1, 1001, 10_000, 1e9, "all", "many", 3.5e3])
def test_limits_cannot_exceed_1000(value):
    with pytest.raises(ValueError):
        fq.validate_limit(value)


def test_plan_limit_cannot_be_forced_above_max():
    with pytest.raises(ValueError):
        fq.build_plan_for_intent("fraud_by_type", limit=5000)


def test_query_plan_rejects_oversized_limit_directly():
    with pytest.raises(ValueError):
        fq.QueryPlan(
            intent="x",
            table="fraud_alerts",
            kind="detail",
            select=("event_id",),
            limit=fq.MAX_LIMIT + 1,
        )


@pytest.mark.parametrize("value", [0, -5, fq.MAX_TIME_RANGE_HOURS + 1, "yesterday"])
def test_invalid_time_ranges_rejected(value):
    with pytest.raises(ValueError):
        fq.validate_hours(value)


# --------------------------------------------------------------------------- #
# Allowlists
# --------------------------------------------------------------------------- #
def test_every_intent_reads_only_allowlisted_tables():
    assert set(fq.table_allowlist()) <= set(EXPECTED_COLUMNS)


@pytest.mark.parametrize("question,_expected", SUPPORTED)
def test_plans_only_reference_allowlisted_columns(question, _expected):
    _, plan = fq.build_plan(question)
    referenced = (
        list(plan.select)
        + [f.column for f in plan.filters]
        + [g.column for g in plan.group_by]
        + [a.column for a in plan.aggregates if a.column]
    )
    assert referenced, "plan references no columns"
    assert_allowlisted(plan.table, referenced)


def test_unknown_table_is_rejected():
    with pytest.raises(SchemaValidationError):
        qualified_name(CATALOG, SCHEMA, "information_schema.tables")
    with pytest.raises(SchemaValidationError):
        assert_allowlisted("system_tables", ["x"])


def test_unknown_column_is_rejected():
    with pytest.raises(SchemaValidationError):
        assert_allowlisted("fraud_alerts", ["ssn"])
    with pytest.raises(SchemaValidationError):
        fq.QueryPlan(
            intent="x", table="fraud_alerts", kind="detail", select=("password_hash",)
        )


@pytest.mark.parametrize(
    "identifier",
    ["fraud_alerts; drop table x", 'a"b', "a b", "", "tbl--x", "x'y", "*"],
)
def test_unsafe_identifiers_are_rejected(identifier):
    with pytest.raises(SchemaValidationError):
        quote_identifier(identifier)


def test_literals_must_be_allowlisted():
    fq.Filter("action", "eq", "BLOCK_AND_ALERT")
    with pytest.raises(ValueError):
        fq.Filter("action", "eq", "BLOCK_AND_ALERT'; DROP TABLE x --")
    with pytest.raises(ValueError):
        fq.Filter("event_type", "eq", "ANYTHING_ELSE")


def test_unsupported_filter_and_aggregate_shapes_rejected():
    with pytest.raises(ValueError):
        fq.Filter("ml_score", "regex", ".*")
    with pytest.raises(ValueError):
        fq.Aggregate("array_agg", "leak", "account_id")
    with pytest.raises(ValueError):
        fq.Aggregate("avg", 'alias" , (select 1) as "x', "ml_score")
    with pytest.raises(ValueError):
        fq.GroupKey("timestamp", "century")


def test_order_by_must_reference_the_projection():
    with pytest.raises(ValueError):
        fq.QueryPlan(
            intent="x",
            table="fraud_alerts",
            kind="detail",
            select=("event_id",),
            order_by=(("ml_score", "desc"),),
        )


# --------------------------------------------------------------------------- #
# Summaries
# --------------------------------------------------------------------------- #
def test_summarize_handles_empty_results():
    _, plan = fq.build_plan("Show fraud alerts by fraud type.")
    text = fq.summarize(plan, [])
    assert "No rows matched" in text


def test_summarize_scalar_and_aggregation():
    _, scalar_plan = fq.build_plan("How many fraud alerts occurred in the last hour?")
    assert "42" in fq.summarize(scalar_plan, [{"alert_count": 42}])

    _, agg_plan = fq.build_plan("Show fraud alerts by fraud type.")
    text = fq.summarize(
        agg_plan,
        [
            {"fraud_type": "CARD_TESTING", "alert_count": 30},
            {"fraud_type": "ATO", "alert_count": 10},
        ],
    )
    assert "CARD_TESTING" in text and "40" in text


# --------------------------------------------------------------------------- #
# Credential hygiene
# --------------------------------------------------------------------------- #
#: A synthetic value used only to prove redaction works. Not a real credential.
SECRET = "FAKE-TEST-CREDENTIAL-do-not-use-abc123"


def test_secret_never_renders_its_value():
    secret = Secret(SECRET)
    assert SECRET not in repr(secret)
    assert SECRET not in str(secret)
    assert SECRET not in f"{secret}"
    assert SECRET not in f"{secret!r}"
    assert SECRET not in "{}".format(secret)  # noqa: UP032
    assert secret.reveal() == SECRET


def test_config_repr_and_str_do_not_leak_the_password(monkeypatch):
    monkeypatch.setenv("AIDP_ENDPOINT", "https://ddae.lab9bgp.com/")
    monkeypatch.setenv("AIDP_USERNAME", "jirawut")
    monkeypatch.setenv("AIDP_PASSWORD", SECRET)
    monkeypatch.setenv("AIDP_CATALOG", CATALOG)
    monkeypatch.setenv("AIDP_SCHEMA", SCHEMA)
    monkeypatch.setenv("AIDP_VERIFY_TLS", "true")

    config = load_config(load_dotenv_file=False)
    assert SECRET not in repr(config)
    assert SECRET not in str(config)
    assert SECRET not in config.safe_target
    assert config.password.reveal() == SECRET
    assert config.source == "aidp-fraud-demo"
    assert (config.host, config.port) == ("ddae.lab9bgp.com", 443)


def test_credentials_never_appear_in_logs(monkeypatch):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("aidp.test.redaction")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    logger.addFilter(SecretRedactingFilter(SECRET))

    logger.info("connecting with password=%s", SECRET)
    logger.info(f"inline {SECRET} leak")
    try:
        raise RuntimeError(f"auth failed for token {SECRET}")
    except RuntimeError:
        logger.exception("boom")
    handler.flush()

    output = stream.getvalue()
    assert SECRET not in output
    assert REDACTED in output


def test_missing_password_raises_before_any_connection(monkeypatch):
    monkeypatch.setenv("AIDP_ENDPOINT", "https://ddae.lab9bgp.com/")
    monkeypatch.setenv("AIDP_USERNAME", "jirawut")
    monkeypatch.setenv("AIDP_CATALOG", CATALOG)
    monkeypatch.setenv("AIDP_SCHEMA", SCHEMA)
    monkeypatch.delenv("AIDP_PASSWORD", raising=False)
    with pytest.raises(AidpConfigError, match="AIDP_PASSWORD"):
        load_config(load_dotenv_file=False)


def test_plain_http_and_embedded_credentials_are_refused(monkeypatch):
    for name, value in (
        ("AIDP_USERNAME", "jirawut"),
        ("AIDP_PASSWORD", SECRET),
        ("AIDP_CATALOG", CATALOG),
        ("AIDP_SCHEMA", SCHEMA),
    ):
        monkeypatch.setenv(name, value)

    monkeypatch.setenv("AIDP_ENDPOINT", "http://ddae.lab9bgp.com/")
    with pytest.raises(AidpConfigError, match="https"):
        load_config(load_dotenv_file=False)

    monkeypatch.setenv("AIDP_ENDPOINT", "https://user:pw@ddae.lab9bgp.com/")
    with pytest.raises(AidpConfigError, match="must not embed credentials"):
        load_config(load_dotenv_file=False)


def test_tls_verification_defaults_to_enabled(monkeypatch):
    for name, value in (
        ("AIDP_ENDPOINT", "https://ddae.lab9bgp.com/"),
        ("AIDP_USERNAME", "jirawut"),
        ("AIDP_PASSWORD", SECRET),
        ("AIDP_CATALOG", CATALOG),
        ("AIDP_SCHEMA", SCHEMA),
    ):
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("AIDP_VERIFY_TLS", raising=False)
    assert load_config(load_dotenv_file=False).verify_tls is True

    monkeypatch.setenv("AIDP_VERIFY_TLS", "false")
    assert load_config(load_dotenv_file=False).verify_tls is False


# --------------------------------------------------------------------------- #
# Error classification
# --------------------------------------------------------------------------- #
def test_error_classification_covers_expected_failure_modes():
    import socket

    import requests.exceptions as rex

    cases = {
        "tls": rex.SSLError("certificate verify failed"),
        "timeout": rex.ConnectTimeout("timed out"),
        "network": rex.ConnectionError("connection refused"),
        "dns": socket.gaierror("Name or service not known"),
        "missing_object": RuntimeError("Schema 'banking' does not exist"),
        "authz": RuntimeError("Access Denied: Cannot select from table"),
    }
    for kind, exc in cases.items():
        assert classify_error(exc).kind == kind, f"{exc!r} misclassified"

    class Http401(Exception):
        status_code = 401

    class Http403(Exception):
        status_code = 403

    assert classify_error(Http401("nope")).kind == "auth"
    assert classify_error(Http403("nope")).kind == "authz"


def test_keycloak_password_rejection_is_classified_as_auth():
    """The coordinator wraps a rejected password in an HTTP 500 + Java stack trace.

    Verified against the live ddae.lab9bgp.com coordinator.
    """
    raw = (
        "error 500: b'java.lang.RuntimeException: Authentication error\\n\\tat "
        "io.trino.server.security.PasswordAuthenticator.authenticate(PasswordAuthenticator.java:101)"
        "\\n\\tat io.trino.plugin.password.keycloak.KeycloakAuthenticator..."
    )
    err = classify_error(RuntimeError(raw))
    assert err.kind == "auth"
    assert "Keycloak" in err.message
    assert "\n" not in err.message


def test_server_errors_are_summarized_not_dumped():
    stack = "io.trino.SomeError: Schema 'nope' does not exist\n" + "\n".join(
        f"\tat com.example.Frame{i}(File.java:{i})" for i in range(200)
    )
    err = classify_error(RuntimeError(stack))
    assert err.kind == "missing_object"
    assert len(err.message) < 400
    assert "at com.example" not in err.message


# --------------------------------------------------------------------------- #
# PyStarburst DataFrame-API fallback detection
# --------------------------------------------------------------------------- #
def test_dataframe_api_unavailability_is_detected():
    assert fq.is_dataframe_api_unavailable(
        RuntimeError("404 Not Found /v1/dataframe/plan")
    )
    assert fq.is_dataframe_api_unavailable(
        RuntimeError("Unknown table function: system.dataframe")
    )


def test_genuine_query_errors_do_not_trigger_the_fallback():
    assert not fq.is_dataframe_api_unavailable(
        RuntimeError("Access Denied on fraud_alerts")
    )
    assert not fq.is_dataframe_api_unavailable(RuntimeError("division by zero"))


def test_fallback_executor_only_runs_read_only_sql():
    """The fallback re-validates the statement and binds no user text."""
    executed = []

    class FakeCursor:
        description = [("fraud_type",), ("alert_count",)]

        def execute(self, sql, *args):
            executed.append((sql, args))

        def fetchall(self):
            return [("CARD_TESTING", 7)]

    class FakeConnection:
        def cursor(self):
            return FakeCursor()

    _, plan = fq.build_plan("Show fraud alerts by fraud type.")
    columns, rows = fq.execute_plan_sql(FakeConnection(), plan, CATALOG, SCHEMA)
    assert columns == ["fraud_type", "alert_count"]
    assert rows == [("CARD_TESTING", 7)]
    sql, args = executed[0]
    assert args == (), "no parameters should be bound: the SQL contains no user text"
    fq.assert_read_only(sql)
    assert sql.lower().startswith("select")


# --------------------------------------------------------------------------- #
# compile_plan: PyStarburst DataFrame construction (offline, recorded calls)
# --------------------------------------------------------------------------- #
class RecordingDataFrame:
    """Records the DataFrame calls compile_plan makes, without a server."""

    def __init__(self, calls):
        self.calls = calls

    def _record(self, name, *args):
        self.calls.append((name, args))
        return self

    def filter(self, *a):
        return self._record("filter", *a)

    def select(self, *a):
        return self._record("select", *a)

    def sort(self, *a):
        return self._record("sort", *a)

    def limit(self, *a):
        return self._record("limit", *a)

    def agg(self, *a):
        return self._record("agg", *a)

    def group_by(self, *a):
        return self._record("group_by", *a)


class RecordingSession:
    def __init__(self):
        self.calls = []
        self.table_args = None

    def table(self, name):
        self.table_args = name
        return RecordingDataFrame(self.calls)


def _compile(question, **params):
    session = RecordingSession()
    _, plan = fq.build_plan(question, **params) if params else fq.build_plan(question)
    fq.compile_plan(session, plan, CATALOG, SCHEMA)
    return session, plan


def test_compile_plan_uses_fully_qualified_table_reference():
    session, _ = _compile("Show fraud alerts by fraud type.")
    assert session.table_args == [CATALOG, SCHEMA, "fraud_alerts"]


def test_compile_plan_issues_exactly_one_sort_for_multiple_keys():
    """Regression: successive sort() calls each *replace* the previous ordering,
    so a two-key ORDER BY silently degraded to the last key only."""
    session, plan = _compile("Which accounts have the highest fraud scores?")
    assert len(plan.order_by) == 2
    sorts = [c for c in session.calls if c[0] == "sort"]
    assert len(sorts) == 1, "multiple sort() calls would drop all but the last key"
    assert len(sorts[0][1]) == 2, "both sort keys must be in the single sort() call"


@pytest.mark.parametrize("question,expected", SUPPORTED)
def test_compile_plan_builds_every_intent(question, expected):
    session, plan = _compile(question)
    names = [c[0] for c in session.calls]
    assert len(session.calls) >= 1
    assert names.count("sort") <= 1
    if plan.kind == "scalar":
        assert "limit" not in names, "scalar aggregates need no LIMIT"
        assert "group_by" not in names
    else:
        assert names[-1] == "limit", "the row limit must be applied last"
    if plan.group_by:
        assert "group_by" in names and "agg" in names
    for flt in plan.filters:
        assert "filter" in names, f"filter on {flt.column} was not applied"


# --------------------------------------------------------------------------- #
# Streamlit UI smoke tests (offline: these fail before any network call)
# --------------------------------------------------------------------------- #
APP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "fraud_analytics_app.py",
)


def _run_app(monkeypatch, env):
    from streamlit.testing.v1 import AppTest

    for name in [k for k in os.environ if k.startswith("AIDP_")]:
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return AppTest.from_file(APP, default_timeout=60).run()


def test_app_reports_missing_password_without_crashing(monkeypatch):
    app = _run_app(
        monkeypatch,
        {
            "AIDP_ENDPOINT": "https://ddae.lab9bgp.com/",
            "AIDP_USERNAME": "jirawut",
            "AIDP_CATALOG": CATALOG,
            "AIDP_SCHEMA": SCHEMA,
        },
    )
    assert not app.exception
    assert app.title[0].value == "AIDP Real-Time Banking Fraud Analytics"
    assert any("AIDP_PASSWORD is not set" in e.value for e in app.error)


def test_app_refuses_plain_http_endpoint(monkeypatch):
    app = _run_app(
        monkeypatch,
        {
            "AIDP_ENDPOINT": "http://ddae.lab9bgp.com/",
            "AIDP_USERNAME": "jirawut",
            "AIDP_PASSWORD": SECRET,
            "AIDP_CATALOG": CATALOG,
            "AIDP_SCHEMA": SCHEMA,
        },
    )
    assert not app.exception
    assert any("must use https" in e.value for e in app.error)
    assert all(SECRET not in e.value for e in app.error)


def test_log_redaction_preserves_non_string_arg_types():
    """Regression: stringifying every arg broke %d/%f format specifiers."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("aidp.test.redaction.types")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    logger.addFilter(SecretRedactingFilter(SECRET))

    logger.info("rebuilt %d models in %.2fs", 53, 1.5)
    logger.info("user=%s password=%s", "jirawut", SECRET)
    handler.flush()

    output = stream.getvalue()
    assert "rebuilt 53 models in 1.50s" in output
    assert SECRET not in output
    assert "password=" + REDACTED in output
