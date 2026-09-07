"""Unit tests for the federated Customer 360 demo.

Offline by default. The MySQL integration tests skip automatically when no
local MySQL is reachable, and never fabricate a pass.
"""

from __future__ import annotations

import csv
import io
import logging
import re
import sys
from datetime import date
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import federated_queries as fed  # noqa: E402
import fraud_queries as fq  # noqa: E402
from aidp_connection import REDACTED, Secret, SecretRedactingFilter  # noqa: E402
from generators import Streaming_gen as gen  # noqa: E402
from mysql_connection import MySQLConfigError, load_mysql_config  # noqa: E402
from scripts import generate_customer360 as g360  # noqa: E402
from scripts import load_customer360 as loader  # noqa: E402

AS_OF = date(2026, 1, 15)


# --------------------------------------------------------------------------- #
# Deterministic customer generation
# --------------------------------------------------------------------------- #
def test_generation_is_deterministic_for_a_given_seed():
    a = g360.generate_customers(500, seed=42, today=AS_OF)
    b = g360.generate_customers(500, seed=42, today=AS_OF)
    assert [c.__dict__ for c in a] == [c.__dict__ for c in b]


def test_different_seeds_produce_different_data():
    a = g360.generate_customers(500, seed=42, today=AS_OF)
    b = g360.generate_customers(500, seed=43, today=AS_OF)
    assert [c.full_name for c in a] != [c.full_name for c in b]
    # ...but the account pool is seed-independent by design: it is the join key.
    assert [c.account_id for c in a] == [c.account_id for c in b]


def test_generation_does_not_disturb_the_global_rng():
    import random

    random.seed(1234)
    expected = [random.random() for _ in range(3)]
    random.seed(1234)
    g360.generate_customers(50, seed=99, today=AS_OF)
    assert [random.random() for _ in range(3)] == expected


def test_customer_count_is_validated():
    with pytest.raises(ValueError):
        g360.generate_customers(0, seed=42, today=AS_OF)


# --------------------------------------------------------------------------- #
# Unique customer and account IDs
# --------------------------------------------------------------------------- #
def test_customer_and_account_ids_are_unique_and_well_formed():
    customers = g360.generate_customers(2000, seed=42, today=AS_OF)
    account_ids = [c.account_id for c in customers]
    customer_ids = [c.customer_id for c in customers]

    assert len(set(account_ids)) == len(account_ids)
    assert len(set(customer_ids)) == len(customer_ids)
    assert all(fed.ACCOUNT_ID_RE.match(a) for a in account_ids)


def test_account_ids_are_contiguous_from_the_documented_base():
    customers = g360.generate_customers(100, seed=42, today=AS_OF)
    assert customers[0].account_id == "ACC-TH-10000001"
    assert customers[-1].account_id == "ACC-TH-10000100"
    numbers = [int(c.account_id.rsplit("-", 1)[1]) for c in customers]
    assert numbers == list(range(10_000_001, 10_000_101))


# --------------------------------------------------------------------------- #
# Distributions
# --------------------------------------------------------------------------- #
def test_customer_distributions_are_realistic():
    customers = g360.generate_customers(10_000, seed=42, today=AS_OF)
    summary = g360.summarize(customers)
    total = len(customers)

    def share(attribute, value):
        return summary[attribute].get(value, 0) / total

    assert set(summary["customer_tier"]) == {"STANDARD", "SILVER", "GOLD", "PLATINUM"}
    assert 0.30 <= share("customer_tier", "STANDARD") <= 0.40
    assert 0.02 <= share("customer_tier", "PLATINUM") <= 0.08

    assert set(summary["risk_rating"]) == {"LOW", "MEDIUM", "HIGH"}
    assert 0.02 <= share("risk_rating", "HIGH") <= 0.09

    assert set(summary["kyc_status"]) == {"VERIFIED", "PENDING", "EXPIRED"}
    assert 0.80 <= share("kyc_status", "VERIFIED") <= 0.90

    assert set(summary["city"]) == {
        "Bangkok",
        "Chiang Mai",
        "Pattaya",
        "Phuket",
        "Khon Kaen",
    }
    assert 0.50 <= share("city", "Bangkok") <= 0.60

    pep = summary["pep_flag"]["PEP"] / total
    assert 0.01 <= pep <= 0.04, f"PEP share {pep:.3f} outside the expected ~2%"
    # Every age bucket must be represented, and none may dominate.
    assert len(summary["age_group"]) == 6
    assert max(summary["age_group"].values()) / total < 0.30


# --------------------------------------------------------------------------- #
# Masked / synthetic PII
# --------------------------------------------------------------------------- #
def test_pii_is_masked_and_clearly_synthetic():
    customers = g360.generate_customers(1000, seed=42, today=AS_OF)
    for customer in customers:
        # National ID: only a single trailing check digit is ever exposed.
        assert re.fullmatch(r"X-XXXX-XXXXX-XX-\d", customer.national_id_masked)
        # Phone: no real subscriber digits.
        assert re.fullmatch(r"\+66-XX-XXX-\d{4}", customer.mobile_number_masked)
        # .invalid is reserved by RFC 6761 and can never resolve to a real inbox.
        assert customer.email.endswith("@example.invalid")
        assert customer.customer_id.startswith("CUST-DEMO-")


def test_no_real_looking_thai_national_id_is_emitted():
    """A real Thai national ID is 13 digits; nothing here may look like one."""
    customers = g360.generate_customers(1000, seed=42, today=AS_OF)
    for customer in customers:
        digits = re.sub(r"\D", "", customer.national_id_masked)
        assert len(digits) < 13, (
            f"{customer.national_id_masked} resembles a real national ID"
        )


def test_names_are_drawn_from_the_fixed_synthetic_word_lists():
    customers = g360.generate_customers(1000, seed=42, today=AS_OF)
    for customer in customers:
        given, family = customer.full_name.split(" ", 1)
        assert given in g360.GIVEN_NAMES
        assert family in g360.FAMILY_NAMES
    # With ~40x40 combinations over 1000 rows, repeats prove it is generated.
    assert len({c.full_name for c in customers}) < 1000


def test_csv_outputs_have_the_expected_columns(tmp_path):
    customers = g360.generate_customers(20, seed=42, today=AS_OF)
    full = tmp_path / "customer360.csv"
    pool = tmp_path / "customer_accounts.csv"
    g360.write_customer_csv(customers, full)
    g360.write_account_pool_csv(customers, pool)

    with full.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 20
    assert tuple(rows[0]) == g360.CUSTOMER_COLUMNS

    with pool.open(newline="", encoding="utf-8") as handle:
        pool_rows = list(csv.DictReader(handle))
    assert tuple(pool_rows[0]) == g360.ACCOUNT_POOL_COLUMNS
    assert pool_rows[0]["account_id"] == "ACC-TH-10000001"


# --------------------------------------------------------------------------- #
# Kafka generator: pool usage and unmatched percentage
# --------------------------------------------------------------------------- #
@pytest.fixture
def pool_file(tmp_path):
    customers = g360.generate_customers(500, seed=42, today=AS_OF)
    path = tmp_path / "customer_accounts.csv"
    g360.write_account_pool_csv(customers, path)
    return path


def test_generator_events_use_customer_pool_account_ids(pool_file):
    import random

    customers = gen.load_customer_pool(pool_file)
    known = {c.account_id for c in customers}
    pool = gen.CustomerPool(customers, random.Random(7), unknown_rate=0.0)

    for gen_fn in (gen.gen_payment, gen.gen_fraud_signal, gen.gen_customer_event):
        for _ in range(300):
            event, account_id, is_known = gen_fn(pool, random.Random(7))
            assert is_known
            assert account_id in known
            assert event["account_id"] == account_id


def test_payment_events_stay_consistent_with_the_customer_record(pool_file):
    import random

    customers = gen.load_customer_pool(pool_file)
    by_account = {c.account_id: c for c in customers}
    pool = gen.CustomerPool(customers, random.Random(3), unknown_rate=0.0)

    for _ in range(300):
        event, account_id, _ = gen.gen_payment(pool, random.Random(3))
        customer = by_account[account_id]
        assert event["city"] == customer.city
        assert event["customer_tier"] == customer.customer_tier
        if not event["is_international"]:
            assert event["country"] == customer.country


@pytest.mark.parametrize("rate", [0.0, 0.01, 0.05, 0.25, 1.0])
def test_unknown_account_rate_is_configurable(pool_file, rate):
    import random

    customers = gen.load_customer_pool(pool_file)
    pool = gen.CustomerPool(customers, random.Random(11), unknown_rate=rate)

    sample = 4000
    unknown = sum(1 for _ in range(sample) if not pool.pick()[1])
    observed = unknown / sample
    assert abs(observed - rate) < 0.03, f"expected ~{rate}, observed {observed}"


def test_unknown_accounts_can_never_collide_with_the_customer_pool(pool_file):
    import random

    customers = gen.load_customer_pool(pool_file)
    known = {c.account_id for c in customers}
    pool = gen.CustomerPool(customers, random.Random(5), unknown_rate=1.0)
    for _ in range(2000):
        customer, is_known = pool.pick()
        assert not is_known
        assert customer.account_id not in known
        number = int(customer.account_id.rsplit("-", 1)[1])
        assert number >= gen.UNKNOWN_ACCOUNT_LOW


def test_invalid_unknown_rate_is_rejected(pool_file):
    import random

    customers = gen.load_customer_pool(pool_file)
    for bad in (-0.1, 1.5):
        with pytest.raises(ValueError):
            gen.CustomerPool(customers, random.Random(1), unknown_rate=bad)
    with pytest.raises(ValueError):
        gen.CustomerPool([], random.Random(1))


def test_generator_reports_known_versus_unknown_usage(pool_file):
    stats = gen.AccountStats()
    for _ in range(97):
        stats.record("payments.raw", True)
    for _ in range(3):
        stats.record("payments.raw", False)
    report = stats.report()
    assert stats.total == 100
    assert "97" in report and "3" in report
    assert "payments.raw" in report


def test_legacy_random_pool_is_still_available():
    """Omitting --customer-file must preserve the original behaviour."""
    import random

    pool = gen.RandomPool(random.Random(1))
    customer, is_known = pool.pick()
    assert not is_known
    assert re.fullmatch(r"ACC-TH-\d{8}", customer.account_id)


def test_pool_csv_requires_account_id_column(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("tier,city\nGOLD,Bangkok\n", encoding="utf-8")
    with pytest.raises(ValueError):
        gen.load_customer_pool(bad)
    with pytest.raises(FileNotFoundError):
        gen.load_customer_pool(tmp_path / "nope.csv")


# --------------------------------------------------------------------------- #
# Safe cross-catalog SQL generation
# --------------------------------------------------------------------------- #
FEDERATED_EXAMPLES = [(q.example, q.name) for q in fed.FEDERATED_QUESTIONS]


@pytest.mark.parametrize("question,expected", FEDERATED_EXAMPLES)
def test_federated_questions_map_to_the_expected_intent(question, expected):
    match = fed.match_federated_question(question)
    assert match.question.name == expected, f"runners up: {match.runners_up}"


@pytest.mark.parametrize("question,expected", FEDERATED_EXAMPLES)
def test_every_federated_question_renders_read_only_sql(question, expected):
    _, sql = fed.build_federated_sql(question, hours=24, limit=50)
    fq.assert_read_only(sql)
    lowered = sql.lower()
    assert lowered.lstrip().startswith(("select", "with"))
    assert ";" not in sql
    # A federated query must genuinely reference both catalogs.
    assert fed.MYSQL_CATALOG in sql
    assert fed.ICEBERG_CATALOG in sql


@pytest.mark.parametrize(
    "question",
    [
        "drop table customers",
        "DELETE FROM customers",
        "truncate customer360.customers",
        "insert into customers values (1)",
        "grant all on customer360 to public",
        "update customers set pep_flag = 0",
    ],
)
def test_destructive_federated_requests_are_refused(question):
    with pytest.raises(fq.UnsupportedQuestionError):
        fed.match_federated_question(question)


@pytest.mark.parametrize(
    "question",
    [
        "",
        "what is the weather",
        "tell me a joke",
        "SELECT * FROM js_mysql_customer360.customer360.customers",
    ],
)
def test_unsupported_federated_questions_are_refused(question):
    with pytest.raises(fq.UnsupportedQuestionError):
        fed.match_federated_question(question)


def test_read_only_gate_still_blocks_dml_wrapped_in_a_cte():
    """Allowing a leading WITH must not open a DML hole."""
    with pytest.raises(fq.UnsafeQueryError):
        fq.assert_read_only("WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x")
    with pytest.raises(fq.UnsafeQueryError):
        fq.assert_read_only("WITH x AS (SELECT 1) DELETE FROM t")
    with pytest.raises(fq.UnsafeQueryError):
        fq.assert_read_only("WITH x AS (SELECT 1)")  # no SELECT body
    # ...while a legitimate CTE query is accepted.
    fq.assert_read_only("WITH x AS (SELECT 1 AS n) SELECT n FROM x")


# --------------------------------------------------------------------------- #
# Account-ID handling: no user text may reach SQL
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "text,expected",
    [
        (
            "Show the Customer 360 profile for account ACC-TH-10000001",
            "ACC-TH-10000001",
        ),
        ("profile for acc-th-10009999", "ACC-TH-10009999"),
        ("ACC TH 10000042 profile", "ACC-TH-10000042"),
    ],
)
def test_account_ids_are_canonically_rebuilt(text, expected):
    assert fed.canonical_account_id(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "profile for account ACC-TH-1' OR '1'='1",
        "profile for account ACC-TH-100",  # too short
        "profile for account ACC-TH-1000000000",  # too long is truncated, see below
        "profile for account DROP TABLE customers",
        "show the profile",
    ],
)
def test_malicious_or_missing_account_ids_are_handled_safely(text):
    try:
        account_id = fed.canonical_account_id(text)
    except fed.InvalidAccountError:
        return
    # If anything was extracted it must be exactly the canonical form, so no
    # injected character can survive into the SQL.
    assert fed.ACCOUNT_ID_RE.fullmatch(account_id)
    assert "'" not in account_id and " " not in account_id


def test_injection_attempt_is_refused_outright():
    question = (
        "Customer 360 profile for account ACC-TH-10000001'; DROP TABLE customers; --"
    )
    with pytest.raises(fq.UnsupportedQuestionError):
        fed.build_federated_sql(question, hours=24, limit=10)


@pytest.mark.parametrize(
    "payload",
    [
        "ACC-TH-10000001' OR '1'='1",
        "ACC-TH-10000001'; DROP TABLE customers; --",
        "ACC-TH-10000001 UNION SELECT password FROM users",
    ],
)
def test_injected_account_text_is_stripped_to_the_canonical_id(payload):
    """Even if a hostile string reaches the renderer, only 8 digits survive."""
    account_id = fed.canonical_account_id(payload)
    assert account_id == "ACC-TH-10000001"
    sql = fed.FEDERATED_BY_NAME["customer_profile_lookup"].render(
        hours=24, limit=10, account_id=account_id
    )
    fq.assert_read_only(sql)
    assert "DROP" not in sql.upper()
    assert "OR '1'='1" not in sql
    assert "'ACC-TH-10000001'" in sql


def test_account_scoped_question_requires_an_account_id():
    with pytest.raises(fed.InvalidAccountError):
        fed.build_federated_sql("Show the Customer 360 profile for account", hours=24)


# --------------------------------------------------------------------------- #
# Many-to-many aggregate inflation
# --------------------------------------------------------------------------- #
def _iceberg_sources_in(sql: str) -> set[str]:
    return {
        t for t in (fed.PAYMENTS, fed.FRAUD, fed.CUSTOMER_EVENTS, fed.AML) if t in sql
    }


def _cte_bodies(sql: str) -> list[str]:
    """Crude but sufficient: the text inside each top-level `name AS ( ... )`."""
    bodies, depth, start = [], 0, None
    for index, char in enumerate(sql):
        if char == "(":
            if depth == 0:
                start = index + 1
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0 and start is not None:
                bodies.append(sql[start:index])
                start = None
    return bodies


def _union_branches(sql: str) -> list[str]:
    """Split a statement into UNION branches.

    Sources sitting in separate UNION branches are stacked, not joined, so they
    cannot multiply each other's rows - each branch is assessed on its own.
    """
    return re.split(r"\bUNION\s+(?:ALL\s+)?", sql, flags=re.IGNORECASE)


def _assert_no_fan_out(sql: str, label: str) -> bool:
    """Return True if the check applied; False if it was not applicable."""
    applied = False
    for branch in _union_branches(sql):
        sources = _iceberg_sources_in(branch)
        if len(sources) < 2:
            continue
        applied = True
        bodies = _cte_bodies(branch)
        for source in sources:
            containing = [b for b in bodies if source in b]
            assert containing, f"{label}: {source} is not isolated inside a CTE"
            # Either collapses the source to one row per account, so the
            # subsequent join to customers is 1:1 and cannot inflate totals.
            assert any(
                re.search(r"group\s+by\s+account_id", b, re.IGNORECASE)
                or re.search(r"select\s+distinct\s+account_id", b, re.IGNORECASE)
                for b in containing
            ), (
                f"{label}: the CTE reading {source} neither GROUPs BY account_id "
                "nor SELECTs DISTINCT account_id"
            )
    return applied


@pytest.mark.parametrize("question,name", FEDERATED_EXAMPLES)
def test_multi_source_queries_pre_aggregate_to_avoid_fan_out(question, name):
    """Any single scope touching 2+ event tables must pre-aggregate each to one
    row per account.

    Joining customers -> payments -> fraud directly multiplies rows, so SUM()
    would over-report. Every such template must wrap each Iceberg source in its
    own `GROUP BY account_id` CTE before joining.
    """
    _, sql = fed.build_federated_sql(question, hours=24, limit=50)
    if not _assert_no_fan_out(sql, name):
        pytest.skip(f"{name} never joins two event tables in one scope")


def test_high_risk_exposure_joins_each_aggregate_exactly_once():
    _, sql = fed.build_federated_sql(
        "Show payment and fraud exposure for high-risk customers.", hours=24, limit=10
    )
    assert sql.count("LEFT JOIN payment_exposure") == 1
    assert sql.count("LEFT JOIN fraud_exposure") == 1
    # The raw tables must appear only inside the CTEs, never in the outer FROM.
    outer = sql.split(")\nSELECT", 1)[-1]
    assert fed.PAYMENTS not in outer
    assert fed.FRAUD not in outer


@pytest.mark.parametrize("path", sorted((REPO / "sql").glob("0[2-6]*.sql")))
def test_sql_files_that_touch_two_event_tables_pre_aggregate(path):
    stripped = re.sub(r"--[^\n]*", "", path.read_text(encoding="utf-8"))
    applied = False
    for statement in stripped.split(";"):
        if statement.strip():
            applied |= _assert_no_fan_out(statement, path.name)
    if not applied:
        pytest.skip(f"{path.name} never joins two event tables in one scope")


def test_all_sql_deliverables_use_the_agreed_catalog_name():
    for path in sorted((REPO / "sql").glob("0*.sql")):
        text = path.read_text(encoding="utf-8")
        assert "js_mysql_customer360" in text or "js_financial_ice" in text
        # The bare name would point at a catalog that does not exist here.
        assert not re.search(r"(?<!js_)\bmysql_customer360\b", text), path.name


# --------------------------------------------------------------------------- #
# Read-only enforcement / credentials
# --------------------------------------------------------------------------- #
def test_starburst_role_config_is_separate_from_the_app_role(monkeypatch):
    monkeypatch.setenv("MYSQL_APP_USER", "customer_app")
    monkeypatch.setenv("MYSQL_APP_PASSWORD", "app-secret")
    monkeypatch.setenv("MYSQL_STARBURST_USER", "starburst_ro")
    monkeypatch.setenv("MYSQL_STARBURST_PASSWORD", "ro-secret")

    app = load_mysql_config(role="app", env_file=Path("/nonexistent"))
    ro = load_mysql_config(role="starburst", env_file=Path("/nonexistent"))
    assert app.user == "customer_app"
    assert ro.user == "starburst_ro"
    assert ro.password.reveal() == "ro-secret"
    # AIDP must never be pointed at root.
    assert ro.user != "root"


def test_placeholder_password_is_refused(monkeypatch):
    monkeypatch.setenv("MYSQL_APP_USER", "customer_app")
    monkeypatch.setenv("MYSQL_APP_PASSWORD", "replace_me")
    with pytest.raises(MySQLConfigError, match="real value"):
        load_mysql_config(role="app", env_file=Path("/nonexistent"))


def test_unknown_role_is_refused():
    with pytest.raises(MySQLConfigError):
        load_mysql_config(role="root", env_file=Path("/nonexistent"))


def test_mysql_config_never_renders_the_password(monkeypatch):
    secret = "MySQL-Sup3r-Secret-Value"
    monkeypatch.setenv("MYSQL_APP_USER", "customer_app")
    monkeypatch.setenv("MYSQL_APP_PASSWORD", secret)
    config = load_mysql_config(role="app", env_file=Path("/nonexistent"))
    assert secret not in repr(config)
    assert secret not in str(config)
    assert secret not in f"{config}"
    assert secret not in config.safe_target
    assert isinstance(config.password, Secret)
    assert config.password.reveal() == secret


def test_mysql_credentials_never_appear_in_logs():
    secret = "MySQL-Sup3r-Secret-Value"
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("mysql360.test.redaction")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    logger.addFilter(SecretRedactingFilter(secret))

    logger.info("connecting with password=%s", secret)
    try:
        raise RuntimeError(f"Access denied using {secret}")
    except RuntimeError:
        logger.exception("boom")
    handler.flush()

    output = stream.getvalue()
    assert secret not in output
    assert REDACTED in output


def test_committed_config_files_contain_no_real_passwords():
    """The examples and compose file must ship placeholders only."""
    for relative in (
        "docker/mysql/.env.example",
        "docker/mysql/docker-compose.yml",
        "catalogs/js_mysql_customer360.properties.example",
        "docker/mysql/init/01_create_schema.sql",
        "docker/mysql/init/02_create_starburst_reader.sh",
    ):
        text = (REPO / relative).read_text(encoding="utf-8")
        assert "P@ssw0rd" not in text, f"{relative} contains a real-looking password"
        for line in text.splitlines():
            if re.match(r"\s*(MYSQL_\w*PASSWORD|connection-password)\s*[=:]", line):
                assert re.search(
                    r"(replace_me|__STARBURST_RO_PASSWORD__|\$\{|:\?)", line
                ), f"{relative} may hard-code a password: {line.strip()}"


def test_env_file_is_git_ignored():
    ignore = (REPO / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in ignore
    assert not (REPO / "docker" / "mysql" / ".env").exists() or ".env" in ignore


# --------------------------------------------------------------------------- #
# Idempotent MySQL loading
# --------------------------------------------------------------------------- #
def test_upsert_statement_is_idempotent_and_covers_every_column():
    sql = loader.INSERT_SQL
    assert sql.upper().startswith("INSERT INTO")
    assert "ON DUPLICATE KEY UPDATE" in sql.upper()
    for column in g360.CUSTOMER_COLUMNS:
        assert f"`{column}`" in sql
    assert sql.count("%s") == len(g360.CUSTOMER_COLUMNS)
    # The primary key and creation time must not be overwritten on conflict.
    update_clause = sql.upper().split("ON DUPLICATE KEY UPDATE", 1)[1]
    assert "`CUSTOMER_ID` =" not in update_clause
    assert "`CREATED_AT` =" not in update_clause


def test_loader_reads_csv_into_positional_rows(tmp_path):
    customers = g360.generate_customers(5, seed=42, today=AS_OF)
    path = tmp_path / "customer360.csv"
    g360.write_customer_csv(customers, path)
    rows = loader.read_customer_csv(path)
    assert len(rows) == 5
    assert len(rows[0]) == len(g360.CUSTOMER_COLUMNS)
    assert rows[0][g360.CUSTOMER_COLUMNS.index("account_id")] == "ACC-TH-10000001"


def test_loader_rejects_a_csv_with_missing_columns(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text(
        "customer_id,account_id\nCUST-DEMO-0000001,ACC-TH-10000001\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="missing required column"):
        loader.read_customer_csv(bad)


def test_loader_batches_and_commits_once(tmp_path):
    """Verify the load path without a database."""
    executed: list[tuple] = []

    class FakeCursor:
        def __init__(self):
            self._result = {"n": 0}

        def execute(self, sql, params=None):
            executed.append(("execute", sql))

        def executemany(self, sql, batch):
            executed.append(("executemany", len(batch)))
            return len(batch)

        def fetchone(self):
            return {"n": 0}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class FakeConnection:
        def __init__(self):
            self.commits = 0

        def cursor(self):
            return FakeCursor()

        def commit(self):
            self.commits += 1

    customers = g360.generate_customers(2500, seed=42, today=AS_OF)
    path = tmp_path / "c.csv"
    g360.write_customer_csv(customers, path)
    rows = loader.read_customer_csv(path)

    connection = FakeConnection()
    loader.load(rows, connection, batch_size=1000)
    batches = [n for kind, n in executed if kind == "executemany"]
    assert batches == [1000, 1000, 500]
    assert connection.commits == 1
    assert not any(
        "TRUNCATE" in str(s).upper() for kind, s in executed if kind == "execute"
    )


# --------------------------------------------------------------------------- #
# Live MySQL integration (skipped when MySQL is not running)
# --------------------------------------------------------------------------- #
def _live_connection():
    try:
        from mysql_connection import connect

        config = load_mysql_config(role="app")
        return connect(config, connect_timeout=3)
    except Exception:  # noqa: BLE001
        return None


@pytest.mark.skipif(_live_connection() is None, reason="local MySQL not reachable")
def test_live_load_is_idempotent():
    """Loading the same CSV twice must not change the row count."""
    from mysql_connection import connect

    csv_path = REPO / "data" / "customer360.csv"
    if not csv_path.exists():
        pytest.skip("data/customer360.csv has not been generated")

    rows = loader.read_customer_csv(csv_path)
    connection = connect(load_mysql_config(role="app"))
    try:
        first = loader.load(rows, connection)
        second = loader.load(rows, connection)
    finally:
        connection.close()

    assert second["rows_after"] == first["rows_after"]
    assert second["inserted"] == 0
    assert second["rows_after"] == second["distinct_account_ids"]


@pytest.mark.skipif(_live_connection() is None, reason="local MySQL not reachable")
def test_live_starburst_user_is_read_only():
    """The account AIDP uses must not be able to write."""
    import pymysql

    from mysql_connection import connect

    try:
        config = load_mysql_config(role="starburst")
    except MySQLConfigError:
        pytest.skip("starburst_ro credentials not configured")
    connection = connect(config)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS n FROM customers")
            assert cursor.fetchone()["n"] >= 0
            with pytest.raises(
                (pymysql.err.OperationalError, pymysql.err.ProgrammingError)
            ):
                cursor.execute("DELETE FROM customers WHERE customer_id = 'nope'")
    finally:
        connection.close()
