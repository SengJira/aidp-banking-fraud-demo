#!/usr/bin/env python3
"""End-to-end validation of the AIDP federated Customer 360 demo.

Prints PASS / FAIL / SKIP per check and exits non-zero if anything FAILed.
SKIP means a prerequisite was unavailable (for example no AIDP_PASSWORD), never
that a check silently succeeded - results are not fabricated.

    python scripts/validate_federated_demo.py
    python scripts/validate_federated_demo.py --min-match-pct 95 --window-hours 1
"""

from __future__ import annotations

import argparse
import io
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import federated_queries as fed  # noqa: E402
from mysql_connection import (  # noqa: E402
    CUSTOMERS_TABLE,
    MySQLConfigError,
    MySQLConnectionError,
    load_mysql_config,  # noqa: E402
)
from mysql_connection import connect as mysql_connect  # noqa: E402

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"
MIN_CUSTOMERS = 10_000
DEFAULT_MIN_MATCH_PCT = 95.0
DEFAULT_WINDOW_HOURS = 1

ICEBERG_TABLES = (
    "payment_transactions",
    "payment_agg",
    "fraud_alerts",
    "aml_alerts",
    "customer_events",
)


class Results:
    """Collects check outcomes and renders the report."""

    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []

    def add(self, status: str, name: str, detail: str = "") -> None:
        self.rows.append((status, name, detail))
        colour = {PASS: "\033[32m", FAIL: "\033[31m", SKIP: "\033[33m"}.get(status, "")
        reset = "\033[0m" if colour else ""
        print(
            f"  {colour}{status:4s}{reset}  {name}"
            + (f"\n          {detail}" if detail else "")
        )

    @property
    def failed(self) -> int:
        return sum(1 for s, _, _ in self.rows if s == FAIL)

    @property
    def skipped(self) -> int:
        return sum(1 for s, _, _ in self.rows if s == SKIP)

    @property
    def passed(self) -> int:
        return sum(1 for s, _, _ in self.rows if s == PASS)


def check_mysql(results: Results, args) -> dict | None:
    """Checks 1-4: MySQL reachable, table present, row count, unique account_id."""
    print("\nMySQL Customer 360")
    try:
        config = load_mysql_config(role=args.mysql_role)
    except MySQLConfigError as exc:
        for name in (
            "MySQL reachable",
            f"{CUSTOMERS_TABLE} table exists",
            f"at least {MIN_CUSTOMERS:,} customers",
            "account_id is unique",
        ):
            results.add(SKIP, name, str(exc))
        return None

    try:
        connection = mysql_connect(config)
    except MySQLConnectionError as exc:
        results.add(FAIL, "MySQL reachable", str(exc))
        for name in (
            f"{CUSTOMERS_TABLE} table exists",
            f"at least {MIN_CUSTOMERS:,} customers",
            "account_id is unique",
        ):
            results.add(SKIP, name, "MySQL unreachable")
        return None

    results.add(PASS, "MySQL reachable", config.safe_target)
    stats: dict = {}
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) AS n FROM information_schema.tables "
                "WHERE table_schema = %s AND table_name = %s",
                (config.database, CUSTOMERS_TABLE),
            )
            if int(cursor.fetchone()["n"]) != 1:
                results.add(
                    FAIL,
                    f"{CUSTOMERS_TABLE} table exists",
                    f"not found in schema {config.database}",
                )
                return None
            results.add(
                PASS,
                f"{CUSTOMERS_TABLE} table exists",
                f"{config.database}.{CUSTOMERS_TABLE}",
            )

            cursor.execute(
                f"SELECT COUNT(*) AS total, COUNT(DISTINCT account_id) AS distinct_accounts, "
                f"MIN(account_id) AS lo, MAX(account_id) AS hi FROM {CUSTOMERS_TABLE}"
            )
            row = cursor.fetchone()
            stats = {k: row[k] for k in ("total", "distinct_accounts", "lo", "hi")}

            if stats["total"] >= MIN_CUSTOMERS:
                results.add(
                    PASS,
                    f"at least {MIN_CUSTOMERS:,} customers",
                    f"{stats['total']:,} rows, range {stats['lo']} .. {stats['hi']}",
                )
            else:
                results.add(
                    FAIL,
                    f"at least {MIN_CUSTOMERS:,} customers",
                    f"only {stats['total']:,} rows loaded",
                )

            duplicates = stats["total"] - stats["distinct_accounts"]
            if duplicates == 0:
                results.add(
                    PASS,
                    "account_id is unique",
                    f"{stats['distinct_accounts']:,} distinct values, 0 duplicates",
                )
            else:
                results.add(
                    FAIL,
                    "account_id is unique",
                    f"{duplicates} duplicate(s) would inflate every federated aggregate",
                )
    finally:
        connection.close()
    return stats


def check_aidp(results: Results, args) -> object | None:
    """Check 5: the AIDP endpoint is reachable and authenticated."""
    print("\nAIDP / Starburst")
    from aidp_connection import (
        AidpConfigError,
        AidpConnectionError,
        create_session,
        load_config,
    )

    try:
        config = load_config()
    except AidpConfigError as exc:
        results.add(SKIP, "AIDP endpoint reachable", str(exc))
        return None
    try:
        session = create_session(config)
    except AidpConnectionError as exc:
        results.add(FAIL, "AIDP endpoint reachable", f"[{exc.kind}] {exc}")
        return None
    results.add(
        PASS,
        "AIDP endpoint reachable",
        f"{config.safe_target} as {config.username} (TLS verify={config.verify_tls})",
    )
    return session


def check_catalogs(results: Results, session) -> bool:
    """Checks 6-7: the MySQL catalog and the Iceberg tables are visible."""
    catalogs = [r[0] for r in session.sql("SHOW CATALOGS").collect()]
    if fed.MYSQL_CATALOG in catalogs:
        count = session.sql(f"SELECT COUNT(*) FROM {fed.CUSTOMERS}").collect()[0][0]
        results.add(
            PASS,
            f"MySQL catalog {fed.MYSQL_CATALOG} visible in AIDP",
            f"{count:,} customers readable through the catalog",
        )
        mysql_ok = True
    else:
        results.add(
            FAIL,
            f"MySQL catalog {fed.MYSQL_CATALOG} visible in AIDP",
            "not registered. An administrator must create it - see "
            "docs/FEDERATED_QUERY_DEMO.md. Visible: " + ", ".join(catalogs),
        )
        mysql_ok = False

    tables = [
        r[0]
        for r in session.sql(
            f"SHOW TABLES FROM {fed.ICEBERG_CATALOG}.{fed.ICEBERG_SCHEMA}"
        ).collect()
    ]
    missing = [t for t in ICEBERG_TABLES if t not in tables]
    if missing:
        results.add(FAIL, "Iceberg tables visible", f"missing: {', '.join(missing)}")
    else:
        results.add(PASS, "Iceberg tables visible", ", ".join(ICEBERG_TABLES))
    return mysql_ok


def check_federated_queries(results: Results, session, args) -> None:
    """Checks 8-9: a customer-payment and a customer-fraud federated query run."""
    for label, name in (
        ("federated customer-payment query", "top_customers_by_payment"),
        ("federated customer-fraud query", "high_risk_with_fraud"),
    ):
        question = fed.FEDERATED_BY_NAME[name]
        sql = question.render(hours=args.window_hours * 24, limit=10)
        try:
            rows = session.sql(sql).collect()
        except Exception as exc:  # noqa: BLE001
            results.add(FAIL, label, str(exc)[:200])
            continue
        if rows:
            results.add(PASS, label, f"{len(rows)} row(s) joined across both catalogs")
        else:
            results.add(
                FAIL,
                label,
                "query succeeded but returned no rows - is the streaming "
                "pipeline running and are account IDs aligned?",
            )


def check_match_rate(results: Results, session, args) -> None:
    """Check 10: at least N% of event account IDs match a MySQL customer."""
    sql = fed.FEDERATED_BY_NAME["unmatched_events"].render(hours=args.window_hours)
    try:
        rows = session.sql(sql).collect()
    except Exception as exc:  # noqa: BLE001
        results.add(
            FAIL,
            f"at least {args.min_match_pct}% of events match MySQL",
            str(exc)[:200],
        )
        return

    details, worst = [], None
    for row in rows:
        source, total, matched, _unmatched, pct = row[0], row[1], row[2], row[3], row[4]
        if not total:
            continue
        pct = float(pct)
        details.append(f"{source}: {matched:,}/{total:,} = {pct:.2f}%")
        worst = pct if worst is None else min(worst, pct)

    if worst is None:
        results.add(
            FAIL,
            f"at least {args.min_match_pct}% of events match MySQL",
            f"no events in the last {args.window_hours}h - is the pipeline running?",
        )
    elif worst >= args.min_match_pct:
        results.add(
            PASS,
            f"at least {args.min_match_pct}% of events match MySQL",
            "; ".join(details),
        )
    else:
        results.add(
            FAIL,
            f"at least {args.min_match_pct}% of events match MySQL",
            "; ".join(details),
        )


def check_no_credentials_leak(results: Results) -> None:
    """Check 11: secrets never appear in logs or generated artefacts."""
    print("\nCredential hygiene")
    secrets: list[tuple[str, str]] = []
    for role in ("app", "starburst"):
        try:
            config = load_mysql_config(role=role)
            secrets.append((f"MySQL {role} password", config.password.reveal()))
        except MySQLConfigError:
            pass
    aidp_password = os.environ.get("AIDP_PASSWORD")
    if aidp_password:
        secrets.append(("AIDP password", aidp_password))

    if not secrets:
        results.add(
            SKIP, "no credentials in generated files", "no secrets configured to test"
        )
        return

    repo = Path(__file__).resolve().parent.parent
    scanned = 0
    offenders: list[str] = []
    patterns = (
        "data/*.csv",
        "sql/*.sql",
        "docs/*.md",
        "*.md",
        "*.py",
        "scripts/*.py",
        "generators/*.py",
        "docker/mysql/*.yml",
        "docker/mysql/*.example",
        "catalogs/*.example",
    )
    for pattern in patterns:
        for path in repo.glob(pattern):
            if not path.is_file() or path.stat().st_size > 20_000_000:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            scanned += 1
            for label, secret in secrets:
                if secret and secret in text:
                    offenders.append(f"{label} found in {path.relative_to(repo)}")
    if offenders:
        results.add(FAIL, "no credentials in generated files", "; ".join(offenders))
    else:
        results.add(
            PASS,
            "no credentials in generated files",
            f"{scanned} tracked file(s) scanned for {len(secrets)} secret(s)",
        )

    # Prove the logging filter actually redacts, rather than assuming it does.
    from aidp_connection import REDACTED, SecretRedactingFilter

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    probe = logging.getLogger("validate.redaction.probe")
    probe.handlers = [handler]
    probe.propagate = False
    probe.setLevel(logging.DEBUG)
    probe.addFilter(SecretRedactingFilter(*[s for _, s in secrets]))
    for label, secret in secrets:
        probe.info("connecting with %s=%s", label, secret)
    handler.flush()
    output = stream.getvalue()
    if any(secret in output for _, secret in secrets):
        results.add(
            FAIL, "no credentials in logs", "a secret survived the redaction filter"
        )
    else:
        results.add(
            PASS,
            "no credentials in logs",
            f"{len(secrets)} secret(s) replaced with {REDACTED}",
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate the AIDP federated Customer 360 demo end to end.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--min-match-pct",
        type=float,
        default=DEFAULT_MIN_MATCH_PCT,
        help="Minimum acceptable event-to-customer match percentage",
    )
    parser.add_argument(
        "--window-hours",
        type=int,
        default=DEFAULT_WINDOW_HOURS,
        help="Look-back window for the match-rate check",
    )
    parser.add_argument(
        "--mysql-role",
        default="app",
        choices=["app", "starburst"],
        help="Which MySQL account to connect as for the direct checks",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.WARNING, format="%(levelname)s %(name)s %(message)s"
    )
    args = build_parser().parse_args(argv)

    print("=" * 78)
    print("AIDP Federated Customer 360 - demo validation")
    print("=" * 78)

    results = Results()
    check_mysql(results, args)

    session = check_aidp(results, args)
    if session is None:
        for name in (
            f"MySQL catalog {fed.MYSQL_CATALOG} visible in AIDP",
            "Iceberg tables visible",
            "federated customer-payment query",
            "federated customer-fraud query",
            f"at least {args.min_match_pct}% of events match MySQL",
        ):
            results.add(SKIP, name, "no AIDP session")
    else:
        mysql_ok = check_catalogs(results, session)
        print("\nFederated queries")
        if mysql_ok:
            check_federated_queries(results, session, args)
            check_match_rate(results, session, args)
        else:
            for name in (
                "federated customer-payment query",
                "federated customer-fraud query",
                f"at least {args.min_match_pct}% of events match MySQL",
            ):
                results.add(SKIP, name, f"catalog {fed.MYSQL_CATALOG} not registered")

    check_no_credentials_leak(results)

    print("\n" + "=" * 78)
    print(
        f"{results.passed} passed, {results.failed} failed, {results.skipped} skipped"
    )
    print("=" * 78)
    if results.failed:
        print("\nFAILED checks:")
        for status, name, detail in results.rows:
            if status == FAIL:
                print(f"  - {name}: {detail}")
        return 1
    if results.skipped:
        print(
            "\nSome checks were skipped - the environment was incomplete, so the demo "
            "is NOT fully validated."
        )
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
