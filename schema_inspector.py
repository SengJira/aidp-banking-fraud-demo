"""Catalog / schema / column validation against the live AIDP metastore.

Everything here is *metadata* only, so results are safe to cache for a short
while (live fraud rows are never cached - see ``fraud_analytics_app.py``).

The expected shape of ``js_financial_ice.banking`` is declared statically in
:data:`EXPECTED_COLUMNS` and cross-checked against the server; the app degrades
gracefully (and says so) when a column is missing rather than emitting SQL that
will fail.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field

from aidp_connection import classify_error

logger = logging.getLogger("aidp.schema")

#: Tables this application is ever allowed to read, with their expected columns.
EXPECTED_COLUMNS: dict[str, tuple[str, ...]] = {
    "fraud_alerts": (
        "event_id",
        "event_type",
        "timestamp",
        "account_id",
        "fraud_type",
        "ml_score",
        "action",
        "case_id",
        "event_date",
    ),
    "payment_transactions": (
        "event_id",
        "event_type",
        "timestamp",
        "transaction_id",
        "account_id",
        "amount",
        "currency",
        "channel",
        "merchant_category",
        "status",
        "city",
        "country",
        "latitude",
        "longitude",
        "is_international",
        "customer_tier",
        "risk_score",
        "ingested_at",
        "event_date",
    ),
    "payment_agg": (
        "window_start",
        "window_end",
        "city",
        "channel",
        "merchant_category",
        "txn_count",
        "total_amount",
        "avg_amount",
        "max_amount",
        "approved_count",
        "declined_count",
        "intl_count",
        "avg_risk_score",
        "event_date",
    ),
    "aml_alerts": (
        "event_id",
        "event_type",
        "timestamp",
        "account_id",
        "alert_type",
        "risk_band",
        "sar_required",
        "total_amount_7d",
        "event_date",
    ),
    "customer_events": (
        "event_id",
        "event_type",
        "timestamp",
        "account_id",
        "channel",
        "auth_method",
        "login_success",
        "new_device",
        "event_date",
    ),
}

PRIMARY_TABLE = "fraud_alerts"

# Trino unquoted identifiers: letters, digits and underscores only.  Anything
# outside this set is rejected outright rather than escaped, because no
# allowlisted identifier in this app needs it.
_SAFE_IDENTIFIER = set("abcdefghijklmnopqrstuvwxyz0123456789_")


class SchemaValidationError(Exception):
    """Raised when a requested table/column is not allowlisted or not present."""


def quote_identifier(name: str) -> str:
    """Return ``name`` as a safely double-quoted Trino identifier.

    Only allowlisted-looking identifiers are accepted; this is a defence in
    depth check, not an escaping routine for untrusted input.
    """
    if not name or not set(name.lower()) <= _SAFE_IDENTIFIER:
        raise SchemaValidationError(f"Unsafe identifier rejected: {name!r}")
    return '"' + name + '"'


def qualified_name(catalog: str, schema: str, table: str) -> str:
    """Fully qualified, safely quoted table reference."""
    if table not in EXPECTED_COLUMNS:
        raise SchemaValidationError(
            f"Table {table!r} is not in the allowlist {sorted(EXPECTED_COLUMNS)}"
        )
    return ".".join(quote_identifier(part) for part in (catalog, schema, table))


def assert_allowlisted(table: str, columns: Sequence[str]) -> None:
    """Validate a table and its referenced columns against the static allowlist."""
    allowed = EXPECTED_COLUMNS.get(table)
    if allowed is None:
        raise SchemaValidationError(
            f"Table {table!r} is not in the allowlist {sorted(EXPECTED_COLUMNS)}"
        )
    unknown = [c for c in columns if c not in allowed]
    if unknown:
        raise SchemaValidationError(
            f"Column(s) {unknown} are not allowlisted for {table!r}"
        )


@dataclass
class SchemaReport:
    """Outcome of validating the live schema against expectations."""

    catalog: str
    schema: str
    tables_found: list[str] = field(default_factory=list)
    missing_tables: list[str] = field(default_factory=list)
    columns: dict[str, list[str]] = field(default_factory=dict)
    missing_columns: dict[str, list[str]] = field(default_factory=dict)
    unexpected_columns: dict[str, list[str]] = field(default_factory=dict)
    #: Tables whose column metadata could not be read, and why.
    describe_failures: dict[str, str] = field(default_factory=dict)

    @property
    def primary_table_ready(self) -> bool:
        return (
            PRIMARY_TABLE in self.tables_found
            and PRIMARY_TABLE in self.columns
            and not self.missing_columns.get(PRIMARY_TABLE)
        )

    @property
    def ok(self) -> bool:
        return (
            not self.missing_tables
            and not self.missing_columns
            and not self.describe_failures
        )


def list_tables(session, catalog: str, schema: str) -> list[str]:
    """List tables in ``catalog.schema`` (metadata read, PyStarburst ``sql``)."""
    stmt = f"SHOW TABLES FROM {quote_identifier(catalog)}.{quote_identifier(schema)}"
    try:
        rows = session.sql(stmt).collect()
    except BaseException as exc:  # noqa: BLE001
        err = classify_error(exc)
        if err.kind == "missing_object":
            raise SchemaValidationError(
                f"Schema {catalog}.{schema} was not found on this AIDP instance."
            ) from None
        raise err from None
    return sorted(str(row[0]) for row in rows)


def describe_table(session, catalog: str, schema: str, table: str) -> list[str]:
    """Return the live column names of an allowlisted table."""
    if table not in EXPECTED_COLUMNS:
        raise SchemaValidationError(f"Table {table!r} is not in the allowlist")
    # DataFrame.schema is the PyStarburst-native way to read column metadata;
    # no SQL text is built from user input.
    try:
        df = session.table([catalog, schema, table])
        return [f.name.lower() for f in df.schema.fields]
    except BaseException as exc:  # noqa: BLE001
        raise classify_error(exc) from None


def inspect_schema(
    session, catalog: str, schema: str, tables: Sequence[str] | None = None
) -> SchemaReport:
    """Validate that the expected tables and columns exist in AIDP."""
    report = SchemaReport(catalog=catalog, schema=schema)
    present = list_tables(session, catalog, schema)
    report.tables_found = present

    wanted = list(tables) if tables else list(EXPECTED_COLUMNS)
    report.missing_tables = [t for t in wanted if t not in present]

    for table in wanted:
        if table in report.missing_tables:
            continue
        try:
            live = describe_table(session, catalog, schema, table)
        except Exception as exc:  # noqa: BLE001 - one bad table must not hide the rest
            logger.warning(
                "Could not describe %s.%s.%s: %s", catalog, schema, table, exc
            )
            report.describe_failures[table] = str(exc)[:200]
            continue
        report.columns[table] = live
        expected = EXPECTED_COLUMNS[table]
        missing = [c for c in expected if c not in live]
        extra = [c for c in live if c not in expected]
        if missing:
            report.missing_columns[table] = missing
        if extra:
            report.unexpected_columns[table] = extra
    return report


def join_match_rate(
    session,
    catalog: str,
    schema: str,
    left: str = "fraud_alerts",
    right: str = "payment_transactions",
    sample_rows: int = 5000,
) -> dict[str, object]:
    """Measure how often ``account_id`` actually matches across two tables.

    The streaming generator draws ``account_id`` independently for payment,
    fraud, AML and customer events, so cross-table joins are expected to match
    almost never.  Run this before trusting any "same customer" narrative.
    """
    for table in (left, right):
        assert_allowlisted(table, ["account_id"])
    sample_rows = max(1, min(int(sample_rows), 100_000))

    left_df = (
        session.table([catalog, schema, left]).select("account_id").limit(sample_rows)
    )
    right_ids = (
        session.table([catalog, schema, right])
        .select("account_id")
        .distinct()
        .limit(sample_rows)
    )
    left_ids = left_df.distinct()
    left_count = left_ids.count()
    matched = left_ids.join(right_ids, on="account_id", how="inner").count()
    return {
        "left": f"{catalog}.{schema}.{left}",
        "right": f"{catalog}.{schema}.{right}",
        "sample_rows": sample_rows,
        "distinct_left_accounts": left_count,
        "matched_accounts": matched,
        "match_rate": (matched / left_count) if left_count else 0.0,
    }
