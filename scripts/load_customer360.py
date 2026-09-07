#!/usr/bin/env python3
"""Load (upsert) the synthetic Customer 360 CSV into MySQL.

Idempotent: the load is an ``INSERT ... ON DUPLICATE KEY UPDATE`` keyed on the
``customer_id`` primary key, so running it repeatedly refreshes existing rows
instead of creating duplicates. ``account_id`` additionally carries a UNIQUE
constraint, because a duplicate account would multiply every federated
aggregate downstream.

Usage
-----
    python scripts/load_customer360.py --input data/customer360.csv
    python scripts/load_customer360.py --input data/customer360.csv --truncate
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mysql_connection import (  # noqa: E402
    CUSTOMERS_TABLE,
    MySQLConfigError,
    MySQLConnectionError,
    connect,
    load_mysql_config,
)
from scripts.generate_customer360 import CUSTOMER_COLUMNS  # noqa: E402

logger = logging.getLogger("mysql360.load")

DEFAULT_INPUT = "data/customer360.csv"
DEFAULT_BATCH_SIZE = 1_000

# Every column except the identity/audit ones is refreshed on conflict.
_UPDATABLE = tuple(
    c for c in CUSTOMER_COLUMNS if c not in ("customer_id", "created_at")
)

INSERT_SQL = (
    f"INSERT INTO {CUSTOMERS_TABLE} ("
    + ", ".join(f"`{c}`" for c in CUSTOMER_COLUMNS)
    + ") VALUES ("
    + ", ".join(["%s"] * len(CUSTOMER_COLUMNS))
    + ") ON DUPLICATE KEY UPDATE "
    + ", ".join(f"`{c}` = VALUES(`{c}`)" for c in _UPDATABLE)
)


def read_customer_csv(path: Path) -> list[tuple]:
    """Read the generated CSV into positional rows matching CUSTOMER_COLUMNS."""
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Generate it first:\n"
            "  python scripts/generate_customer360.py --customers 10000 --seed 42 "
            "--output-dir data"
        )
    rows: list[tuple] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = [c for c in CUSTOMER_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"{path} is missing required column(s): {missing}")
        for record in reader:
            rows.append(tuple(record[column] or None for column in CUSTOMER_COLUMNS))
    if not rows:
        raise ValueError(f"{path} contains no data rows")
    return rows


def load(
    rows: list[tuple],
    connection,
    batch_size: int = DEFAULT_BATCH_SIZE,
    truncate: bool = False,
) -> dict[str, int]:
    """Upsert ``rows``. Returns before/after counts and the affected-row total."""
    stats: dict[str, int] = {}
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT COUNT(*) AS n FROM {CUSTOMERS_TABLE}")
        stats["rows_before"] = int(cursor.fetchone()["n"])

        if truncate:
            logger.warning(
                "--truncate given: deleting all existing customer rows first"
            )
            cursor.execute(f"TRUNCATE TABLE {CUSTOMERS_TABLE}")
            stats["rows_before_after_truncate"] = 0

        affected = 0
        for start in range(0, len(rows), batch_size):
            batch = rows[start : start + batch_size]
            affected += cursor.executemany(INSERT_SQL, batch)
            print(
                f"  upserted {min(start + len(batch), len(rows)):,}/{len(rows):,}",
                end="\r",
                flush=True,
            )
        print()
        connection.commit()

        cursor.execute(f"SELECT COUNT(*) AS n FROM {CUSTOMERS_TABLE}")
        stats["rows_after"] = int(cursor.fetchone()["n"])
        cursor.execute(f"SELECT COUNT(DISTINCT account_id) AS n FROM {CUSTOMERS_TABLE}")
        stats["distinct_account_ids"] = int(cursor.fetchone()["n"])

    # MySQL reports 1 per insert and 2 per updated row, so this is a signal of
    # insert-vs-update mix rather than an exact count.
    stats["affected_rows"] = affected
    stats["inserted"] = stats["rows_after"] - stats["rows_before"]
    return stats


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Idempotently load synthetic Customer 360 data into MySQL.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--input", default=DEFAULT_INPUT, help="Path to customer360.csv"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help="Rows per executemany batch",
    )
    parser.add_argument(
        "--truncate",
        action="store_true",
        help="Delete existing rows before loading (destructive)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    args = build_parser().parse_args(argv)

    try:
        rows = read_customer_csv(Path(args.input))
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        config = load_mysql_config(role="app")
        connection = connect(config)
    except (MySQLConfigError, MySQLConnectionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3

    try:
        print(f"Loading {len(rows):,} customers into {config.safe_target}")
        stats = load(rows, connection, args.batch_size, args.truncate)
    except Exception as exc:  # noqa: BLE001
        connection.rollback()
        print(f"ERROR: load failed and was rolled back: {exc}", file=sys.stderr)
        return 4
    finally:
        connection.close()

    print(
        f"\nrows before      : {stats['rows_before']:,}\n"
        f"rows after       : {stats['rows_after']:,}\n"
        f"newly inserted   : {stats['inserted']:,}\n"
        f"updated in place : {len(rows) - stats['inserted']:,}\n"
        f"distinct accounts: {stats['distinct_account_ids']:,}"
    )
    if stats["rows_after"] != stats["distinct_account_ids"]:
        print(
            "WARNING: account_id is not unique - federated aggregates would be inflated."
        )
        return 5
    print(
        "\nLoad is idempotent: re-running refreshes rows instead of duplicating them."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
