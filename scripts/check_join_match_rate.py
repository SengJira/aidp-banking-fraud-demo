#!/usr/bin/env python3
"""Report the real account_id join-match rate between the banking tables.

The streaming generator calls ``rand_account()`` independently for payment,
fraud, AML and customer events, so cross-table joins on ``account_id`` are
expected to match approximately never.  Run this before writing any analysis
that claims records in different tables belong to the same customer.

    python scripts/check_join_match_rate.py [--sample-rows 5000]
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aidp_connection import (
    AidpConfigError,
    AidpConnectionError,
    create_session,
    load_config,
)
from schema_inspector import join_match_rate

PAIRS = (
    ("fraud_alerts", "payment_transactions"),
    ("fraud_alerts", "aml_alerts"),
    ("fraud_alerts", "customer_events"),
    ("aml_alerts", "customer_events"),
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample-rows", type=int, default=5000)
    args = parser.parse_args()

    try:
        config = load_config()
        session = create_session(config)
    except (AidpConfigError, AidpConnectionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(
        f"Join-match rate on account_id (sample of {args.sample_rows} rows per side)\n"
    )
    for left, right in PAIRS:
        try:
            result = join_match_rate(
                session, config.catalog, config.schema, left, right, args.sample_rows
            )
        except Exception as exc:  # noqa: BLE001
            print(f"{left:22s} x {right:22s}  FAILED: {exc}")
            continue
        print(
            f"{left:22s} x {right:22s}  "
            f"distinct_left={result['distinct_left_accounts']:<8} "
            f"matched={result['matched_accounts']:<8} "
            f"match_rate={result['match_rate']:.4%}"
        )

    print(
        "\nA match rate near 0% confirms account_id is independently generated per "
        "table: do NOT present cross-table rows as the same customer."
    )
    session.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
