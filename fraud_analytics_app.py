"""AIDP Real-Time Banking Fraud Analytics - Streamlit front end.

Read-only by construction: user text is matched against an allowlisted intent
set (see :mod:`fraud_queries`) and never concatenated into SQL.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import pandas as pd
import streamlit as st

import federated_queries as fed
import fraud_queries as fq
from aidp_connection import (
    AidpConfig,
    AidpConfigError,
    AidpConnectionError,
    check_pystarburst_api,
    classify_error,
    load_config,
)
from schema_inspector import (
    EXPECTED_COLUMNS,
    PRIMARY_TABLE,
    SchemaValidationError,
    inspect_schema,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)

PAGE_TITLE = "AIDP Real-Time Banking Fraud Analytics"

st.set_page_config(page_title=PAGE_TITLE, page_icon=None, layout="wide")


# --------------------------------------------------------------------------- #
# Cached resources
# --------------------------------------------------------------------------- #
@st.cache_resource(show_spinner="Connecting to AIDP over HTTPS...")
def get_session_and_config():
    """One authenticated PyStarburst session per Streamlit server process."""
    from aidp_connection import create_session

    config = load_config()
    return create_session(config), config


@st.cache_data(ttl=300, show_spinner="Reading catalog metadata...")
def get_schema_report(catalog: str, schema: str) -> dict[str, Any]:
    """Metadata only - safe to cache for 5 minutes."""
    session, _ = get_session_and_config()
    report = inspect_schema(session, catalog, schema)
    return {
        "tables_found": report.tables_found,
        "missing_tables": report.missing_tables,
        "columns": report.columns,
        "missing_columns": report.missing_columns,
        "unexpected_columns": report.unexpected_columns,
        "describe_failures": report.describe_failures,
        "primary_table_ready": report.primary_table_ready,
        "ok": report.ok,
    }


@st.cache_resource(show_spinner=False)
def get_trino_fallback_connection():
    """Raw Trino DBAPI connection, created lazily only if the fallback is needed."""
    from aidp_connection import create_trino_connection

    _, config = get_session_and_config()
    return create_trino_connection(config)


def run_plan(plan: fq.QueryPlan, config: AidpConfig) -> tuple[pd.DataFrame, str | None]:
    """Execute a validated plan. Live fraud rows are deliberately NOT cached.

    Returns the result frame plus a note if the Trino-client fallback was used.
    """
    session, _ = get_session_and_config()
    try:
        df = fq.compile_plan(session, plan, config.catalog, config.schema)
        return df.to_pandas(), None
    except Exception as exc:  # noqa: BLE001
        if not fq.is_dataframe_api_unavailable(exc):
            raise
        logging.warning(
            "PyStarburst DataFrame analyzer unavailable; using Trino client fallback"
        )
        columns, rows = fq.execute_plan_sql(
            get_trino_fallback_connection(), plan, config.catalog, config.schema
        )
        note = (
            "PyStarburst's server-side DataFrame plan analyzer is not available on this "
            "cluster, so this result came from the official Trino client executing the "
            "read-only SELECT shown above. See README - 'PyStarburst fallbacks'."
        )
        return pd.DataFrame(rows, columns=columns), note


# --------------------------------------------------------------------------- #
# Sidebar
# --------------------------------------------------------------------------- #
def render_sidebar() -> dict[str, Any]:
    st.sidebar.header("Query settings")
    hours = st.sidebar.slider(
        "Time range (hours back from now, UTC)",
        min_value=1,
        max_value=168,
        value=fq.DEFAULT_TIME_RANGE_HOURS,
        help="Applied as timestamp >= current_timestamp - INTERVAL 'N' HOUR. "
        "The 'last hour' question always uses exactly 1 hour.",
    )
    score = st.sidebar.slider(
        "High-risk fraud score threshold (ml_score >=)",
        min_value=0.0,
        max_value=1.0,
        value=fq.DEFAULT_HIGH_RISK_SCORE,
        step=0.01,
    )
    override = st.sidebar.checkbox(
        "Override the row limit",
        value=False,
        help="Off: each question uses its own natural limit (e.g. 10 for 'the ten most "
        f"recent alerts', otherwise {fq.DEFAULT_LIMIT}).",
    )
    limit = st.sidebar.number_input(
        "Result row limit",
        min_value=1,
        max_value=fq.MAX_LIMIT,
        value=fq.DEFAULT_LIMIT,
        step=10,
        disabled=not override,
        help=f"Hard cap is {fq.MAX_LIMIT} rows.",
    )
    st.sidebar.caption(
        "Read-only: only SELECT statements are generated, from an allowlist of "
        "tables, columns and question intents. Arbitrary SQL is never executed."
    )
    return {
        "hours": int(hours),
        "score_threshold": float(score),
        "limit": int(limit) if override else None,
        "federated_limit": int(limit) if override else fq.DEFAULT_LIMIT,
    }


# --------------------------------------------------------------------------- #
# Connection status
# --------------------------------------------------------------------------- #
def render_connection_status() -> AidpConfig | None:
    version, api_problems = check_pystarburst_api()
    try:
        session, config = get_session_and_config()
    except AidpConfigError as exc:
        st.error(f"Configuration problem: {exc}")
        st.info(
            "Copy `.env.example` to `.env` (never commit it) or export the variables, "
            "then press R to rerun. `AIDP_PASSWORD` is only ever read from the environment."
        )
        return None
    except AidpConnectionError as exc:
        st.error(f"[{exc.kind}] {exc.message}")
        if exc.remedy:
            st.info(exc.remedy)
        return None
    except Exception as exc:  # noqa: BLE001
        err = classify_error(exc)
        st.error(f"[{err.kind}] {err.message}")
        if err.remedy:
            st.info(err.remedy)
        return None

    cols = st.columns([2, 2, 2, 1])
    cols[0].success(f"Connected to AIDP: {config.safe_target}")
    cols[1].metric("Catalog / schema", config.qualified_schema)
    cols[2].metric("Authenticated user", config.username)
    tls_label = "verified" if config.verify_tls else "DISABLED (lab only)"
    cols[3].metric("TLS", tls_label)
    if not config.verify_tls:
        st.warning(
            "TLS certificate verification is disabled (AIDP_VERIFY_TLS=false). "
            "Acceptable for lab testing only - re-enable it for any real data."
        )
    st.caption(
        f"PyStarburst {version} - password (HTTP Basic over HTTPS) authentication - "
        f"source/application name `{config.source}`. Credentials are never rendered or logged."
    )
    if api_problems:
        st.warning("PyStarburst API differences detected: " + "; ".join(api_problems))
    return config


def render_schema_panel(config: AidpConfig) -> bool:
    with st.expander(
        f"Access check: tables in {config.qualified_schema}", expanded=False
    ):
        try:
            report = get_schema_report(config.catalog, config.schema)
        except (SchemaValidationError, AidpConnectionError) as exc:
            st.error(str(exc))
            return False
        except Exception as exc:  # noqa: BLE001
            st.error(str(classify_error(exc)))
            return False

        st.write("Tables visible to this user:", report["tables_found"] or "(none)")
        if report["missing_tables"]:
            st.warning(
                "Expected tables not found (or not readable by this role): "
                + ", ".join(report["missing_tables"])
            )
        if report["missing_columns"]:
            st.warning(f"Missing expected columns: {report['missing_columns']}")
        if report["describe_failures"]:
            st.warning(
                f"Could not read column metadata for: {report['describe_failures']}"
            )
        if report["unexpected_columns"]:
            st.caption(
                f"Extra columns present on the server: {report['unexpected_columns']}"
            )
        st.caption(
            "Column allowlist used for query generation: "
            + ", ".join(f"{t} ({len(c)} cols)" for t, c in EXPECTED_COLUMNS.items())
        )
        st.info(
            "Data caveat: the streaming generator draws `account_id` independently for "
            "payment, fraud, AML and customer events, so records in different tables "
            "almost never describe the same customer. This app therefore performs no "
            "cross-table joins. Measure it yourself with "
            "`python scripts/check_join_match_rate.py`."
        )
        if not report["primary_table_ready"]:
            st.error(
                f"{config.qualified_schema}.{PRIMARY_TABLE} is not available with the "
                "expected columns; fraud questions cannot run."
            )
            return False
    return True


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #
def render_chart(plan: fq.QueryPlan, frame: pd.DataFrame) -> None:
    if plan.chart is None or frame.empty:
        return
    x, y = plan.chart_x, plan.chart_y
    if x not in frame.columns or y not in frame.columns:
        return
    st.subheader("Chart")
    data = frame[[x, y]].copy()
    data[x] = data[x].astype(str)
    data = data.set_index(x)
    if plan.chart == "line":
        st.line_chart(data)
    else:
        st.bar_chart(data)


def render_result(
    plan: fq.QueryPlan, match_explanation: str, config: AidpConfig
) -> None:
    sql_preview = fq.render_sql(plan, config.catalog, config.schema)

    with st.expander("Generated query and plan", expanded=True):
        st.caption(match_explanation)
        st.code(sql_preview, language="sql")
        st.caption(
            "Executed through the PyStarburst DataFrame API "
            "(session.table(...).filter(...).group_by(...).agg(...)); the SQL above is the "
            "equivalent statement, shown for review. Identifiers come from an allowlist."
        )
        st.json(
            {
                "intent": plan.intent,
                "table": f"{config.qualified_schema}.{plan.table}",
                "kind": plan.kind,
                "filters": [f"{f.column} {f.op} {f.value}" for f in plan.filters],
                "group_by": [g.alias for g in plan.group_by],
                "aggregates": [a.alias for a in plan.aggregates],
                "order_by": [f"{c} {d}" for c, d in plan.order_by],
                "limit": plan.limit,
            },
            expanded=False,
        )

    try:
        frame, fallback_note = run_plan(plan, config)
    except AidpConnectionError as exc:
        st.error(f"[{exc.kind}] {exc.message}")
        if exc.remedy:
            st.info(exc.remedy)
        return
    except Exception as exc:  # noqa: BLE001
        err = classify_error(exc)
        st.error(f"[{err.kind}] {err.message}")
        if err.remedy:
            st.info(err.remedy)
        return

    if fallback_note:
        st.info(fallback_note)

    st.subheader("Result")
    if frame.empty:
        st.info("The query returned no rows.")
    else:
        st.dataframe(frame, width="stretch")
        st.caption(f"{len(frame)} row(s), limit {plan.limit}.")

    rows: list[dict[str, Any]] = frame.to_dict("records")
    st.subheader("Interpretation")
    st.write(fq.summarize(plan, rows))
    render_chart(plan, frame)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def render_fraud_page(config: AidpConfig, params: dict[str, Any]) -> None:
    """Page 1: single-catalog real-time fraud analytics over Iceberg."""
    if not render_schema_panel(config):
        st.stop()

    st.divider()
    st.session_state.setdefault("question", fq.SUGGESTED_QUESTIONS[0])

    st.caption("Suggested questions")
    intents = list(fq.INTENTS)
    for row_start in range(0, len(intents), 3):
        chunk = intents[row_start : row_start + 3]
        for col, intent in zip(st.columns(3), chunk, strict=False):
            if col.button(intent.example, key=f"btn_{intent.name}", width="stretch"):
                st.session_state["question"] = intent.example
                st.rerun()

    left, right = st.columns([4, 1])
    asked = left.text_input(
        "Ask a question about the fraud data",
        key="question",
        help="Natural language, matched against a fixed set of supported questions.",
    )
    if right.button("Refresh", width="stretch", help="Re-read metadata and live data"):
        get_schema_report.clear()
        st.rerun()

    st.divider()

    try:
        match = fq.match_intent(asked)
        plan = fq.build_plan_for_intent(match.intent.name, **params)
    except fq.UnsupportedQuestionError as exc:
        st.warning(str(exc))
        st.write("Try one of these supported questions:")
        for suggestion in exc.suggestions:
            st.markdown(f"- {suggestion}")
        st.stop()
    except (ValueError, SchemaValidationError, fq.UnsafeQueryError) as exc:
        st.error(f"Rejected: {exc}")
        st.stop()

    render_result(plan, match.explanation, config)


# --------------------------------------------------------------------------- #
# Page 2: Federated Customer 360 (MySQL + Iceberg)
# --------------------------------------------------------------------------- #
def run_federated_sql(sql: str) -> pd.DataFrame:
    """Execute a validated federated statement. Live results are never cached."""
    session, _ = get_session_and_config()
    return session.sql(fed.assert_read_only(sql)).to_pandas()


def render_federated_catalog_status(config: AidpConfig) -> bool:
    """Show both catalogs and confirm the MySQL side is actually reachable."""
    try:
        status = get_federated_catalog_status()
    except Exception as exc:  # noqa: BLE001
        st.error(str(classify_error(exc)))
        return False

    cols = st.columns(3)
    if status["catalog_present"]:
        cols[0].success(f"MySQL catalog: {fed.MYSQL_CATALOG}")
    else:
        cols[0].error(f"MySQL catalog {fed.MYSQL_CATALOG} not found")
    cols[1].metric("Customer 360 rows (MySQL)", f"{status['customer_count']:,}")
    cols[2].metric("Iceberg catalog", fed.ICEBERG_CATALOG)

    if not status["catalog_present"]:
        st.error(
            f"The catalog `{fed.MYSQL_CATALOG}` is not registered on this AIDP cluster. "
            "An administrator must create it - see docs/FEDERATED_QUERY_DEMO.md, "
            "section 'AIDP MySQL catalog configuration'. Catalogs visible now: "
            + ", ".join(status["catalogs"])
        )
        return False
    if status["duplicate_accounts"]:
        st.error(
            f"{status['duplicate_accounts']} duplicate account_id value(s) in MySQL. "
            "Every federated aggregate would be inflated. Reload with "
            "`python scripts/load_customer360.py --input data/customer360.csv`."
        )
    st.caption(
        f"Federation: customer master data stays in MySQL ({fed.MYSQL_CATALOG}"
        f".{fed.MYSQL_SCHEMA}), event data stays in Iceberg ({fed.ICEBERG_CATALOG}"
        f".{fed.ICEBERG_SCHEMA}). Starburst joins them at query time - nothing is copied."
    )
    return True


@st.cache_data(ttl=300, show_spinner="Checking the MySQL catalog...")
def get_federated_catalog_status() -> dict[str, Any]:
    """Catalog metadata only - safe to cache briefly."""
    session, _ = get_session_and_config()
    catalogs = [r[0] for r in session.sql("SHOW CATALOGS").collect()]
    present = fed.MYSQL_CATALOG in catalogs
    count = duplicates = 0
    if present:
        row = session.sql(
            f"SELECT COUNT(*), COUNT(*) - COUNT(DISTINCT account_id) FROM {fed.CUSTOMERS}"
        ).collect()[0]
        count, duplicates = int(row[0]), int(row[1])
    return {
        "catalogs": catalogs,
        "catalog_present": present,
        "customer_count": count,
        "duplicate_accounts": duplicates,
    }


def render_source_attribution(
    question: fed.FederatedQuestion, frame: pd.DataFrame
) -> None:
    """Spell out which returned columns came from which catalog."""
    mysql_present = [c for c in question.mysql_columns if c in frame.columns]
    iceberg_present = [c for c in question.iceberg_columns if c in frame.columns]
    left, right = st.columns(2)
    left.markdown(
        f"**From MySQL** &nbsp;`{fed.MYSQL_CATALOG}.{fed.MYSQL_SCHEMA}.customers`\n\n"
        + ("\n".join(f"- `{c}`" for c in mysql_present) or "_(none in this result)_")
    )
    right.markdown(
        f"**From Iceberg** &nbsp;`{fed.ICEBERG_CATALOG}.{fed.ICEBERG_SCHEMA}.*`\n\n"
        + ("\n".join(f"- `{c}`" for c in iceberg_present) or "_(none in this result)_")
    )


def render_federated_chart(
    question: fed.FederatedQuestion, frame: pd.DataFrame
) -> None:
    if question.chart is None or frame.empty:
        return
    x, y = question.chart_x, question.chart_y
    if x not in frame.columns or y not in frame.columns:
        return
    st.subheader("Chart")
    data = frame[[x, y]].copy()
    data[x] = data[x].astype(str)
    data[y] = pd.to_numeric(data[y], errors="coerce")
    data = data.dropna().head(25).set_index(x)
    if data.empty:
        return
    st.line_chart(data) if question.chart == "line" else st.bar_chart(data)


def render_pushdown_diagnostics(sql: str) -> None:
    """Optional EXPLAIN panel. Reports only what the plan actually shows."""
    with st.expander("Pushdown diagnostics (EXPLAIN)", expanded=False):
        st.caption(
            "Shows the real distributed plan. Read it rather than assuming: a MySQL "
            "filter or aggregate is only pushed down when the plan's TableScan for "
            "the MySQL table shows it. The cross-catalog join itself always runs in "
            "Starburst."
        )
        if not st.button("Run EXPLAIN", key="explain_btn"):
            return
        session, _ = get_session_and_config()
        try:
            plan = session.sql(f"EXPLAIN {fed.assert_read_only(sql)}").collect()
        except Exception as exc:  # noqa: BLE001
            st.error(str(classify_error(exc)))
            return
        text = "\n".join(str(r[0]) for r in plan)
        st.code(text, language="text")

        mysql_scan = "mysql" in text.lower()
        pushed_filter = bool(
            re.search(r"mysql:.*(?:Query|WHERE|filter)", text, re.IGNORECASE)
        )
        st.markdown(
            f"- MySQL table scan present in plan: **{'yes' if mysql_scan else 'no'}**\n"
            f"- Plan text shows a MySQL-side filter/query fragment: "
            f"**{'yes' if pushed_filter else 'not visible'}**\n"
            "- Iceberg partition pruning uses `event_date`; add an `event_date` "
            "predicate to benefit from it.\n"
            "- The final cross-catalog join is executed by Starburst by definition."
        )
        if not pushed_filter:
            st.info(
                "No MySQL-side filter is visible in this plan, so do not claim pushdown "
                "occurred for this query."
            )


def render_federated_page(config: AidpConfig, params: dict[str, Any]) -> None:
    """Page 2: cross-catalog Customer 360."""
    if not render_federated_catalog_status(config):
        st.stop()

    st.divider()
    st.session_state.setdefault("fed_question", fed.FEDERATED_SUGGESTIONS[0])

    st.caption("Suggested federated questions")
    questions = list(fed.FEDERATED_QUESTIONS)
    for row_start in range(0, len(questions), 2):
        chunk = questions[row_start : row_start + 2]
        for col, question in zip(st.columns(2), chunk, strict=False):
            if col.button(
                question.example, key=f"fedbtn_{question.name}", width="stretch"
            ):
                st.session_state["fed_question"] = question.example
                st.rerun()

    left, right = st.columns([4, 1])
    asked = left.text_input(
        "Ask a question that spans MySQL Customer 360 and Iceberg banking data",
        key="fed_question",
    )
    if right.button("Refresh", width="stretch", key="fed_refresh"):
        get_federated_catalog_status.clear()
        st.rerun()

    st.divider()
    try:
        match, sql = fed.build_federated_sql(
            asked,
            hours=params["hours"],
            limit=params["federated_limit"],
            score=params["score_threshold"],
        )
    except fed.UnsupportedQuestionError as exc:
        st.warning(str(exc))
        st.write("Try one of these supported federated questions:")
        for suggestion in exc.suggestions:
            st.markdown(f"- {suggestion}")
        st.stop()
    except (ValueError, fq.UnsafeQueryError) as exc:
        st.error(f"Rejected: {exc}")
        st.stop()

    with st.expander("Generated federated SQL", expanded=True):
        st.caption(match.explanation)
        st.code(sql, language="sql")
        st.caption(
            "Read-only, built from a fixed reviewed template. No user text is "
            "concatenated into SQL; only validated numeric parameters and a "
            "canonically rebuilt ACC-TH-######## account ID are substituted."
        )

    try:
        frame = run_federated_sql(sql)
    except Exception as exc:  # noqa: BLE001
        err = classify_error(exc)
        st.error(f"[{err.kind}] {err.message}")
        if err.remedy:
            st.info(err.remedy)
        st.stop()

    st.subheader("Result")
    if frame.empty:
        st.info("The federated query returned no rows.")
    else:
        st.dataframe(frame, width="stretch")
        st.caption(f"{len(frame)} row(s).")

    st.subheader("Where each column came from")
    render_source_attribution(match.question, frame)

    st.subheader("Interpretation")
    st.write(fed.summarize_federated(match.question, frame.to_dict("records")))

    render_federated_chart(match.question, frame)
    render_pushdown_diagnostics(sql)


def main() -> None:
    st.title(PAGE_TITLE)

    params = render_sidebar()
    config = render_connection_status()
    if config is None:
        st.stop()

    page = st.sidebar.radio(
        "Page",
        ("Real-Time Fraud", "Federated Customer 360"),
        help="Federated Customer 360 joins MySQL master data with Iceberg events.",
    )
    if page == "Federated Customer 360":
        render_federated_page(config, params)
    else:
        render_fraud_page(config, params)


if __name__ == "__main__":
    main()
