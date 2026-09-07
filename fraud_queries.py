"""Allowlisted question -> query translation for the AIDP fraud demo.

Design notes
------------
* A question is matched to one of a fixed set of :class:`Intent` objects by an
  explainable keyword/pattern matcher.  Nothing the user types ever reaches SQL.
* Each intent builds a declarative :class:`QueryPlan` (an internal IR) whose
  identifiers are validated against :mod:`schema_inspector`'s allowlist.
* The plan is then either rendered to SQL *for display* (:func:`render_sql`) or
  compiled into PyStarburst DataFrame operations (:func:`compile_plan`).  Only
  read paths exist - there is no code path that can emit DML/DDL.

Adding an LLM later: replace :func:`match_intent` with a component that emits a
``QueryPlan`` (or an intent name + params).  Because ``QueryPlan`` construction
re-validates every identifier, literal and limit, an LLM cannot widen the blast
radius beyond what is allowlisted here.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from schema_inspector import (
    EXPECTED_COLUMNS,
    assert_allowlisted,
    qualified_name,
    quote_identifier,
)

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
DEFAULT_HIGH_RISK_SCORE = 0.85
DEFAULT_TIME_RANGE_HOURS = 24
MAX_TIME_RANGE_HOURS = 24 * 365

#: Statement keywords that must never appear in anything this module produces.
FORBIDDEN_SQL_KEYWORDS = (
    "insert",
    "update",
    "delete",
    "merge",
    "upsert",
    "drop",
    "create",
    "alter",
    "truncate",
    "replace",
    "grant",
    "revoke",
    "call",
    "commit",
    "rollback",
    "vacuum",
    "optimize",
    "refresh",
    "comment",
    "prepare",
    "deallocate",
    "execute",
    "use",
    "set session",
    "reset session",
)

_FORBIDDEN_RE = re.compile(
    r"(?:^|[^a-z_])("
    + "|".join(k.replace(" ", r"\s+") for k in FORBIDDEN_SQL_KEYWORDS)
    + r")(?:[^a-z_]|$)",
    re.IGNORECASE,
)

#: Literal values that may appear in a generated predicate, per column.
ALLOWED_LITERALS: dict[str, tuple[str, ...]] = {
    "action": ("BLOCK_AND_ALERT", "FLAG_REVIEW", "STEP_UP_AUTH"),
    "event_type": (
        "FRAUD_SIGNAL",
        "AML_ALERT",
        "CUSTOMER_LOGIN",
        "PROFILE_CHANGE",
        "ACCOUNT_OPEN",
    ),
    "risk_band": ("HIGH", "MEDIUM", "LOW"),
}

_AGG_FUNCS = {"count", "count_star", "avg", "max", "min", "sum"}
_TRANSFORMS = {"hour": "date_trunc('hour', {col})", "day": "date_trunc('day', {col})"}


class UnsupportedQuestionError(Exception):
    """Raised when a question cannot be mapped to an allowlisted intent."""

    def __init__(self, message: str, suggestions: Sequence[str] | None = None) -> None:
        super().__init__(message)
        self.suggestions = list(suggestions or ())


class UnsafeQueryError(Exception):
    """Raised when a generated statement fails the read-only safety check."""


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #
def validate_limit(limit: Any, default: int = DEFAULT_LIMIT) -> int:
    """Clamp/validate a row limit to 1..:data:`MAX_LIMIT`."""
    if limit is None:
        return default
    try:
        value = int(limit)
    except (TypeError, ValueError):
        raise ValueError(f"Row limit must be an integer, got {limit!r}") from None
    if value < 1:
        raise ValueError(f"Row limit must be at least 1, got {value}")
    if value > MAX_LIMIT:
        raise ValueError(f"Row limit must not exceed {MAX_LIMIT}, got {value}")
    return value


def validate_score_threshold(
    score: Any, default: float = DEFAULT_HIGH_RISK_SCORE
) -> float:
    """Validate an ``ml_score`` threshold; must be a float in [0.0, 1.0]."""
    if score is None:
        return default
    try:
        value = float(score)
    except (TypeError, ValueError):
        raise ValueError(
            f"Fraud score threshold must be numeric, got {score!r}"
        ) from None
    if not (0.0 <= value <= 1.0):
        raise ValueError(
            f"Fraud score threshold must be between 0.0 and 1.0, got {value}"
        )
    return value


def validate_hours(hours: Any, default: int = DEFAULT_TIME_RANGE_HOURS) -> int:
    """Validate a look-back window in whole hours."""
    if hours is None:
        return default
    try:
        value = int(hours)
    except (TypeError, ValueError):
        raise ValueError(
            f"Time range must be an integer number of hours, got {hours!r}"
        ) from None
    if not (1 <= value <= MAX_TIME_RANGE_HOURS):
        raise ValueError(
            f"Time range must be between 1 and {MAX_TIME_RANGE_HOURS} hours, got {value}"
        )
    return value


def _strip_parenthesised(text: str) -> str:
    """Remove balanced ``( ... )`` groups, leaving only top-level text."""
    out, depth = [], 0
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(char)
    return "".join(out)


def assert_read_only(sql: str) -> str:
    """Assert a statement is a single read-only ``SELECT`` (or ``WITH ... SELECT``).

    The federated Customer 360 queries need CTEs, so a leading ``WITH`` is
    accepted. That does not weaken the gate: Trino also allows
    ``WITH x AS (...) INSERT ...``, but ``insert`` - like every other DML/DDL
    keyword - is rejected by :data:`FORBIDDEN_SQL_KEYWORDS` below, and a
    ``WITH`` form must still contain a ``SELECT``.
    """
    text = sql.strip().rstrip(";")
    if ";" in text:
        raise UnsafeQueryError("Multiple statements are not allowed")
    if "--" in text or "/*" in text:
        raise UnsafeQueryError("SQL comments are not allowed")
    lowered = text.lower().lstrip("( ")
    if lowered.startswith("with"):
        # The body after the CTE definitions must itself be a SELECT. Checking
        # for "select" anywhere would be satisfied by the CTE's own SELECT, so
        # balanced parenthesised groups are removed first and the *remainder*
        # is what must contain the top-level SELECT.
        if not re.search(
            r"(?:^|[^a-z_])select(?:[^a-z_]|$)",
            _strip_parenthesised(text),
            re.IGNORECASE,
        ):
            raise UnsafeQueryError("A WITH statement must end in a top-level SELECT")
    elif not lowered.startswith("select"):
        raise UnsafeQueryError("Only SELECT statements are permitted")
    match = _FORBIDDEN_RE.search(text)
    if match:
        raise UnsafeQueryError(
            f"Forbidden keyword in generated SQL: {match.group(1)!r}"
        )
    return text


# --------------------------------------------------------------------------- #
# Query plan IR
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Filter:
    """A single predicate over an allowlisted column."""

    column: str
    op: str
    value: Any = None

    VALID_OPS = (
        "gte",
        "lte",
        "eq",
        "in",
        "is_true",
        "is_false",
        "not_null",
        "since_hours",
    )

    def __post_init__(self) -> None:
        if self.op not in self.VALID_OPS:
            raise ValueError(f"Unsupported filter operator {self.op!r}")
        if self.op == "since_hours":
            object.__setattr__(self, "value", validate_hours(self.value))
        elif self.op in ("gte", "lte"):
            if not isinstance(self.value, (int, float)) or isinstance(self.value, bool):
                raise ValueError(
                    f"{self.op} requires a numeric value, got {self.value!r}"
                )
        elif self.op == "eq":
            self._check_literal(self.value)
        elif self.op == "in":
            if not isinstance(self.value, (list, tuple)) or not self.value:
                raise ValueError("in requires a non-empty sequence of values")
            for item in self.value:
                self._check_literal(item)
        elif self.value is not None:
            raise ValueError(f"{self.op} does not take a value")

    def _check_literal(self, value: Any) -> None:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return
        if not isinstance(value, str):
            raise ValueError(f"Unsupported literal type {type(value).__name__}")
        allowed = ALLOWED_LITERALS.get(self.column, ())
        if value not in allowed:
            raise ValueError(
                f"Literal {value!r} is not allowlisted for column {self.column!r} "
                f"(allowed: {list(allowed)})"
            )


@dataclass(frozen=True)
class GroupKey:
    """A grouping expression: a bare column or an allowlisted transform of one."""

    column: str
    transform: str | None = None
    alias: str | None = None

    def __post_init__(self) -> None:
        if self.transform is not None and self.transform not in _TRANSFORMS:
            raise ValueError(f"Unsupported transform {self.transform!r}")
        object.__setattr__(self, "alias", self.alias or (self.transform or self.column))

    def sql(self) -> str:
        col = quote_identifier(self.column)
        expr = _TRANSFORMS[self.transform].format(col=col) if self.transform else col
        return f"{expr} AS {quote_identifier(self.alias)}"

    def expr_sql(self) -> str:
        col = quote_identifier(self.column)
        return _TRANSFORMS[self.transform].format(col=col) if self.transform else col


@dataclass(frozen=True)
class Aggregate:
    """An aggregate measure."""

    func: str
    alias: str
    column: str | None = None

    def __post_init__(self) -> None:
        if self.func not in _AGG_FUNCS:
            raise ValueError(f"Unsupported aggregate {self.func!r}")
        if self.func != "count_star" and not self.column:
            raise ValueError(f"{self.func} requires a column")
        if not set(self.alias.lower()) <= set("abcdefghijklmnopqrstuvwxyz0123456789_"):
            raise ValueError(f"Unsafe aggregate alias {self.alias!r}")

    def sql(self) -> str:
        inner = "*" if self.func == "count_star" else quote_identifier(self.column)
        name = "count" if self.func == "count_star" else self.func
        return f"{name}({inner}) AS {quote_identifier(self.alias)}"


@dataclass(frozen=True)
class QueryPlan:
    """Fully validated, read-only query description."""

    intent: str
    table: str
    kind: str  # "scalar" | "aggregation" | "detail"
    select: tuple[str, ...] = ()
    filters: tuple[Filter, ...] = ()
    group_by: tuple[GroupKey, ...] = ()
    aggregates: tuple[Aggregate, ...] = ()
    order_by: tuple[tuple[str, str], ...] = ()
    limit: int = DEFAULT_LIMIT
    chart: str | None = None  # "bar" | "line" | None
    chart_x: str | None = None
    chart_y: str | None = None
    narrative: str = ""

    def __post_init__(self) -> None:
        if self.kind not in ("scalar", "aggregation", "detail"):
            raise ValueError(f"Unsupported plan kind {self.kind!r}")
        columns = (
            list(self.select)
            + [f.column for f in self.filters]
            + [g.column for g in self.group_by]
            + [a.column for a in self.aggregates if a.column]
        )
        assert_allowlisted(self.table, columns)
        object.__setattr__(self, "limit", validate_limit(self.limit))
        output_names = {g.alias for g in self.group_by} | {
            a.alias for a in self.aggregates
        }
        output_names |= set(self.select)
        for column, direction in self.order_by:
            if direction not in ("asc", "desc"):
                raise ValueError(f"Unsupported sort direction {direction!r}")
            if column not in output_names:
                raise ValueError(f"Cannot order by {column!r}: not in the projection")


def _filter_sql(flt: Filter) -> str:
    col = quote_identifier(flt.column)
    if flt.op == "since_hours":
        return f"{col} >= current_timestamp - INTERVAL '{int(flt.value)}' HOUR"
    if flt.op == "gte":
        return (
            f"{col} >= {float(flt.value)!r}"
            if isinstance(flt.value, float)
            else f"{col} >= {int(flt.value)}"
        )
    if flt.op == "lte":
        return (
            f"{col} <= {float(flt.value)!r}"
            if isinstance(flt.value, float)
            else f"{col} <= {int(flt.value)}"
        )
    if flt.op == "eq":
        return f"{col} = {_literal_sql(flt.value)}"
    if flt.op == "in":
        values = ", ".join(_literal_sql(v) for v in flt.value)
        return f"{col} IN ({values})"
    if flt.op == "is_true":
        return f"{col} = true"
    if flt.op == "is_false":
        return f"{col} = false"
    return f"{col} IS NOT NULL"


def _literal_sql(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    # Only allowlisted enum values reach here (enforced by Filter.__post_init__),
    # so this is a formatting concern rather than an injection boundary.
    return "'" + str(value).replace("'", "''") + "'"


def render_sql(plan: QueryPlan, catalog: str, schema: str) -> str:
    """Render the plan as display SQL and assert it is read-only."""
    table = qualified_name(catalog, schema, plan.table)
    if plan.kind == "detail":
        projection = ", ".join(quote_identifier(c) for c in plan.select) or "*"
    else:
        projection = ", ".join(
            [g.sql() for g in plan.group_by] + [a.sql() for a in plan.aggregates]
        )

    parts = [f"SELECT {projection}", f"FROM {table}"]
    if plan.filters:
        parts.append("WHERE " + "\n  AND ".join(_filter_sql(f) for f in plan.filters))
    if plan.group_by:
        parts.append("GROUP BY " + ", ".join(g.expr_sql() for g in plan.group_by))
    if plan.order_by:
        parts.append(
            "ORDER BY "
            + ", ".join(f"{quote_identifier(c)} {d.upper()}" for c, d in plan.order_by)
        )
    if plan.kind != "scalar":
        parts.append(f"LIMIT {int(plan.limit)}")
    return assert_read_only("\n".join(parts))


def compile_plan(session, plan: QueryPlan, catalog: str, schema: str):
    """Compile the plan into a PyStarburst DataFrame (no SQL string involved)."""
    from pystarburst import functions as F

    df = session.table([catalog, schema, plan.table])

    for flt in plan.filters:
        col = F.col(flt.column)
        if flt.op == "since_hours":
            # PyStarburst has no INTERVAL helper, so a server-side SQL expression is
            # used.  The interval is an int validated by Filter/validate_hours.
            df = df.filter(
                col
                >= F.sql_expr(f"current_timestamp - INTERVAL '{int(flt.value)}' HOUR")
            )
        elif flt.op == "gte":
            df = df.filter(col >= F.lit(flt.value))
        elif flt.op == "lte":
            df = df.filter(col <= F.lit(flt.value))
        elif flt.op == "eq":
            df = df.filter(col == F.lit(flt.value))
        elif flt.op == "in":
            df = df.filter(col.in_([F.lit(v) for v in flt.value]))
        elif flt.op == "is_true":
            df = df.filter(col == F.lit(True))
        elif flt.op == "is_false":
            df = df.filter(col == F.lit(False))
        elif flt.op == "not_null":
            df = df.filter(col.is_not_null())

    if plan.kind == "detail":
        df = df.select(*[F.col(c) for c in plan.select])
    else:
        keys = []
        for key in plan.group_by:
            expr = (
                F.date_trunc(key.transform, F.col(key.column))
                if key.transform
                else F.col(key.column)
            )
            keys.append(expr.alias(key.alias))
        measures = [_agg_expr(F, a) for a in plan.aggregates]
        # Project the group keys (with their aliases) and the measured columns first
        # so the aggregation can refer to the aliases.
        projection = keys + [F.col(a.column) for a in plan.aggregates if a.column]
        if projection:
            df = df.select(*projection)
        if keys:
            df = df.group_by(*[F.col(k.alias) for k in plan.group_by]).agg(*measures)
        else:
            df = df.agg(*measures)

    if plan.order_by:
        # A single sort() call with all keys: successive sort() calls would each
        # *replace* the previous ordering, silently keeping only the last key.
        sort_exprs = [
            F.col(column).desc() if direction == "desc" else F.col(column).asc()
            for column, direction in plan.order_by
        ]
        df = df.sort(*sort_exprs)

    if plan.kind != "scalar":
        df = df.limit(plan.limit)
    return df


#: Symptoms that PyStarburst's *server-side* DataFrame plan analyzer
#: (``/v1/dataframe/plan`` or the ``dataframe`` table function) is not enabled on
#: this cluster, rather than a problem with the query itself.
DATAFRAME_API_SYMPTOMS = (
    "dataframe/plan",
    "table function",
    "dataframe_api",
    "function 'dataframe'",
    "not registered",
    "404",
    "unknown table function",
    "pystarburstgeneralexception",
)


def is_dataframe_api_unavailable(exc: BaseException) -> bool:
    """Heuristic: did the DataFrame plan analyzer itself fail (not the query)?"""
    text = str(exc).lower() + " " + type(exc).__name__.lower()
    return any(symptom in text for symptom in DATAFRAME_API_SYMPTOMS)


def execute_plan_sql(connection, plan: QueryPlan, catalog: str, schema: str):
    """Fallback executor using the official Trino client's DBAPI cursor.

    PyStarburst 0.14.x analyzes every DataFrame plan server-side, so if that
    facility is not enabled on the cluster the DataFrame API cannot run at all.
    Only in that case do we execute the rendered statement directly - and only
    after :func:`assert_read_only` has re-validated it.  Returns
    ``(column_names, rows)``.
    """
    sql = assert_read_only(render_sql(plan, catalog, schema))
    cursor = connection.cursor()
    # No parameters are bound because the statement contains only allowlisted
    # identifiers and validated numeric/enum literals - never user text.
    cursor.execute(sql)
    rows = cursor.fetchall()
    columns = [d[0] for d in (cursor.description or [])]
    return columns, rows


def _agg_expr(F, agg: Aggregate):
    if agg.func == "count_star":
        return F.count(F.lit(1)).alias(agg.alias)
    return getattr(F, agg.func)(F.col(agg.column)).alias(agg.alias)


# --------------------------------------------------------------------------- #
# Intent registry
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Intent:
    """An allowlisted question shape."""

    name: str
    example: str
    description: str
    table: str
    build: Callable[..., QueryPlan]
    #: Every inner tuple is an OR-group; all groups must match for the intent to apply.
    required: tuple[tuple[str, ...], ...] = ()
    boost: tuple[str, ...] = ()
    excludes: tuple[str, ...] = ()
    #: Row limit implied by the question itself ("the *ten* most recent alerts").
    #: Used when the caller does not pass an explicit limit.
    default_limit: int = DEFAULT_LIMIT


@dataclass
class MatchResult:
    """Explainable outcome of intent matching."""

    intent: Intent
    score: int
    matched_terms: list[str] = field(default_factory=list)
    runners_up: list[tuple[str, int]] = field(default_factory=list)

    @property
    def explanation(self) -> str:
        terms = ", ".join(f"'{t}'" for t in self.matched_terms) or "no keywords"
        return f"Matched intent '{self.intent.name}' (score {self.score}) on {terms}."


def _fraud_count_last_hour(**params) -> QueryPlan:
    return QueryPlan(
        intent="fraud_count_last_hour",
        table="fraud_alerts",
        kind="scalar",
        filters=(Filter("timestamp", "since_hours", 1),),
        aggregates=(Aggregate("count_star", "alert_count"),),
        narrative="fraud alerts raised in the last hour",
    )


def _fraud_by_type(
    hours: int = DEFAULT_TIME_RANGE_HOURS, limit: int = DEFAULT_LIMIT, **params
) -> QueryPlan:
    return QueryPlan(
        intent="fraud_by_type",
        table="fraud_alerts",
        kind="aggregation",
        filters=(Filter("timestamp", "since_hours", hours),),
        group_by=(GroupKey("fraud_type"),),
        aggregates=(Aggregate("count_star", "alert_count"),),
        order_by=(("alert_count", "desc"),),
        limit=limit,
        chart="bar",
        chart_x="fraud_type",
        chart_y="alert_count",
        narrative="fraud alerts grouped by fraud type",
    )


def _fraud_by_action(
    hours: int = DEFAULT_TIME_RANGE_HOURS, limit: int = DEFAULT_LIMIT, **params
) -> QueryPlan:
    return QueryPlan(
        intent="fraud_by_action",
        table="fraud_alerts",
        kind="aggregation",
        filters=(Filter("timestamp", "since_hours", hours),),
        group_by=(GroupKey("action"),),
        aggregates=(Aggregate("count_star", "alert_count"),),
        order_by=(("alert_count", "desc"),),
        limit=limit,
        chart="bar",
        chart_x="action",
        chart_y="alert_count",
        narrative="fraud alerts grouped by the action the platform took",
    )


def _action_outcome_counts(
    hours: int = DEFAULT_TIME_RANGE_HOURS, limit: int = DEFAULT_LIMIT, **params
) -> QueryPlan:
    return QueryPlan(
        intent="action_outcome_counts",
        table="fraud_alerts",
        kind="aggregation",
        filters=(
            Filter("timestamp", "since_hours", hours),
            Filter("action", "in", list(ALLOWED_LITERALS["action"])),
        ),
        group_by=(GroupKey("action"),),
        aggregates=(Aggregate("count_star", "alert_count"),),
        order_by=(("alert_count", "desc"),),
        limit=limit,
        chart="bar",
        chart_x="action",
        chart_y="alert_count",
        narrative="alerts that were blocked, flagged for review or sent to step-up authentication",
    )


def _top_accounts_by_score(
    hours: int = DEFAULT_TIME_RANGE_HOURS, limit: int = 20, **params
) -> QueryPlan:
    return QueryPlan(
        intent="top_accounts_by_score",
        table="fraud_alerts",
        kind="aggregation",
        filters=(Filter("timestamp", "since_hours", hours),),
        group_by=(GroupKey("account_id"),),
        aggregates=(
            Aggregate("max", "max_ml_score", "ml_score"),
            Aggregate("count_star", "alert_count"),
        ),
        order_by=(("max_ml_score", "desc"), ("alert_count", "desc")),
        limit=limit,
        chart="bar",
        chart_x="account_id",
        chart_y="max_ml_score",
        narrative="accounts with the highest fraud (ML) scores",
    )


def _latest_high_risk(
    hours: int = DEFAULT_TIME_RANGE_HOURS,
    limit: int = DEFAULT_LIMIT,
    score_threshold: float = DEFAULT_HIGH_RISK_SCORE,
    **params,
) -> QueryPlan:
    return QueryPlan(
        intent="latest_high_risk",
        table="fraud_alerts",
        kind="detail",
        select=(
            "timestamp",
            "account_id",
            "fraud_type",
            "ml_score",
            "action",
            "case_id",
            "event_id",
        ),
        filters=(
            Filter("timestamp", "since_hours", hours),
            Filter("ml_score", "gte", validate_score_threshold(score_threshold)),
        ),
        order_by=(("timestamp", "desc"),),
        limit=limit,
        narrative=f"the most recent alerts with ml_score >= {validate_score_threshold(score_threshold)}",
    )


def _avg_score_by_type(
    hours: int = DEFAULT_TIME_RANGE_HOURS, limit: int = DEFAULT_LIMIT, **params
) -> QueryPlan:
    return QueryPlan(
        intent="avg_score_by_type",
        table="fraud_alerts",
        kind="aggregation",
        filters=(Filter("timestamp", "since_hours", hours),),
        group_by=(GroupKey("fraud_type"),),
        aggregates=(
            Aggregate("avg", "avg_ml_score", "ml_score"),
            Aggregate("count_star", "alert_count"),
        ),
        order_by=(("avg_ml_score", "desc"),),
        limit=limit,
        chart="bar",
        chart_x="fraud_type",
        chart_y="avg_ml_score",
        narrative="the average fraud (ML) score for each fraud type",
    )


def _fraud_trend_by_hour(
    hours: int = DEFAULT_TIME_RANGE_HOURS, limit: int = DEFAULT_LIMIT, **params
) -> QueryPlan:
    return QueryPlan(
        intent="fraud_trend_by_hour",
        table="fraud_alerts",
        kind="aggregation",
        filters=(Filter("timestamp", "since_hours", hours),),
        group_by=(GroupKey("timestamp", "hour", "alert_hour"),),
        aggregates=(
            Aggregate("count_star", "alert_count"),
            Aggregate("avg", "avg_ml_score", "ml_score"),
        ),
        order_by=(("alert_hour", "asc"),),
        limit=limit,
        chart="line",
        chart_x="alert_hour",
        chart_y="alert_count",
        narrative="how the fraud alert volume moved hour by hour",
    )


def _recent_fraud_alerts(limit: int = 10, **params) -> QueryPlan:
    return QueryPlan(
        intent="recent_fraud_alerts",
        table="fraud_alerts",
        kind="detail",
        select=(
            "timestamp",
            "account_id",
            "fraud_type",
            "ml_score",
            "action",
            "case_id",
            "event_id",
        ),
        order_by=(("timestamp", "desc"),),
        limit=limit,
        narrative="the newest fraud alerts, newest first",
    )


def _aml_by_risk_band(
    hours: int = DEFAULT_TIME_RANGE_HOURS, limit: int = DEFAULT_LIMIT, **params
) -> QueryPlan:
    return QueryPlan(
        intent="aml_by_risk_band",
        table="aml_alerts",
        kind="aggregation",
        filters=(Filter("timestamp", "since_hours", hours),),
        group_by=(GroupKey("risk_band"),),
        aggregates=(
            Aggregate("count_star", "alert_count"),
            Aggregate("avg", "avg_amount_7d", "total_amount_7d"),
        ),
        order_by=(("alert_count", "desc"),),
        limit=limit,
        chart="bar",
        chart_x="risk_band",
        chart_y="alert_count",
        narrative="AML alerts grouped by risk band",
    )


def _login_outcomes(
    hours: int = DEFAULT_TIME_RANGE_HOURS, limit: int = DEFAULT_LIMIT, **params
) -> QueryPlan:
    return QueryPlan(
        intent="login_outcomes",
        table="customer_events",
        kind="aggregation",
        filters=(
            Filter("timestamp", "since_hours", hours),
            Filter("event_type", "eq", "CUSTOMER_LOGIN"),
        ),
        group_by=(GroupKey("login_success"),),
        aggregates=(Aggregate("count_star", "login_count"),),
        order_by=(("login_count", "desc"),),
        limit=limit,
        chart="bar",
        chart_x="login_success",
        chart_y="login_count",
        narrative="successful versus failed customer logins",
    )


def _new_device_logins(
    hours: int = DEFAULT_TIME_RANGE_HOURS, limit: int = DEFAULT_LIMIT, **params
) -> QueryPlan:
    return QueryPlan(
        intent="new_device_logins",
        table="customer_events",
        kind="aggregation",
        filters=(
            Filter("timestamp", "since_hours", hours),
            Filter("event_type", "eq", "CUSTOMER_LOGIN"),
        ),
        group_by=(GroupKey("new_device"),),
        aggregates=(Aggregate("count_star", "login_count"),),
        order_by=(("login_count", "desc"),),
        limit=limit,
        chart="bar",
        chart_x="new_device",
        chart_y="login_count",
        narrative="customer logins from a new (previously unseen) device",
    )


INTENTS: tuple[Intent, ...] = (
    Intent(
        name="fraud_count_last_hour",
        example="How many fraud alerts occurred in the last hour?",
        description="Count of fraud alerts in the trailing 60 minutes.",
        table="fraud_alerts",
        build=_fraud_count_last_hour,
        required=(
            (
                "last hour",
                "past hour",
                "previous hour",
                "last 1 hour",
                "one hour",
                "60 minutes",
            ),
        ),
        boost=("how many", "count", "fraud", "alert"),
        excludes=("trend", "by hour", "hourly", "per hour", "average", "avg"),
    ),
    Intent(
        name="avg_score_by_type",
        example="What is the average fraud score by fraud type?",
        description="Mean ml_score per fraud_type.",
        table="fraud_alerts",
        build=_avg_score_by_type,
        required=(("average", "avg", "mean"), ("score", "ml_score", "ml score")),
        boost=("fraud type", "fraud_type", "by type"),
        excludes=("aml", "login"),
    ),
    Intent(
        name="top_accounts_by_score",
        example="Which accounts have the highest fraud scores?",
        description="Accounts ranked by their peak ml_score.",
        table="fraud_alerts",
        build=_top_accounts_by_score,
        required=(
            ("account", "accounts", "account_id", "customer"),
            (
                "highest",
                "top",
                "worst",
                "riskiest",
                "max",
                "maximum",
                "biggest",
                "largest",
            ),
        ),
        boost=("fraud score", "ml_score", "score", "rank"),
        excludes=("aml", "login"),
        default_limit=20,
    ),
    Intent(
        name="latest_high_risk",
        example="Show the latest high-risk fraud alerts.",
        description="Recent alerts above the configured ml_score threshold.",
        table="fraud_alerts",
        build=_latest_high_risk,
        required=(("high risk", "high-risk", "highrisk", "riskiest alerts", "severe"),),
        boost=("latest", "recent", "fraud", "alert", "show"),
        excludes=("aml", "login", "trend"),
    ),
    Intent(
        name="fraud_trend_by_hour",
        example="Show fraud trends by hour.",
        description="Hourly alert volume via date_trunc('hour', timestamp).",
        table="fraud_alerts",
        build=_fraud_trend_by_hour,
        required=(
            (
                "trend",
                "trends",
                "over time",
                "by hour",
                "hourly",
                "per hour",
                "time series",
            ),
        ),
        boost=("fraud", "alert", "chart"),
        excludes=("last hour", "past hour", "aml", "login"),
    ),
    Intent(
        name="action_outcome_counts",
        example="How many alerts were blocked, flagged for review, or required step-up authentication?",
        description="Counts for the BLOCK_AND_ALERT / FLAG_REVIEW / STEP_UP_AUTH outcomes.",
        table="fraud_alerts",
        build=_action_outcome_counts,
        required=(
            (
                "blocked",
                "block",
                "flagged",
                "flag for review",
                "flag review",
                "step-up",
                "step up",
                "stepup",
            ),
        ),
        boost=("how many", "alerts", "authentication", "review", "outcome"),
        excludes=("aml", "login", "trend"),
    ),
    Intent(
        name="fraud_by_action",
        example="Show fraud alerts by action.",
        description="Alert counts grouped by the action column.",
        table="fraud_alerts",
        build=_fraud_by_action,
        required=(("action", "actions", "disposition", "outcome"),),
        boost=("fraud", "alert", "by action", "group"),
        excludes=(
            "blocked",
            "flagged",
            "step-up",
            "step up",
            "stepup",
            "aml",
            "login",
            "trend",
            "average",
        ),
    ),
    Intent(
        name="fraud_by_type",
        example="Show fraud alerts by fraud type.",
        description="Alert counts grouped by fraud_type.",
        table="fraud_alerts",
        build=_fraud_by_type,
        required=(
            (
                "fraud type",
                "fraud_type",
                "by type",
                "type of fraud",
                "fraud types",
                "by category",
            ),
        ),
        boost=("fraud", "alert", "count", "breakdown", "group"),
        excludes=("average", "avg", "mean", "aml", "login", "trend"),
    ),
    Intent(
        name="recent_fraud_alerts",
        example="Show the ten most recent fraud alerts.",
        description="Detail rows ordered by timestamp DESC.",
        table="fraud_alerts",
        build=_recent_fraud_alerts,
        required=(("recent", "latest", "newest", "last few", "most recent"),),
        boost=("fraud", "alert", "ten", "10", "show"),
        excludes=(
            "high risk",
            "high-risk",
            "highrisk",
            "last hour",
            "past hour",
            "trend",
            "by type",
            "by action",
            "average",
            "aml",
            "login",
        ),
        default_limit=10,
    ),
    Intent(
        name="aml_by_risk_band",
        example="How many AML alerts exist by risk band?",
        description="AML alert counts grouped by risk_band.",
        table="aml_alerts",
        build=_aml_by_risk_band,
        required=(("aml", "anti-money", "money laundering", "sar"),),
        boost=("risk band", "risk_band", "band", "how many", "alerts"),
        excludes=(),
    ),
    Intent(
        name="new_device_logins",
        example="How many customer logins used a new device?",
        description="Login counts split by the new_device flag.",
        table="customer_events",
        build=_new_device_logins,
        required=(
            (
                "new device",
                "new_device",
                "unknown device",
                "unrecognised device",
                "unrecognized device",
                "device",
            ),
        ),
        boost=("login", "logins", "customer", "how many"),
        excludes=(),
    ),
    Intent(
        name="login_outcomes",
        example="Show successful and failed customer logins.",
        description="Login counts split by the login_success flag.",
        table="customer_events",
        build=_login_outcomes,
        required=(("login", "logins", "log in", "sign in", "signin", "log-in"),),
        boost=("successful", "success", "failed", "failure", "customer"),
        excludes=("device",),
    ),
)

INTENTS_BY_NAME: dict[str, Intent] = {i.name: i for i in INTENTS}
SUGGESTED_QUESTIONS: tuple[str, ...] = tuple(i.example for i in INTENTS)

_DESTRUCTIVE_HINTS = (
    "drop",
    "delete",
    "truncate",
    "insert",
    "update ",
    "alter",
    "grant",
    "revoke",
    "create ",
    "merge into",
)


def normalize_question(question: str) -> str:
    """Lowercase and collapse punctuation/whitespace for keyword matching."""
    text = (question or "").lower()
    text = re.sub(r"[^a-z0-9_\-\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _matches(text: str, term: str) -> bool:
    if " " in term or "-" in term or "_" in term:
        return term in text
    return re.search(rf"(?:^|\s){re.escape(term)}(?:$|\s)", text) is not None


def match_intent(question: str) -> MatchResult:
    """Map a natural-language question to exactly one allowlisted intent.

    Raises :class:`UnsupportedQuestionError` when nothing matches confidently.
    """
    text = normalize_question(question)
    if not text:
        raise UnsupportedQuestionError("Please enter a question.", SUGGESTED_QUESTIONS)

    for hint in _DESTRUCTIVE_HINTS:
        if hint.strip() in text.split() or hint in text:
            raise UnsupportedQuestionError(
                "This request looks like it is trying to modify data. This application is "
                "strictly read-only and does not execute user-supplied SQL.",
                SUGGESTED_QUESTIONS,
            )

    scored: list[tuple[int, int, Intent, list[str]]] = []
    for intent in INTENTS:
        if any(_matches(text, term) for term in intent.excludes):
            continue
        matched: list[str] = []
        satisfied = True
        for group in intent.required:
            group = (group,) if isinstance(group, str) else group
            hit = next((term for term in group if _matches(text, term)), None)
            if hit is None:
                satisfied = False
                break
            matched.append(hit)
        if not satisfied:
            continue
        score = 10 * len(matched)
        for term in intent.boost:
            if _matches(text, term):
                score += 3
                matched.append(term)
        scored.append((score, len(intent.required), intent, matched))

    if not scored:
        raise UnsupportedQuestionError(
            "That question is not supported yet. This first version uses an explainable "
            "keyword matcher over a fixed set of questions.",
            SUGGESTED_QUESTIONS,
        )

    scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
    best = scored[0]
    return MatchResult(
        intent=best[2],
        score=best[0],
        matched_terms=best[3],
        runners_up=[(s[2].name, s[0]) for s in scored[1:4]],
    )


def build_plan(question: str, **params) -> tuple[MatchResult, QueryPlan]:
    """Match a question and build its validated :class:`QueryPlan`."""
    match = match_intent(question)
    return match, build_plan_for_intent(match.intent.name, **params)


def build_plan_for_intent(intent_name: str, **params) -> QueryPlan:
    """Build the plan for an explicit intent name (used by the suggestion buttons)."""
    intent = INTENTS_BY_NAME.get(intent_name)
    if intent is None:
        raise UnsupportedQuestionError(
            f"Unknown intent {intent_name!r}", SUGGESTED_QUESTIONS
        )
    clean = {
        "hours": validate_hours(params.get("hours")),
        "limit": validate_limit(params.get("limit"), default=intent.default_limit),
        "score_threshold": validate_score_threshold(params.get("score_threshold")),
    }
    return intent.build(**clean)


# --------------------------------------------------------------------------- #
# Plain-language interpretation
# --------------------------------------------------------------------------- #
def _fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:,.3f}"
    if isinstance(value, int):
        return f"{value:,}"
    return str(value)


def summarize(plan: QueryPlan, rows: Sequence[dict[str, Any]]) -> str:
    """Produce a short plain-language interpretation of a result set."""
    if not rows:
        return (
            f"No rows matched: there are currently no {plan.narrative}. "
            "Either the stream is idle or the time window is too narrow - widen the "
            "time range in the sidebar and refresh."
        )

    if plan.kind == "scalar":
        measure = plan.aggregates[0].alias
        return f"There were {_fmt(rows[0][measure])} {plan.narrative}."

    if plan.kind == "detail":
        parts = [
            f"Showing {len(rows)} of at most {plan.limit} rows covering {plan.narrative}."
        ]
        if "timestamp" in plan.select:
            parts.append(f"The newest is from {rows[0].get('timestamp')}.")
        if "ml_score" in plan.select:
            scores = [r["ml_score"] for r in rows if r.get("ml_score") is not None]
            if scores:
                parts.append(
                    f"ml_score ranges from {_fmt(min(scores))} to {_fmt(max(scores))}."
                )
        return " ".join(parts)

    key = plan.group_by[0].alias
    measure = plan.chart_y or plan.aggregates[0].alias
    total = sum(r[measure] for r in rows if isinstance(r.get(measure), (int, float)))
    lead = rows[0]
    parts = [
        f"{len(rows)} group(s) returned for {plan.narrative}.",
        f"The largest is {key}={lead.get(key)} with {measure}={_fmt(lead.get(measure))}.",
    ]
    if plan.aggregates[0].func == "count_star" and measure == plan.aggregates[0].alias:
        parts.append(f"Total across the groups shown: {_fmt(total)}.")
        if total:
            share = 100.0 * float(lead.get(measure, 0)) / float(total)
            parts.append(f"That top group is {share:.1f}% of the total.")
    return " ".join(parts)


def table_allowlist() -> tuple[str, ...]:
    """Tables any intent is permitted to read."""
    return tuple(sorted({i.table for i in INTENTS}))


assert set(table_allowlist()) <= set(EXPECTED_COLUMNS), (
    "intent table outside schema allowlist"
)
