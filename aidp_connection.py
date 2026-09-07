"""Secure connection handling for the Dell AI Data Platform (Starburst/Trino).

Configuration comes exclusively from the environment (optionally seeded from a
local ``.env`` that is never committed).  The password is wrapped in
:class:`Secret` so that accidental ``print``/``repr``/f-string usage cannot leak
it, and :class:`SecretRedactingFilter` scrubs it from anything that reaches the
logging subsystem.
"""

from __future__ import annotations

import logging
import os
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger("aidp")

DEFAULT_SOURCE = "aidp-fraud-demo"
DEFAULT_REQUEST_TIMEOUT = 30.0
REDACTED = "***REDACTED***"


class Secret:
    """A string that refuses to reveal itself unless explicitly asked."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value or ""

    def reveal(self) -> str:
        return self._value

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        # Deliberately not the real length; only "empty or not" is observable.
        return 1 if self._value else 0

    def __repr__(self) -> str:
        return f"Secret({REDACTED})"

    __str__ = __repr__

    def __format__(self, _spec: str) -> str:
        return REDACTED


class SecretRedactingFilter(logging.Filter):
    """Replaces known secret values anywhere in a log record with a marker."""

    def __init__(self, *secrets: str) -> None:
        super().__init__()
        self._secrets = [s for s in secrets if s]

    def _scrub(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, REDACTED)
        return text

    def _scrub_arg(self, value: object) -> object:
        """Scrub a log argument, preserving its type unless it held a secret.

        Blindly stringifying every argument would break ``%d``/``%f`` format
        specifiers, so non-strings are only replaced if they actually contain a
        secret (which numbers never do).
        """
        if isinstance(value, str):
            return self._scrub(value)
        text = str(value)
        scrubbed = self._scrub(text)
        return scrubbed if scrubbed != text else value

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self._scrub(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._scrub_arg(v) for k, v in record.args.items()}
            else:
                record.args = tuple(self._scrub_arg(a) for a in record.args)
        if record.exc_info and record.exc_info[1] is not None:
            exc = record.exc_info[1]
            scrubbed = tuple(self._scrub(str(a)) for a in exc.args)
            if scrubbed != exc.args:
                exc.args = scrubbed
        return True


class AidpConfigError(Exception):
    """Raised when the environment configuration is missing or invalid."""


@dataclass(frozen=True)
class AidpConfig:
    """Connection settings. Never holds the password in a printable field."""

    endpoint: str
    host: str
    port: int
    username: str
    catalog: str
    schema: str
    verify_tls: bool
    password: Secret
    source: str = DEFAULT_SOURCE
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT

    @property
    def safe_target(self) -> str:
        """Human-readable target with no credential material."""
        return f"https://{self.host}:{self.port}"

    @property
    def qualified_schema(self) -> str:
        return f"{self.catalog}.{self.schema}"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise AidpConfigError(f"{name} must be a boolean-like value, got {raw!r}")


def load_config(load_dotenv_file: bool = True) -> AidpConfig:
    """Build an :class:`AidpConfig` from environment variables.

    ``AIDP_PASSWORD`` is required and is only ever read from the environment.
    """
    if load_dotenv_file:
        try:
            from dotenv import load_dotenv

            load_dotenv(override=False)
        except ImportError:  # optional convenience only
            pass

    endpoint = os.environ.get("AIDP_ENDPOINT", "").strip()
    if not endpoint:
        raise AidpConfigError("AIDP_ENDPOINT is not set (e.g. https://host:443/)")

    parsed = urlparse(endpoint)
    if parsed.scheme != "https":
        raise AidpConfigError(
            f"AIDP_ENDPOINT must use https://, got scheme {parsed.scheme!r}. "
            "Plain HTTP would send the password unencrypted."
        )
    if not parsed.hostname:
        raise AidpConfigError(
            f"Could not parse a hostname out of AIDP_ENDPOINT={endpoint!r}"
        )
    if parsed.username or parsed.password:
        raise AidpConfigError(
            "AIDP_ENDPOINT must not embed credentials; use AIDP_USERNAME/AIDP_PASSWORD."
        )

    username = os.environ.get("AIDP_USERNAME", "").strip()
    if not username:
        raise AidpConfigError("AIDP_USERNAME is not set")

    password = os.environ.get("AIDP_PASSWORD", "")
    if not password:
        raise AidpConfigError(
            "AIDP_PASSWORD is not set. Export it in your shell "
            '(export AIDP_PASSWORD="...") or put it in an uncommitted .env file.'
        )

    catalog = os.environ.get("AIDP_CATALOG", "").strip()
    schema = os.environ.get("AIDP_SCHEMA", "").strip()
    if not catalog or not schema:
        raise AidpConfigError("AIDP_CATALOG and AIDP_SCHEMA must both be set")

    verify_tls = _env_bool("AIDP_VERIFY_TLS", True)
    if not verify_tls:
        logger.warning(
            "TLS certificate verification is DISABLED (AIDP_VERIFY_TLS=false). "
            "This is acceptable for lab testing only - never for production data."
        )

    config = AidpConfig(
        endpoint=endpoint,
        host=parsed.hostname,
        port=parsed.port or 443,
        username=username,
        catalog=catalog,
        schema=schema,
        verify_tls=verify_tls,
        password=Secret(password),
        source=os.environ.get("AIDP_SOURCE", DEFAULT_SOURCE).strip() or DEFAULT_SOURCE,
        request_timeout=float(
            os.environ.get("AIDP_REQUEST_TIMEOUT", DEFAULT_REQUEST_TIMEOUT)
        ),
    )
    install_log_redaction(config)
    return config


def install_log_redaction(config: AidpConfig) -> None:
    """Attach a redacting filter to the root logger and common noisy loggers."""
    secret_filter = SecretRedactingFilter(config.password.reveal())
    for name in ("", "aidp", "trino", "pystarburst", "urllib3", "requests"):
        target = logging.getLogger(name)
        if not any(isinstance(f, SecretRedactingFilter) for f in target.filters):
            target.addFilter(secret_filter)


class AidpConnectionError(Exception):
    """A connection/authorisation failure, classified and safe to display."""

    def __init__(self, kind: str, message: str, remedy: str = "") -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.remedy = remedy

    def __str__(self) -> str:
        return f"{self.message} {self.remedy}".strip()


_STATUS_HINTS = {
    401: (
        "auth",
        "Authentication failed (HTTP 401): AIDP rejected the username/password.",
        "Re-check AIDP_USERNAME and re-export AIDP_PASSWORD.",
    ),
    403: (
        "authz",
        "Authorization failed (HTTP 403): the account authenticated but is not "
        "permitted to perform this operation.",
        "Ask an AIDP administrator to grant SELECT on the catalog/schema to this user or role.",
    ),
}


def _summarize_server_error(text: str, max_length: int = 240) -> str:
    """Reduce a Trino/Java error (often a multi-KB stack trace) to one line."""
    cleaned = text.replace("\\n", "\n").replace("\\t", "\t")
    for line in cleaned.splitlines():
        line = line.strip()
        if line and not line.startswith("at ") and not line.startswith("... "):
            summary = line
            break
    else:
        summary = cleaned.strip()
    summary = summary.rstrip("'\"")
    return summary[:max_length] + ("..." if len(summary) > max_length else "")


def classify_error(exc: BaseException) -> AidpConnectionError:
    """Map a low-level driver/network exception to a user-facing diagnosis."""
    if isinstance(exc, AidpConnectionError):
        return exc

    text = str(exc)

    # Starburst's Keycloak password authenticator surfaces a rejected credential
    # as HTTP 500 wrapping an internal 401, so match on the authenticator name
    # before falling through to the generic HTTP status handling.
    if "PasswordAuthenticator" in text or "KeycloakAuthenticator" in text:
        return AidpConnectionError(
            "auth",
            "Authentication failed: the AIDP coordinator's password authenticator "
            "(Keycloak) rejected these credentials.",
            "Re-check AIDP_USERNAME and re-export AIDP_PASSWORD. Note the coordinator "
            "reports this as HTTP 500 wrapping an internal 401.",
        )

    status = getattr(exc, "status_code", None) or getattr(
        getattr(exc, "response", None), "status_code", None
    )
    if status in _STATUS_HINTS:
        kind, message, remedy = _STATUS_HINTS[status]
        return AidpConnectionError(kind, message, remedy)

    try:
        import requests.exceptions as rex

        if isinstance(exc, rex.SSLError):
            return AidpConnectionError(
                "tls",
                "TLS certificate validation failed - the server certificate is not "
                "trusted by this machine's CA bundle.",
                "Install the lab CA certificate (e.g. REQUESTS_CA_BUNDLE=/path/ca.pem), "
                "or set AIDP_VERIFY_TLS=false for lab testing only.",
            )
        if isinstance(exc, (rex.ConnectTimeout, rex.ReadTimeout, rex.Timeout)):
            return AidpConnectionError(
                "timeout",
                "Connection timed out while talking to AIDP.",
                "Check VPN/firewall reachability of the coordinator, then retry.",
            )
        if isinstance(exc, rex.ConnectionError):
            if "NameResolution" in text or "nodename nor servname" in text:
                return AidpConnectionError(
                    "dns",
                    "DNS resolution failed for the AIDP hostname.",
                    "Verify AIDP_ENDPOINT and that this host can resolve it.",
                )
            return AidpConnectionError(
                "network",
                "Network error: could not establish a connection to AIDP.",
                "Check the endpoint host/port, VPN and firewall rules.",
            )
    except ImportError:  # pragma: no cover - requests ships with trino
        pass

    if isinstance(exc, socket.gaierror):
        return AidpConnectionError(
            "dns",
            "DNS resolution failed for the AIDP hostname.",
            "Verify AIDP_ENDPOINT and that this host can resolve it.",
        )
    if isinstance(exc, socket.timeout):
        return AidpConnectionError(
            "timeout", "Connection timed out while talking to AIDP.", ""
        )

    lowered = text.lower()
    if "does not exist" in lowered or "not found" in lowered:
        return AidpConnectionError(
            "missing_object",
            f"AIDP reported a missing catalog, schema or table: {_summarize_server_error(text)}",
            "Confirm AIDP_CATALOG/AIDP_SCHEMA and that the tables have been created.",
        )
    if "access denied" in lowered or "permission denied" in lowered:
        return AidpConnectionError(
            "authz",
            f"Access denied by AIDP RBAC: {_summarize_server_error(text)}",
            "Ask an administrator to grant read access to this user or role.",
        )
    if "certificate" in lowered:
        return AidpConnectionError(
            "tls",
            f"TLS certificate problem: {_summarize_server_error(text)}",
            "Install the lab CA bundle, or set AIDP_VERIFY_TLS=false for lab testing only.",
        )
    if "authentication" in lowered or "unauthorized" in lowered:
        return AidpConnectionError(
            "auth",
            f"Authentication failed: {_summarize_server_error(text)}",
            "Re-check AIDP_USERNAME/AIDP_PASSWORD.",
        )

    return AidpConnectionError(
        "unknown", f"Unexpected AIDP error: {_summarize_server_error(text)}", ""
    )


def check_pystarburst_api() -> tuple[str, list[str]]:
    """Return the installed PyStarburst version and any API incompatibilities."""
    try:
        import pystarburst
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise AidpConnectionError(
            "version",
            "PyStarburst is not installed.",
            "pip install -r requirements.txt",
        ) from exc

    version = getattr(pystarburst, "__version__", "unknown")
    problems: list[str] = []
    from pystarburst import DataFrame, Session

    builder = getattr(Session, "builder", None)
    if builder is None or not hasattr(type(builder), "configs"):
        problems.append(
            "Session.builder.configs() is unavailable in this PyStarburst version."
        )
    for method in ("table", "sql"):
        if not hasattr(Session, method):
            problems.append(f"Session.{method}() is unavailable.")
    for method in ("filter", "group_by", "order_by", "limit", "to_pandas", "queries"):
        if not hasattr(DataFrame, method):
            problems.append(f"DataFrame.{method} is unavailable.")
    return version, problems


_models_rebuilt = False


def ensure_pystarburst_models_built() -> int:
    """Work around a PyStarburst 0.14.1 / pydantic 2.12.5 packaging bug.

    PyStarburst serialises its logical plans with pydantic models that use forward
    references, and ``pystarburst/__init__.py`` calls ``model_rebuild()`` on a
    hand-curated list of them.  That list is incomplete for the pydantic version
    PyStarburst itself pins (``pydantic>=2.12.5,<2.13``): base classes such as
    ``Expression``, ``LogicalPlan``, ``DataType`` and ~50 others are left
    incomplete, and every DataFrame operation then dies with::

        TypeError: 'MockValSer' object cannot be converted to 'SchemaSerializer'

    Importing every submodule and rebuilding whatever is still incomplete fixes
    it.  Safe and idempotent: completed models are skipped, and this only
    finalises type resolution that PyStarburst intended to do itself.

    Returns the number of models rebuilt.
    """
    global _models_rebuilt
    if _models_rebuilt:
        return 0

    import importlib
    import pkgutil

    import pydantic
    import pystarburst

    for module in pkgutil.walk_packages(pystarburst.__path__, "pystarburst."):
        try:
            importlib.import_module(module.name)
        except Exception:  # noqa: BLE001 - optional/mock submodules may not import
            logger.debug("Skipping unimportable PyStarburst module %s", module.name)

    rebuilt = 0
    seen: set[type] = set()

    def walk(cls: type) -> None:
        nonlocal rebuilt
        for subclass in cls.__subclasses__():
            if subclass in seen:
                continue
            seen.add(subclass)
            if not getattr(subclass, "__pydantic_complete__", True):
                try:
                    subclass.model_rebuild(raise_errors=True, _parent_namespace_depth=0)
                    rebuilt += 1
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Could not rebuild %s: %s", subclass.__name__, exc)
            walk(subclass)

    walk(pydantic.BaseModel)
    _models_rebuilt = True
    if rebuilt:
        logger.info(
            "Rebuilt %d incomplete PyStarburst pydantic model(s) "
            "(known pystarburst 0.14.1 + pydantic 2.12.x issue)",
            rebuilt,
        )
    return rebuilt


def _connect_options(config: AidpConfig) -> dict:
    """Build the driver options shared by PyStarburst and the raw Trino client."""
    from trino.auth import BasicAuthentication

    return {
        "host": config.host,
        "port": config.port,
        "http_scheme": "https",
        "auth": BasicAuthentication(config.username, config.password.reveal()),
        "catalog": config.catalog,
        "schema": config.schema,
        "verify": config.verify_tls,
        "request_timeout": config.request_timeout,
    }


def create_trino_connection(config: AidpConfig | None = None):
    """Create a raw Trino DBAPI connection.

    Used **only** as a fallback when PyStarburst's server-side DataFrame plan
    analyzer is unavailable on the cluster (see README "PyStarburst fallbacks").
    """
    config = config or load_config()
    from trino.dbapi import connect

    options = _connect_options(config)
    options["source"] = config.source
    try:
        return connect(**options)
    except BaseException as exc:  # noqa: BLE001
        raise classify_error(exc) from None


def create_session(config: AidpConfig | None = None):
    """Create an authenticated PyStarburst :class:`~pystarburst.Session`.

    Uses HTTPS + LDAP/password (HTTP Basic) authentication.  Raises
    :class:`AidpConnectionError` with an actionable, credential-free message.
    """
    config = config or load_config()
    version, problems = check_pystarburst_api()
    if problems:
        raise AidpConnectionError(
            "version",
            f"PyStarburst {version} is missing APIs this app relies on: "
            + "; ".join(problems),
            "Pin the version from requirements.txt (pystarburst==0.14.1).",
        )

    from pystarburst import Session

    ensure_pystarburst_models_built()

    if not config.verify_tls:
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:  # pragma: no cover
            pass
        logger.warning("Connecting with TLS verification disabled - lab testing only.")

    options = _connect_options(config)

    logger.info(
        "Connecting to AIDP at %s as %s (catalog=%s schema=%s verify_tls=%s)",
        config.safe_target,
        config.username,
        config.catalog,
        config.schema,
        config.verify_tls,
    )
    try:
        # .config("source", ...) must come *after* .configs(): configs() forces
        # source="PyStarburst", so an earlier value would be overwritten.
        session = (
            Session.builder.configs(options).config("source", config.source).create()
        )
        # Force a round trip so authentication/TLS problems surface here rather
        # than on the first user query.
        session.sql("SELECT 1").collect()
    except BaseException as exc:  # noqa: BLE001 - re-raised as a classified error
        raise classify_error(exc) from None
    logger.info("Connected to AIDP (PyStarburst %s)", version)
    return session
