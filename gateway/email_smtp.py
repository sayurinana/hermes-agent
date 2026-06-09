"""Shared SMTP security policy for Hermes email senders."""

from __future__ import annotations

import smtplib
import ssl
from collections.abc import Callable
from typing import Literal

SmtpSecuritySetting = Literal["auto", "starttls", "implicit_tls"]
SmtpConnectionMode = Literal["starttls", "implicit_tls"]

SMTP_SECURITY_ENV = "EMAIL_SMTP_SECURITY"
SMTP_TIMEOUT_SECONDS = 30

_CANONICAL_VALUES: tuple[SmtpSecuritySetting, ...] = ("auto", "starttls", "implicit_tls")
_SMTP_SECURITY_ALIASES: dict[str, SmtpSecuritySetting] = {
    "start_tls": "starttls",
    "start-tls": "starttls",
    "implicit-tls": "implicit_tls",
    "smtps": "implicit_tls",
    "smtp_ssl": "implicit_tls",
}


def normalize_smtp_security(raw_mode: str | None) -> SmtpSecuritySetting:
    """Return the canonical EMAIL_SMTP_SECURITY setting.

    Missing, empty, or whitespace-only values default to ``auto``.  Explicit
    values are case-insensitive, but only the documented aliases are accepted;
    ambiguous values such as ``tls`` and ``ssl`` fail instead of guessing.
    """
    if raw_mode is None:
        return "auto"

    normalized = raw_mode.strip().lower()
    if not normalized:
        return "auto"

    if normalized in _CANONICAL_VALUES:
        return normalized  # type: ignore[return-value]

    alias = _SMTP_SECURITY_ALIASES.get(normalized)
    if alias is not None:
        return alias

    allowed = ", ".join(_CANONICAL_VALUES)
    aliases = ", ".join(_SMTP_SECURITY_ALIASES)
    raise ValueError(
        f"Invalid {SMTP_SECURITY_ENV}={raw_mode!r}. Expected one of: {allowed} "
        f"(aliases: {aliases}). Ambiguous tls/ssl and plaintext/no TLS modes "
        "are not supported."
    )


def resolve_smtp_security(port: int, raw_mode: str | None = None) -> SmtpConnectionMode:
    """Resolve EMAIL_SMTP_SECURITY plus port into an SMTP connection mode."""
    mode = normalize_smtp_security(raw_mode)
    if mode == "auto":
        return "implicit_tls" if int(port) == 465 else "starttls"
    return mode


def open_smtp_connection(
    host: str,
    port: int,
    raw_mode: str | None = None,
    *,
    timeout: int = SMTP_TIMEOUT_SECONDS,
    smtp_module=smtplib,
    context_factory: Callable[[], ssl.SSLContext] = ssl.create_default_context,
):
    """Open an SMTP connection according to the shared security policy.

    Validation happens before constructing SMTP objects so invalid explicit
    EMAIL_SMTP_SECURITY values never silently fall back or open a network
    connection.  Returned objects are ready for login/send/quit by callers.
    """
    mode = resolve_smtp_security(port, raw_mode)
    context = context_factory()

    if mode == "implicit_tls":
        return smtp_module.SMTP_SSL(host, port, timeout=timeout, context=context)

    smtp = smtp_module.SMTP(host, port, timeout=timeout)
    try:
        smtp.starttls(context=context)
    except Exception:
        try:
            smtp.quit()
        except Exception:
            smtp.close()
        raise
    return smtp
