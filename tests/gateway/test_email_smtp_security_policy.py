"""Unit tests for the shared SMTP security policy helper."""

from unittest.mock import MagicMock

import pytest

from gateway.email_smtp import (
    normalize_smtp_security,
    open_smtp_connection,
    resolve_smtp_security,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, "auto"),
        ("", "auto"),
        ("   ", "auto"),
        ("AUTO", "auto"),
        ("StartTLS", "starttls"),
        ("start_tls", "starttls"),
        ("start-tls", "starttls"),
        ("IMPLICIT_TLS", "implicit_tls"),
        ("implicit-tls", "implicit_tls"),
        ("SMTPS", "implicit_tls"),
        ("smtp_ssl", "implicit_tls"),
    ],
)
def test_normalize_smtp_security_accepts_canonical_values_and_limited_aliases(raw, expected):
    assert normalize_smtp_security(raw) == expected


@pytest.mark.parametrize("raw", ["tls", "ssl", "none", "plain", "plaintext", "no_tls", "off", "false", "true", "bogus"])
def test_normalize_smtp_security_rejects_ambiguous_or_plaintext_modes(raw):
    with pytest.raises(ValueError) as exc_info:
        normalize_smtp_security(raw)

    message = str(exc_info.value)
    assert "EMAIL_SMTP_SECURITY" in message
    assert raw in message
    assert "auto" in message
    assert "starttls" in message
    assert "implicit_tls" in message


@pytest.mark.parametrize(
    ("port", "raw", "expected"),
    [
        (465, None, "implicit_tls"),
        (465, "auto", "implicit_tls"),
        (587, None, "starttls"),
        (2525, "auto", "starttls"),
        (465, "starttls", "starttls"),
        (587, "implicit_tls", "implicit_tls"),
        (2525, "smtps", "implicit_tls"),
    ],
)
def test_resolve_smtp_security_maps_auto_by_port_and_respects_explicit_overrides(port, raw, expected):
    assert resolve_smtp_security(port, raw) == expected


def test_open_smtp_connection_closes_starttls_connection_when_upgrade_fails():
    smtp_module = MagicMock()
    server = MagicMock()
    smtp_module.SMTP.return_value = server
    server.starttls.side_effect = RuntimeError("starttls failed")
    tls_context = object()

    with pytest.raises(RuntimeError, match="starttls failed"):
        open_smtp_connection(
            "smtp.test.com",
            587,
            raw_mode="starttls",
            timeout=30,
            smtp_module=smtp_module,
            context_factory=lambda: tls_context,
        )

    smtp_module.SMTP.assert_called_once_with("smtp.test.com", 587, timeout=30)
    smtp_module.SMTP_SSL.assert_not_called()
    server.starttls.assert_called_once_with(context=tls_context)
    server.quit.assert_called_once()
