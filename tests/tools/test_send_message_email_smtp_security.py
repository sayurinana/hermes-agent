"""Tests for EMAIL_SMTP_SECURITY in the one-shot email send_message path."""

import asyncio
import os
from unittest.mock import MagicMock, patch

from tools.send_message_tool import _send_email


def _email_env(*, port: int, security: str | None = None):
    env = {
        "EMAIL_ADDRESS": "hermes@test.com",
        "EMAIL_PASSWORD": "secret",
        "EMAIL_SMTP_HOST": "smtp.test.com",
        "EMAIL_SMTP_PORT": str(port),
    }
    if security is not None:
        env["EMAIL_SMTP_SECURITY"] = security
    return env


def _email_extra():
    return {"address": "hermes@test.com", "smtp_host": "smtp.test.com"}


def _run_send():
    return asyncio.run(_send_email(_email_extra(), "user@test.com", "hello"))


def _assert_one_shot_uses_starttls(*, port: int, security: str | None = None):
    tls_context = object()
    with patch.dict(os.environ, _email_env(port=port, security=security), clear=True), \
         patch("tools.send_message_tool.ssl.create_default_context", return_value=tls_context), \
         patch("smtplib.SMTP") as mock_smtp, \
         patch("smtplib.SMTP_SSL") as mock_smtp_ssl:
        mock_server = MagicMock()
        mock_smtp.return_value = mock_server

        result = _run_send()

    assert result["success"] is True
    assert mock_smtp.call_count == 1
    assert mock_smtp.call_args.args == ("smtp.test.com", port)
    mock_smtp_ssl.assert_not_called()
    mock_server.starttls.assert_called_once_with(context=tls_context)
    mock_server.login.assert_called_once_with("hermes@test.com", "secret")
    mock_server.send_message.assert_called_once()
    mock_server.quit.assert_called_once()


def _assert_one_shot_uses_implicit_tls(*, port: int, security: str | None = None):
    tls_context = object()
    with patch.dict(os.environ, _email_env(port=port, security=security), clear=True), \
         patch("tools.send_message_tool.ssl.create_default_context", return_value=tls_context), \
         patch("smtplib.SMTP") as mock_smtp, \
         patch("smtplib.SMTP_SSL") as mock_smtp_ssl:
        mock_server = MagicMock()
        mock_smtp_ssl.return_value = mock_server

        result = _run_send()

    assert result["success"] is True
    mock_smtp.assert_not_called()
    mock_smtp_ssl.assert_called_once_with(
        "smtp.test.com", port, timeout=30, context=tls_context
    )
    mock_server.starttls.assert_not_called()
    mock_server.login.assert_called_once_with("hermes@test.com", "secret")
    mock_server.send_message.assert_called_once()
    mock_server.quit.assert_called_once()


def test_unset_security_uses_smtp_ssl_for_port_465():
    _assert_one_shot_uses_implicit_tls(port=465)


def test_auto_security_uses_smtp_ssl_for_port_465():
    _assert_one_shot_uses_implicit_tls(port=465, security="auto")


def test_unset_security_uses_starttls_for_port_587():
    _assert_one_shot_uses_starttls(port=587)


def test_auto_security_uses_starttls_for_non_465_port():
    _assert_one_shot_uses_starttls(port=2525, security="auto")


def test_explicit_starttls_uses_starttls_even_on_port_465():
    _assert_one_shot_uses_starttls(port=465, security="starttls")


def test_starttls_connection_uses_timeout_to_avoid_long_hang():
    with patch.dict(os.environ, _email_env(port=587), clear=True), \
         patch("smtplib.SMTP") as mock_smtp, \
         patch("smtplib.SMTP_SSL") as mock_smtp_ssl:
        mock_smtp.return_value = MagicMock()

        result = _run_send()

    assert result["success"] is True
    mock_smtp.assert_called_once_with("smtp.test.com", 587, timeout=30)
    mock_smtp_ssl.assert_not_called()


def test_explicit_implicit_tls_uses_smtp_ssl_even_on_non_465_port():
    _assert_one_shot_uses_implicit_tls(port=587, security="implicit_tls")


def test_invalid_security_fails_clearly_without_connecting_smtp():
    with patch.dict(os.environ, _email_env(port=587, security="bogus"), clear=True), \
         patch("smtplib.SMTP") as mock_smtp, \
         patch("smtplib.SMTP_SSL") as mock_smtp_ssl:
        try:
            result = _run_send()
        except Exception as exc:  # clear config-time failure is acceptable
            error_text = str(exc)
        else:
            assert "error" in result
            error_text = result["error"]

    assert "EMAIL_SMTP_SECURITY" in error_text
    assert "bogus" in error_text
    mock_smtp.assert_not_called()
    mock_smtp_ssl.assert_not_called()


def test_smtps_alias_uses_implicit_tls():
    _assert_one_shot_uses_implicit_tls(port=2525, security="smtps")


def test_start_tls_alias_uses_starttls():
    _assert_one_shot_uses_starttls(port=465, security="start_tls")
