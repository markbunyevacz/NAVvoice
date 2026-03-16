"""
Tests for email_backend.py -- EmailBackend ABC, concrete backends, and factory.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from email_backend import (
    EmailBackend,
    EmailBackendConfig,
    GmailSMTPBackend,
    GmailSMTPConfig,
    SendGridBackend,
    SendGridConfig,
    AmazonSESBackend,
    AmazonSESConfig,
    create_email_backend,
)


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def gmail_config_dry():
    return GmailSMTPConfig(
        sender_email="test@gmail.com",
        sender_password="app-password",
        dry_run=True,
    )


@pytest.fixture
def gmail_config_live():
    return GmailSMTPConfig(
        sender_email="test@gmail.com",
        sender_password="app-password",
        dry_run=False,
    )


@pytest.fixture
def gmail_backend_dry(gmail_config_dry):
    return GmailSMTPBackend(gmail_config_dry)


# =============================================================================
# GmailSMTPConfig
# =============================================================================


class TestGmailSMTPConfig:

    def test_defaults(self):
        cfg = GmailSMTPConfig()
        assert cfg.smtp_server == "smtp.gmail.com"
        assert cfg.smtp_port == 587
        assert cfg.use_tls is True
        assert cfg.dry_run is False

    def test_custom_values(self):
        cfg = GmailSMTPConfig(
            smtp_server="mail.example.com",
            smtp_port=465,
            sender_email="a@b.com",
            sender_password="pw",
            use_tls=False,
            dry_run=True,
        )
        assert cfg.smtp_server == "mail.example.com"
        assert cfg.smtp_port == 465
        assert cfg.dry_run is True


# =============================================================================
# GmailSMTPBackend
# =============================================================================


class TestGmailSMTPBackend:

    def test_dry_run_returns_success(self, gmail_backend_dry):
        result = gmail_backend_dry.send(
            "vendor@example.com", "Subject", "Body",
        )
        assert result["success"] is True
        assert result["dry_run"] is True
        assert result["to"] == "vendor@example.com"
        assert result["subject"] == "Subject"

    def test_dry_run_with_cc(self, gmail_backend_dry):
        result = gmail_backend_dry.send(
            "a@b.com", "Subj", "Body",
            cc=["cc@b.com"],
        )
        assert result["success"] is True

    @patch("email_backend.smtplib.SMTP")
    def test_smtp_send_success(self, mock_smtp, gmail_config_live):
        backend = GmailSMTPBackend(gmail_config_live)
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        result = backend.send(
            "vendor@example.com", "Subject", "Body",
        )

        assert result["success"] is True
        assert "sent_at" in result
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with(
            "test@gmail.com", "app-password",
        )
        mock_server.sendmail.assert_called_once()

    @patch("email_backend.smtplib.SMTP")
    def test_smtp_send_with_cc_and_reply_to(
        self, mock_smtp, gmail_config_live,
    ):
        backend = GmailSMTPBackend(gmail_config_live)
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        result = backend.send(
            "to@example.com", "Subj", "Body",
            cc=["cc1@ex.com", "cc2@ex.com"],
            reply_to="reply@ex.com",
        )

        assert result["success"] is True
        recipients = mock_server.sendmail.call_args[0][1]
        assert "to@example.com" in recipients
        assert "cc1@ex.com" in recipients
        assert "cc2@ex.com" in recipients

    @patch("email_backend.smtplib.SMTP")
    def test_smtp_auth_error(self, mock_smtp, gmail_config_live):
        import smtplib as _smtplib

        backend = GmailSMTPBackend(gmail_config_live)
        mock_server = MagicMock()
        mock_server.login.side_effect = (
            _smtplib.SMTPAuthenticationError(535, "Bad credentials")
        )
        mock_smtp.return_value.__enter__.return_value = mock_server

        result = backend.send("a@b.com", "Subj", "Body")

        assert result["success"] is False
        assert "Authentication failed" in result["error"]

    @patch("email_backend.smtplib.SMTP")
    def test_smtp_generic_error(self, mock_smtp, gmail_config_live):
        import smtplib as _smtplib

        backend = GmailSMTPBackend(gmail_config_live)
        mock_server = MagicMock()
        mock_server.login.side_effect = (
            _smtplib.SMTPException("Connection refused")
        )
        mock_smtp.return_value.__enter__.return_value = mock_server

        result = backend.send("a@b.com", "Subj", "Body")

        assert result["success"] is False
        assert "SMTP error" in result["error"]

    @patch("email_backend.smtplib.SMTP")
    def test_smtp_unexpected_error(
        self, mock_smtp, gmail_config_live,
    ):
        backend = GmailSMTPBackend(gmail_config_live)
        mock_server = MagicMock()
        mock_server.login.side_effect = OSError("timeout")
        mock_smtp.return_value.__enter__.return_value = mock_server

        result = backend.send("a@b.com", "Subj", "Body")

        assert result["success"] is False
        assert "timeout" in result["error"]

    @patch("email_backend.smtplib.SMTP")
    def test_no_tls_when_disabled(self, mock_smtp):
        cfg = GmailSMTPConfig(
            sender_email="a@b.com",
            sender_password="pw",
            use_tls=False,
            dry_run=False,
        )
        backend = GmailSMTPBackend(cfg)
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        backend.send("to@b.com", "Subj", "Body")

        mock_server.starttls.assert_not_called()


# =============================================================================
# SendGridBackend (Phase 3 stub)
# =============================================================================


class TestSendGridBackend:

    def test_raises_not_implemented(self):
        cfg = SendGridConfig(api_key="sg-key")
        backend = SendGridBackend(cfg)
        with pytest.raises(NotImplementedError, match="Phase 3"):
            backend.send("a@b.com", "Subj", "Body")

    def test_dry_run_succeeds(self):
        cfg = SendGridConfig(api_key="sg-key", dry_run=True)
        backend = SendGridBackend(cfg)
        result = backend.send("a@b.com", "Subj", "Body")
        assert result["success"] is True
        assert result["dry_run"] is True


# =============================================================================
# AmazonSESBackend (Phase 3 stub)
# =============================================================================


class TestAmazonSESBackend:

    def test_raises_not_implemented(self):
        cfg = AmazonSESConfig(sender_email="a@b.com")
        backend = AmazonSESBackend(cfg)
        with pytest.raises(NotImplementedError, match="Phase 3"):
            backend.send("to@b.com", "Subj", "Body")

    def test_dry_run_succeeds(self):
        cfg = AmazonSESConfig(
            sender_email="a@b.com", dry_run=True,
        )
        backend = AmazonSESBackend(cfg)
        result = backend.send("to@b.com", "Subj", "Body")
        assert result["success"] is True
        assert result["dry_run"] is True


# =============================================================================
# create_email_backend factory
# =============================================================================


class TestCreateEmailBackend:

    def test_gmail(self):
        b = create_email_backend(
            "gmail",
            sender_email="x@gmail.com",
            sender_password="pw",
            dry_run=True,
        )
        assert isinstance(b, GmailSMTPBackend)

    def test_sendgrid(self):
        b = create_email_backend(
            "sendgrid", api_key="sg-key", dry_run=True,
        )
        assert isinstance(b, SendGridBackend)

    def test_ses(self):
        b = create_email_backend(
            "ses", sender_email="a@b.com", dry_run=True,
        )
        assert isinstance(b, AmazonSESBackend)

    def test_unknown_backend_raises(self):
        with pytest.raises(ValueError, match="Unknown email backend"):
            create_email_backend("mailchimp")

    def test_case_insensitive(self):
        b = create_email_backend("Gmail", dry_run=True)
        assert isinstance(b, GmailSMTPBackend)

    def test_ignores_unknown_kwargs(self):
        b = create_email_backend(
            "gmail",
            sender_email="x@g.com",
            sender_password="p",
            nonexistent_field="ignored",
            dry_run=True,
        )
        assert isinstance(b, GmailSMTPBackend)
