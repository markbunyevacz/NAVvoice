"""
Email Backend Strategy Pattern

Provides pluggable email sending backends for the NAVvoice mailer.

Backends:
- GmailSMTPBackend: Gmail App Password over SMTP (MVP)
- SendGridBackend: SendGrid Web API (Phase 3)
- AmazonSESBackend: AWS SES (Phase 3)

Usage:
    backend = create_email_backend("gmail", sender_email="x@gmail.com",
                                   sender_password="app-password")
    result = backend.send("vendor@example.com", "Subject", "Body")
"""

import logging
import smtplib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION DATACLASSES
# =============================================================================


@dataclass
class EmailBackendConfig:
    """Base configuration shared by all email backends."""
    sender_email: str = ""
    sender_name: str = "NAV Invoice System"
    dry_run: bool = False


@dataclass
class GmailSMTPConfig(EmailBackendConfig):
    """Gmail SMTP configuration (App Password required)."""
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    sender_password: str = ""
    use_tls: bool = True


@dataclass
class SendGridConfig(EmailBackendConfig):
    """SendGrid Web API configuration (Phase 3)."""
    api_key: str = ""


@dataclass
class AmazonSESConfig(EmailBackendConfig):
    """Amazon SES configuration (Phase 3)."""
    aws_region: str = "eu-central-1"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""


# =============================================================================
# ABSTRACT BACKEND
# =============================================================================


class EmailBackend(ABC):
    """Abstract base for email delivery backends."""

    @abstractmethod
    def send(
        self,
        to: str,
        subject: str,
        body: str,
        cc: Optional[List[str]] = None,
        reply_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Send a single email.

        Returns:
            Dict with at least ``success: bool``. On success may include
            ``to``, ``subject``, ``sent_at``. On failure includes ``error``.
        """
        ...  # pragma: no cover


# =============================================================================
# GMAIL SMTP BACKEND (MVP)
# =============================================================================


class GmailSMTPBackend(EmailBackend):
    """Sends email via Gmail SMTP with App Password authentication."""

    def __init__(self, config: GmailSMTPConfig):
        self.config = config

    def send(
        self,
        to: str,
        subject: str,
        body: str,
        cc: Optional[List[str]] = None,
        reply_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        msg = MIMEMultipart()
        msg["From"] = f"{self.config.sender_name} <{self.config.sender_email}>"
        msg["To"] = to
        msg["Subject"] = subject

        if cc:
            msg["Cc"] = ", ".join(cc)
        if reply_to:
            msg["Reply-To"] = reply_to

        msg.attach(MIMEText(body, "plain", "utf-8"))

        if self.config.dry_run:
            logger.info("[DRY RUN] Would send email to %s: %s", to, subject)
            return {
                "success": True,
                "dry_run": True,
                "to": to,
                "subject": subject,
            }

        try:
            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port) as server:
                if self.config.use_tls:
                    server.starttls()
                server.login(self.config.sender_email, self.config.sender_password)
                recipients = [to] + (cc or [])
                server.sendmail(self.config.sender_email, recipients, msg.as_string())

            logger.info("Email sent to %s: %s", to, subject)
            return {
                "success": True,
                "to": to,
                "subject": subject,
                "sent_at": datetime.now().isoformat(),
            }
        except smtplib.SMTPAuthenticationError as e:
            logger.error("SMTP auth failed: %s", e)
            return {
                "success": False,
                "error": "Authentication failed. Check email/password.",
                "details": str(e),
            }
        except smtplib.SMTPException as e:
            logger.error("SMTP error: %s", e)
            return {"success": False, "error": f"SMTP error: {e}"}
        except Exception as e:
            logger.error("Email send failed: %s", e)
            return {"success": False, "error": str(e)}


# =============================================================================
# SENDGRID BACKEND (Phase 3 stub)
# =============================================================================


class SendGridBackend(EmailBackend):
    """SendGrid Web API backend -- available in Phase 3."""

    def __init__(self, config: SendGridConfig):
        self.config = config

    def send(
        self,
        to: str,
        subject: str,
        body: str,
        cc: Optional[List[str]] = None,
        reply_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        if self.config.dry_run:
            logger.info("[DRY RUN] SendGrid would send to %s: %s", to, subject)
            return {"success": True, "dry_run": True, "to": to, "subject": subject}
        raise NotImplementedError(
            "SendGrid backend is planned for Phase 3. "
            "Set dry_run=True to test email flow without sending."
        )


# =============================================================================
# AMAZON SES BACKEND (Phase 3 stub)
# =============================================================================


class AmazonSESBackend(EmailBackend):
    """Amazon SES backend -- available in Phase 3."""

    def __init__(self, config: AmazonSESConfig):
        self.config = config

    def send(
        self,
        to: str,
        subject: str,
        body: str,
        cc: Optional[List[str]] = None,
        reply_to: Optional[str] = None,
    ) -> Dict[str, Any]:
        if self.config.dry_run:
            logger.info("[DRY RUN] SES would send to %s: %s", to, subject)
            return {"success": True, "dry_run": True, "to": to, "subject": subject}
        raise NotImplementedError(
            "Amazon SES backend is planned for Phase 3. "
            "Set dry_run=True to test email flow without sending."
        )


# =============================================================================
# FACTORY
# =============================================================================

_BACKEND_REGISTRY: Dict[str, type] = {
    "gmail": GmailSMTPBackend,
    "sendgrid": SendGridBackend,
    "ses": AmazonSESBackend,
}

_CONFIG_REGISTRY: Dict[str, type] = {
    "gmail": GmailSMTPConfig,
    "sendgrid": SendGridConfig,
    "ses": AmazonSESConfig,
}


def create_email_backend(backend_type: str, **kwargs: Any) -> EmailBackend:
    """
    Factory: build an ``EmailBackend`` from a type name and keyword config.

    Args:
        backend_type: One of ``"gmail"``, ``"sendgrid"``, ``"ses"``.
        **kwargs: Passed to the corresponding config dataclass.

    Raises:
        ValueError: Unknown backend type.
    """
    backend_type = backend_type.lower().strip()
    if backend_type not in _BACKEND_REGISTRY:
        supported = ", ".join(sorted(_BACKEND_REGISTRY))
        raise ValueError(
            f"Unknown email backend '{backend_type}'. Supported: {supported}"
        )
    config_cls = _CONFIG_REGISTRY[backend_type]
    valid_fields = {f.name for f in config_cls.__dataclass_fields__.values()}
    filtered = {k: v for k, v in kwargs.items() if k in valid_fields}
    config = config_cls(**filtered)
    return _BACKEND_REGISTRY[backend_type](config)
