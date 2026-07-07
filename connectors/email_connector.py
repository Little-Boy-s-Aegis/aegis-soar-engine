import logging
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from secret_manager import secrets

logger = logging.getLogger("soar-engine.connectors.email")


class EmailConnector:
    """SMTP Email Connector for sending security alert and recovery notification emails."""

    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "mock-smtp-host")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "soc-alerts@company.com")
        self.smtp_password = secrets.get_secret("SMTP_PASSWORD", "mock-smtp-password")
        self.email_from = os.getenv("EMAIL_FROM", "soc-alerts@company.com")
        self.email_to_soc = os.getenv("EMAIL_TO_SOC", "soc-team@company.com")

    def _is_simulation(self) -> bool:
        """Returns True if running in simulation/mock mode."""
        return self.smtp_host == "mock-smtp-host"

    def _get_recipients(self, recipients: list = None) -> list:
        """Returns the recipient list, defaulting to the SOC team email."""
        if recipients:
            return recipients
        return [addr.strip() for addr in self.email_to_soc.split(",") if addr.strip()]

    def _build_html_template(self, title: str, content: str, severity: str) -> str:
        """
        Builds a styled HTML email template for security notifications.
        Returns the complete HTML string.
        """
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
            "recovery": "#28a745",
        }
        color = severity_colors.get(severity.lower(), "#6c757d")

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }}
        .container {{ max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .header {{ background-color: {color}; color: #ffffff; padding: 20px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 22px; }}
        .header .severity {{ font-size: 14px; text-transform: uppercase; letter-spacing: 1px; margin-top: 5px; }}
        .body {{ padding: 20px 30px; color: #333333; line-height: 1.6; }}
        .footer {{ padding: 15px 30px; background-color: #f8f9fa; font-size: 12px; color: #888888; text-align: center; border-top: 1px solid #e9ecef; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{title}</h1>
            <div class="severity">Severity: {severity.upper()}</div>
        </div>
        <div class="body">
            {content}
        </div>
        <div class="footer">
            Aegis SOAR Engine &mdash; Automated Security Notification<br>
            This is an automated message. Do not reply directly.
        </div>
    </div>
</body>
</html>"""
        return html

    def send_alert_email(
        self, subject: str, body_html: str, recipients: list = None
    ) -> tuple[bool, str]:
        """
        Sends an HTML-formatted security alert email.
        Returns (success, message).
        """
        to_list = self._get_recipients(recipients)
        logger.info(f"[EMAIL] Sending alert email: '{subject}' to {to_list}")

        if self._is_simulation():
            logger.info(
                f"[EMAIL-SIMULATION] Alert email sent to {to_list}: {subject}"
            )
            return True, f"[SIMULATION] Alert email sent to {to_list}: {subject}"

        return self._send_email(subject, body_html, to_list)

    def send_recovery_email(
        self, subject: str, body_html: str, recipients: list = None
    ) -> tuple[bool, str]:
        """
        Sends an HTML-formatted recovery notification email.
        Returns (success, message).
        """
        to_list = self._get_recipients(recipients)
        logger.info(f"[EMAIL] Sending recovery email: '{subject}' to {to_list}")

        if self._is_simulation():
            logger.info(
                f"[EMAIL-SIMULATION] Recovery email sent to {to_list}: {subject}"
            )
            return True, f"[SIMULATION] Recovery email sent to {to_list}: {subject}"

        return self._send_email(subject, body_html, to_list)

    def _send_email(self, subject: str, body_html: str, to_list: list) -> tuple[bool, str]:
        """
        Internal helper to send an email via SMTP with TLS.
        Returns (success, message).
        """
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.email_from
            msg["To"] = ", ".join(to_list)

            html_part = MIMEText(body_html, "html")
            msg.attach(html_part)

            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.email_from, to_list, msg.as_string())

            logger.info(f"[EMAIL] Email sent successfully: {subject}")
            return True, f"Email sent successfully to {to_list}: {subject}"

        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"[EMAIL ERROR] SMTP authentication failed: {e}")
            return False, f"SMTP authentication failed: {str(e)}"
        except smtplib.SMTPException as e:
            logger.error(f"[EMAIL ERROR] SMTP error: {e}")
            return False, f"SMTP error: {str(e)}"
        except Exception as e:
            logger.error(f"[EMAIL ERROR] Failed to send email: {e}")
            return False, f"Email connection error: {str(e)}"
