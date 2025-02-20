# File: email_sender.py
"""
This module sends invoice emails using SMTP with detailed logging.
It expects invoice payload fields for base64-encoded subject and body.
"""

import base64
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def send_invoice_email(invoice_payload):
    """
    Sends an invoice email using SMTP.
    Expects the invoice_payload to contain emailConfig details.
    """
    try:
        email_config = invoice_payload.get("emailConfig", {})

        # Completely remove static environment variable fallbacks.
        mail_from = email_config.get("mailFrom")
        if not mail_from:
            raise ValueError("mailFrom is missing in the invoice payload.")

        password = email_config.get("password")
        if not password:
            raise ValueError("password is missing in the invoice payload.")

        smtp_server = email_config.get("smtpServer")
        if not smtp_server:
            raise ValueError("smtpServer is missing in the invoice payload.")

        smtp_port = email_config.get("smtpPort")
        if not smtp_port:
            raise ValueError("smtpPort is missing in the invoice payload.")

        use_tls = email_config.get("useTLS")
        if use_tls is None:
            raise ValueError("useTLS is missing in the invoice payload.")

        recipient = invoice_payload.get("to")
        if not recipient:
            raise ValueError("Recipient email is missing in payload.")

        subject_encoded = invoice_payload.get("subject", "")
        body_text_encoded = invoice_payload.get("bodyText", "")
        if not subject_encoded or not body_text_encoded:
            raise ValueError("Email subject or body is missing.")

        logger.debug("Decoding email subject and body.")
        subject = base64.b64decode(subject_encoded).decode("utf-8")
        body_text = base64.b64decode(body_text_encoded).decode("utf-8")

        msg = MIMEMultipart()
        msg["From"] = mail_from
        msg["To"] = recipient
        msg["Subject"] = subject
        msg.attach(MIMEText(body_text, "plain"))

        logger.debug("Connecting to SMTP server: %s:%s", smtp_server, smtp_port)
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        server.ehlo()
        if use_tls:
            server.starttls()
            server.ehlo()
        logger.debug("Logging in as %s.", mail_from)
        server.login(mail_from, password)
        server.sendmail(mail_from, recipient, msg.as_string())
        server.quit()
        logger.info("Invoice email sent successfully to %s.", recipient)
        return True
    except Exception as e:
        logger.exception("Failed to send invoice email: %s", e)
        raise
