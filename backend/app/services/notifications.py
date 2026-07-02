"""
Notification delivery layer. Two channels:
  - Email via SendGrid (client contact_email)
  - Slack via a per-client incoming webhook URL (Client.slack_webhook_url)

Design: sending is always an explicit function call, never automatic
side-effect of drafting. draft_alert_for_finding (Module 5) only sends
when settings.AUTO_SEND_CRITICAL_ALERTS AND the client has opted in via
Client.auto_send_critical_alerts — otherwise it's logged for human review
and sent manually through the portal/API.
"""
import logging

import httpx

from app.core.config import settings
from app.models.models import Client

logger = logging.getLogger(__name__)

SENDGRID_URL = "https://api.sendgrid.com/v3/mail/send"


def send_email(to_email: str, subject: str, body_text: str, timeout: int = 15) -> bool:
    if not settings.SENDGRID_API_KEY:
        logger.warning(f"SENDGRID_API_KEY not set — cannot send email to {to_email}. Subject: {subject}")
        return False

    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": settings.ALERT_FROM_EMAIL},
        "subject": subject,
        "content": [{"type": "text/plain", "value": body_text}],
    }
    headers = {"Authorization": f"Bearer {settings.SENDGRID_API_KEY}", "Content-Type": "application/json"}

    try:
        resp = httpx.post(SENDGRID_URL, json=payload, headers=headers, timeout=timeout)
        if resp.status_code >= 300:
            logger.error(f"SendGrid send failed ({resp.status_code}): {resp.text}")
            return False
        return True
    except httpx.RequestError as e:
        logger.error(f"SendGrid request failed: {e}")
        return False


def send_slack_message(webhook_url: str, text: str, timeout: int = 15) -> bool:
    if not webhook_url:
        return False
    try:
        resp = httpx.post(webhook_url, json={"text": text}, timeout=timeout)
        if resp.status_code >= 300:
            logger.error(f"Slack webhook failed ({resp.status_code}): {resp.text}")
            return False
        return True
    except httpx.RequestError as e:
        logger.error(f"Slack webhook request failed: {e}")
        return False


def notify_client(client: Client, subject: str, body_text: str) -> dict:
    """Sends via every channel the client has configured. Returns per-channel success flags."""
    results = {"email": False, "slack": False}
    results["email"] = send_email(client.contact_email, subject, body_text)
    if client.slack_webhook_url:
        results["slack"] = send_slack_message(client.slack_webhook_url, f"*{subject}*\n{body_text}")
    return results


def notify_finding_alert(client: Client, finding_title: str, severity: str, draft_body: str) -> dict:
    subject = f"[{severity.upper()}] Security alert — {finding_title}"
    return notify_client(client, subject, draft_body)


def notify_sla_breach(client: Client, finding_title: str, severity: str, sla_deadline) -> dict:
    subject = f"[SLA BREACH] {finding_title}"
    body = (f"A {severity} finding for {client.name} has exceeded its SLA deadline "
            f"({sla_deadline}) while still unresolved. Please review and update its status.")
    return notify_client(client, subject, body)


def notify_weekly_digest(client: Client, digest_text: str) -> dict:
    subject = f"Weekly Threat Digest — {client.name}"
    return notify_client(client, subject, digest_text)
