"""
soar_email.py — SOAR Stage 6: Real email alert on BLOCK/CRITICAL threats.
Runs in a background daemon thread — pipeline is never blocked if email fails.
"""

import smtplib
import logging
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone
from typing import List, Optional

from app import config

logger = logging.getLogger("hpe.soar.email")


# ── Internal sender ────────────────────────────────────────────────────────────

def _build_html(
    event_id: str,
    user: str,
    source_ip: str,
    threat_score: float,
    action: str,
    reasons: List[str],
    timestamp: str,
) -> str:
    """Build a styled HTML email body for the threat alert."""

    score_pct = round(threat_score * 100, 1)
    action_color = "#ff4a4a" if action == "CRITICAL_ALERT" else "#f59e0b"
    reasons_html = "".join(
        f"<li style='margin-bottom:6px;'>⚠️ {r}</li>" for r in reasons
    ) or "<li>Anomalous behaviour detected by AI models</li>"

    return f"""
    <!DOCTYPE html>
    <html>
    <body style="margin:0;padding:0;background:#0a0a0a;font-family:Inter,Arial,sans-serif;color:#ffffff;">
      <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:40px 0;">
        <tr><td align="center">
          <table width="580" cellpadding="0" cellspacing="0"
                 style="background:#111111;border-radius:12px;overflow:hidden;
                        border:1px solid #222222;box-shadow:0 20px 40px rgba(0,0,0,0.6);">

            <!-- Header -->
            <tr>
              <td style="background:{action_color};padding:4px 0;"></td>
            </tr>
            <tr>
              <td style="padding:32px 40px 20px;">
                <table width="100%">
                  <tr>
                    <td>
                      <div style="background:#01A982;width:36px;height:36px;border-radius:8px;
                                  display:inline-block;vertical-align:middle;margin-right:12px;"></div>
                      <span style="font-size:20px;font-weight:700;vertical-align:middle;">HPE Security</span>
                    </td>
                    <td align="right">
                      <span style="background:{action_color};color:#000;font-size:11px;
                                   font-weight:700;padding:4px 10px;border-radius:20px;
                                   letter-spacing:1px;">{action.replace("_", " ")}</span>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <!-- Title -->
            <tr>
              <td style="padding:0 40px 24px;">
                <h1 style="margin:0;font-size:24px;font-weight:700;color:{action_color};">
                  🚨 Threat Detected
                </h1>
                <p style="margin:8px 0 0;color:#888888;font-size:14px;">
                  SOAR automated alert — immediate review required
                </p>
              </td>
            </tr>

            <!-- Divider -->
            <tr><td style="border-top:1px solid #222222;margin:0 40px;"></td></tr>

            <!-- Event Details -->
            <tr>
              <td style="padding:24px 40px;">
                <table width="100%" cellspacing="0" cellpadding="0">
                  <tr>
                    <td style="padding:10px 0;border-bottom:1px solid #1a1a1a;">
                      <span style="color:#888;font-size:12px;text-transform:uppercase;letter-spacing:1px;">User</span><br>
                      <span style="color:#fff;font-size:16px;font-weight:600;">{user}</span>
                    </td>
                    <td style="padding:10px 0;border-bottom:1px solid #1a1a1a;" align="right">
                      <span style="color:#888;font-size:12px;text-transform:uppercase;letter-spacing:1px;">Source IP</span><br>
                      <span style="color:#01A982;font-size:16px;font-family:monospace;">{source_ip}</span>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding:10px 0;border-bottom:1px solid #1a1a1a;">
                      <span style="color:#888;font-size:12px;text-transform:uppercase;letter-spacing:1px;">Threat Score</span><br>
                      <span style="color:{action_color};font-size:22px;font-weight:700;">{score_pct}%</span>
                    </td>
                    <td style="padding:10px 0;border-bottom:1px solid #1a1a1a;" align="right">
                      <span style="color:#888;font-size:12px;text-transform:uppercase;letter-spacing:1px;">Event ID</span><br>
                      <span style="color:#fff;font-size:13px;font-family:monospace;">{event_id}</span>
                    </td>
                  </tr>
                  <tr>
                    <td colspan="2" style="padding:10px 0;">
                      <span style="color:#888;font-size:12px;text-transform:uppercase;letter-spacing:1px;">Timestamp</span><br>
                      <span style="color:#fff;font-size:14px;">{timestamp}</span>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <!-- Reasons -->
            <tr>
              <td style="padding:0 40px 24px;">
                <div style="background:#1a1a1a;border-radius:8px;padding:20px;
                            border-left:3px solid {action_color};">
                  <p style="margin:0 0 12px;font-size:13px;font-weight:700;
                            text-transform:uppercase;letter-spacing:1px;color:{action_color};">
                    Detection Reasons
                  </p>
                  <ul style="margin:0;padding-left:16px;font-size:13px;color:#cccccc;line-height:1.7;">
                    {reasons_html}
                  </ul>
                </div>
              </td>
            </tr>

            <!-- CTA -->
            <tr>
              <td style="padding:0 40px 32px;" align="center">
                <p style="font-size:13px;color:#888888;margin-bottom:16px;">
                  Review this alert in the HPE Admin Console
                </p>
                <div style="background:#01A982;color:#000;padding:12px 32px;
                            border-radius:6px;font-weight:700;font-size:14px;
                            display:inline-block;">
                  Open Admin Console
                </div>
              </td>
            </tr>

            <!-- Footer -->
            <tr>
              <td style="background:#0d0d0d;padding:16px 40px;border-top:1px solid #1a1a1a;">
                <p style="margin:0;font-size:11px;color:#555555;text-align:center;">
                  This is an automated alert from HPE Security Pipeline •
                  SOAR Stage 6 • Do not reply to this email
                </p>
              </td>
            </tr>

          </table>
        </td></tr>
      </table>
    </body>
    </html>
    """


def _send_email(
    event_id: str,
    user: str,
    source_ip: str,
    threat_score: float,
    action: str,
    reasons: List[str],
) -> None:
    """Internal: build and send the email via SMTP. Called in background thread."""
    if not config.SOAR_EMAIL_ENABLED:
        logger.debug("SOAR email disabled — skipping alert")
        return

    if not all([config.SOAR_SENDER_EMAIL, config.SOAR_SENDER_PASSWORD, config.SOAR_RECEIVER_EMAIL]):
        logger.warning("SOAR email: missing SMTP credentials in config — skipping")
        return

    try:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        subject = (
            f"🚨 [HPE SOAR] {action.replace('_', ' ')} — "
            f"{user} @ {source_ip} | Score: {round(threat_score * 100, 1)}%"
        )

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"HPE Security SOAR <{config.SOAR_SENDER_EMAIL}>"
        msg["To"] = config.SOAR_RECEIVER_EMAIL

        html_body = _build_html(event_id, user, source_ip, threat_score, action, reasons, timestamp)
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(config.SOAR_SMTP_HOST, config.SOAR_SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(config.SOAR_SENDER_EMAIL, config.SOAR_SENDER_PASSWORD)
            server.sendmail(config.SOAR_SENDER_EMAIL, config.SOAR_RECEIVER_EMAIL, msg.as_string())

        logger.info(
            f"[SOAR] Alert email sent → {config.SOAR_RECEIVER_EMAIL} | "
            f"user={user} score={round(threat_score * 100, 1)}% action={action}"
        )

    except Exception as exc:
        # Never crash the pipeline — just log the warning
        logger.warning(f"[SOAR] Email failed (pipeline unaffected): {exc}")


# ── Public API ─────────────────────────────────────────────────────────────────

def send_threat_alert_async(
    event_id: str,
    user: Optional[str],
    source_ip: Optional[str],
    threat_score: float,
    action: str,
    reasons: Optional[List[str]] = None,
) -> None:
    """
    Fire-and-forget: send a threat alert email in a background daemon thread.
    Returns immediately — the pipeline is never blocked.
    """
    t = threading.Thread(
        target=_send_email,
        args=(
            event_id,
            user or "unknown",
            source_ip or "unknown",
            threat_score,
            action,
            reasons or [],
        ),
        daemon=True,
        name=f"soar-email-{event_id}",
    )
    t.start()
