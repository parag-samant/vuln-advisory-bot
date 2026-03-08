"""
Email Sender Module
Sends professional HTML-formatted vulnerability advisories via SMTP.
Each vulnerability gets its own individual email.
"""

import os
import re
import sys
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

logger = logging.getLogger(__name__)


def _safe_print(text: str):
    """Print text safely, handling encoding issues on Windows console."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"))


def _get_smtp_config() -> dict:
    """Get SMTP configuration from environment variables."""
    return {
        "host": os.environ.get("SMTP_HOST", "smtp.gmail.com"),
        "port": int(os.environ.get("SMTP_PORT", "587")),
        "username": os.environ.get("SMTP_USERNAME", ""),
        "password": os.environ.get("SMTP_PASSWORD", ""),
        "sender": os.environ.get("SMTP_SENDER", os.environ.get("SMTP_USERNAME", "")),
        "recipient": os.environ.get("RECIPIENT_EMAIL", ""),
    }


def _markdown_to_html(text: str) -> str:
    """
    Convert markdown-ish advisory text to styled HTML for email.
    Handles headers, bold, bullet points, and code blocks.
    """
    lines = text.split("\n")
    html_lines = []
    in_code_block = False

    for line in lines:
        stripped = line.strip()

        # Code blocks
        if stripped.startswith("```"):
            if in_code_block:
                html_lines.append("</pre>")
                in_code_block = False
            else:
                html_lines.append(
                    '<pre style="background-color:#1e1e2e;color:#cdd6f4;padding:12px;'
                    'border-radius:6px;font-family:monospace;font-size:13px;overflow-x:auto;">'
                )
                in_code_block = True
            continue

        if in_code_block:
            html_lines.append(line)
            continue

        # Headers
        if stripped.startswith("### "):
            header_text = stripped[4:]
            html_lines.append(
                f'<h3 style="color:#89b4fa;border-bottom:1px solid #313244;'
                f'padding-bottom:6px;margin-top:20px;font-size:16px;">{header_text}</h3>'
            )
            continue
        elif stripped.startswith("## "):
            header_text = stripped[3:]
            html_lines.append(
                f'<h2 style="color:#cba6f7;border-bottom:2px solid #313244;'
                f'padding-bottom:8px;margin-top:24px;font-size:18px;">{header_text}</h2>'
            )
            continue
        elif stripped.startswith("# "):
            header_text = stripped[2:]
            html_lines.append(
                f'<h1 style="color:#f38ba8;font-size:22px;margin-top:16px;">{header_text}</h1>'
            )
            continue

        # Horizontal rules
        if stripped in ("---", "───────────────────────────────────────────────────────────────", "═══════════════════════════════════════════════════════════════"):
            html_lines.append('<hr style="border:1px solid #313244;margin:16px 0;">')
            continue

        # Bullet points
        if stripped.startswith("- ") or stripped.startswith("• "):
            content = stripped[2:]
            content = _inline_markdown(content)
            html_lines.append(
                f'<div style="margin:4px 0 4px 20px;padding-left:10px;'
                f'border-left:2px solid #45475a;">◆ {content}</div>'
            )
            continue

        # Numbered items
        numbered_match = re.match(r"^(\d+)\.\s(.+)", stripped)
        if numbered_match:
            num = numbered_match.group(1)
            content = _inline_markdown(numbered_match.group(2))
            html_lines.append(
                f'<div style="margin:4px 0 4px 20px;padding-left:10px;">'
                f'<span style="color:#fab387;font-weight:bold;">{num}.</span> {content}</div>'
            )
            continue

        # Empty lines
        if not stripped:
            html_lines.append("<br>")
            continue

        # Regular text
        content = _inline_markdown(stripped)
        html_lines.append(f'<p style="margin:4px 0;line-height:1.6;">{content}</p>')

    return "\n".join(html_lines)


def _inline_markdown(text: str) -> str:
    """Convert inline markdown (bold, italic, code) to HTML."""
    # Bold
    text = re.sub(r"\*\*(.+?)\*\*", r'<strong style="color:#f9e2af;">\1</strong>', text)
    # Italic
    text = re.sub(r"\*(.+?)\*", r'<em>\1</em>', text)
    # Inline code
    text = re.sub(
        r"`(.+?)`",
        r'<code style="background-color:#313244;padding:2px 6px;border-radius:3px;font-family:monospace;font-size:13px;">\1</code>',
        text,
    )
    # URLs
    text = re.sub(
        r"(https?://[^\s<>\"]+)",
        r'<a href="\1" style="color:#89b4fa;text-decoration:underline;">\1</a>',
        text,
    )
    return text


def _build_html_email(vuln, advisory_text: str) -> str:
    """Build a complete HTML email with header banner and advisory content."""
    severity_colors = {
        "CRITICAL": {"bg": "#f38ba8", "text": "#11111b"},
        "HIGH": {"bg": "#fab387", "text": "#11111b"},
    }
    sev = severity_colors.get(vuln.severity, severity_colors["HIGH"])

    kev_badge = ""
    if vuln.is_kev:
        kev_badge = (
            '<span style="background-color:#f38ba8;color:#11111b;padding:4px 12px;'
            'border-radius:4px;font-weight:bold;font-size:12px;margin-left:10px;">'
            '⚠ ACTIVELY EXPLOITED (CISA KEV)</span>'
        )

    advisory_html = _markdown_to_html(advisory_text)

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background-color:#1e1e2e;font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">

<!-- Container -->
<div style="max-width:800px;margin:0 auto;background-color:#181825;border:1px solid #313244;border-radius:8px;overflow:hidden;">

  <!-- Header Banner -->
  <div style="background:linear-gradient(135deg, {sev['bg']}22, {sev['bg']}44);border-bottom:3px solid {sev['bg']};padding:24px 32px;">
    <div style="font-size:12px;color:#a6adc8;text-transform:uppercase;letter-spacing:2px;margin-bottom:8px;">
      Security Vulnerability Advisory
    </div>
    <div style="font-size:24px;font-weight:bold;color:#cdd6f4;margin-bottom:8px;">
      {vuln.cve_id}
    </div>
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
      <span style="background-color:{sev['bg']};color:{sev['text']};padding:4px 16px;border-radius:4px;font-weight:bold;font-size:14px;">
        {vuln.severity} — CVSS {vuln.cvss_score}
      </span>
      {kev_badge}
    </div>
    <div style="margin-top:12px;color:#a6adc8;font-size:13px;">
      Published: {vuln.published_date} &nbsp;|&nbsp; Source: {vuln.source}
      {f' &nbsp;|&nbsp; Vendor: {vuln.vendor}' if vuln.vendor else ''}
      {f' &nbsp;|&nbsp; Product: {vuln.product}' if vuln.product else ''}
    </div>
  </div>

  <!-- Advisory Content -->
  <div style="padding:24px 32px;color:#cdd6f4;font-size:14px;line-height:1.7;">
    {advisory_html}
  </div>

  <!-- Footer -->
  <div style="background-color:#11111b;padding:16px 32px;border-top:1px solid #313244;text-align:center;">
    <div style="color:#6c7086;font-size:12px;">
      This advisory was automatically generated by the Vulnerability Advisory Automation System.
      <br>Data sources: NVD, CISA KEV, GitHub Advisory Database &nbsp;|&nbsp; AI-powered by GitHub Models
      <br>Accenture Security — Vulnerability Management & Security Advisory
    </div>
  </div>

</div>
</body>
</html>"""

    return html


def send_advisory_email(vuln, advisory_text: str, dry_run: bool = False) -> bool:
    """
    Send a single vulnerability advisory email.

    Args:
        vuln: VulnerabilityRecord object
        advisory_text: The generated advisory text
        dry_run: If True, log the email content but don't actually send

    Returns:
        True if the email was sent (or dry-run logged) successfully
    """
    config = _get_smtp_config()

    # Build subject line
    product_info = ""
    if vuln.product and vuln.product != "*":
        product_info = f" | {vuln.vendor}:{vuln.product}" if vuln.vendor else f" | {vuln.product}"

    kev_tag = " | 🔴 KEV" if vuln.is_kev else ""

    subject = f"[VULN ADVISORY] {vuln.cve_id} | {vuln.severity} (CVSS {vuln.cvss_score}){product_info}{kev_tag}"

    # Dry run: print to console and return
    if dry_run:
        recipient = config["recipient"] or "dry-run@example.com"
        logger.info(f"[DRY RUN] Would send email: {subject}")
        logger.info(f"[DRY RUN] To: {recipient}")
        logger.info(f"[DRY RUN] Advisory length: {len(advisory_text)} chars")
        _safe_print(f"\n{'='*70}")
        _safe_print(f"EMAIL: {subject}")
        _safe_print(f"   To: {recipient}")
        _safe_print(f"{'='*70}")
        _safe_print(advisory_text[:500] + "..." if len(advisory_text) > 500 else advisory_text)
        _safe_print(f"{'='*70}\n")
        return True

    if not config["recipient"]:
        logger.error("RECIPIENT_EMAIL environment variable not set")
        return False

    # Build email
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = config["sender"]
    msg["To"] = config["recipient"]
    msg["X-Priority"] = "1" if vuln.severity == "CRITICAL" or vuln.is_kev else "2"

    # Plain text version
    msg.attach(MIMEText(advisory_text, "plain", "utf-8"))

    # HTML version
    html_content = _build_html_email(vuln, advisory_text)
    msg.attach(MIMEText(html_content, "html", "utf-8"))

    if not config["username"] or not config["password"]:
        logger.error("SMTP_USERNAME and SMTP_PASSWORD environment variables are required for sending emails")
        return False

    try:
        with smtplib.SMTP(config["host"], config["port"]) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(config["username"], config["password"])
            server.send_message(msg)

        logger.info(f"✅ Email sent: {subject}")
        return True

    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP authentication failed: {e}. Check SMTP_USERNAME and SMTP_PASSWORD.")
        return False
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error sending email for {vuln.cve_id}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending email for {vuln.cve_id}: {e}")
        return False

