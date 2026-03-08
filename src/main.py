"""
Main Orchestrator
Entry point for the vulnerability advisory automation pipeline.
Chains: Fetch → Deduplicate → Generate Advisory → Email → Update State
"""

import argparse
import logging
import sys
import time
import os

# Add parent directory to path for imports when run from src/
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cve_fetcher import fetch_all_vulnerabilities
from dedup import DeduplicationTracker
from advisory_generator import generate_advisory, generate_fallback_advisory
from email_sender import send_advisory_email

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("main")


def run_pipeline(hours_back: int = 4, min_cvss: float = 7.0, dry_run: bool = False):
    """
    Run the full vulnerability advisory pipeline.

    Args:
        hours_back: How far back to look for new CVEs (hours)
        min_cvss: Minimum CVSS score to include
        dry_run: If True, skip email sending and print advisories to console
    """
    logger.info("=" * 70)
    logger.info("VULNERABILITY ADVISORY AUTOMATION PIPELINE")
    logger.info(f"Parameters: hours_back={hours_back}, min_cvss={min_cvss}, dry_run={dry_run}")
    logger.info("=" * 70)

    # ── Step 1: Fetch vulnerabilities from all sources ──────────────────
    logger.info("\n📡 STEP 1: Fetching vulnerabilities from all sources...")
    try:
        vulnerabilities = fetch_all_vulnerabilities(
            hours_back=hours_back,
            min_cvss=min_cvss,
        )
    except Exception as e:
        logger.error(f"Fatal error fetching vulnerabilities: {e}")
        sys.exit(1)

    if not vulnerabilities:
        logger.info("✅ No new high-severity vulnerabilities found in the time window. Exiting.")
        return

    logger.info(f"Found {len(vulnerabilities)} vulnerabilities from all sources")

    # ── Step 2: Deduplicate against previously processed CVEs ───────────
    logger.info("\n🔍 STEP 2: Deduplicating against processed CVEs...")
    tracker = DeduplicationTracker()
    tracker.prune_old_entries(max_age_days=30)

    new_vulns = []
    for vuln in vulnerabilities:
        if not tracker.is_duplicate(vuln.cve_id):
            new_vulns.append(vuln)
        else:
            logger.debug(f"Skipping duplicate: {vuln.cve_id}")

    if not new_vulns:
        logger.info("✅ All vulnerabilities were already processed. No new advisories needed.")
        tracker.save()
        return

    logger.info(f"📋 {len(new_vulns)} new vulnerabilities to process (filtered out {len(vulnerabilities) - len(new_vulns)} duplicates)")

    # ── Step 3: Generate AI advisories and send emails ──────────────────
    logger.info("\n🤖 STEP 3: Generating advisories and sending emails...")
    success_count = 0
    fail_count = 0
    processed_ids = []

    for i, vuln in enumerate(new_vulns, 1):
        logger.info(f"\n--- Processing [{i}/{len(new_vulns)}]: {vuln.cve_id} (CVSS {vuln.cvss_score} {vuln.severity}) ---")

        # Generate AI advisory
        advisory_text = None
        try:
            advisory_text = generate_advisory(vuln)
        except Exception as e:
            logger.warning(f"AI generation failed for {vuln.cve_id}: {e}")

        # Fallback to template-based advisory
        if not advisory_text:
            logger.info(f"Using fallback advisory template for {vuln.cve_id}")
            advisory_text = generate_fallback_advisory(vuln)

        # Send email
        try:
            email_sent = send_advisory_email(vuln, advisory_text, dry_run=dry_run)
            if email_sent:
                success_count += 1
                processed_ids.append(vuln.cve_id)
                logger.info(f"✅ Advisory {'generated' if dry_run else 'sent'} for {vuln.cve_id}")
            else:
                fail_count += 1
                logger.error(f"❌ Failed to send advisory for {vuln.cve_id}")
                # Still mark as processed to avoid retry spam
                processed_ids.append(vuln.cve_id)
        except Exception as e:
            fail_count += 1
            logger.error(f"❌ Error processing {vuln.cve_id}: {e}")
            processed_ids.append(vuln.cve_id)

        # Rate limiting: small delay between API calls to respect GitHub Models limits
        if i < len(new_vulns):
            time.sleep(2)

    # ── Step 4: Update deduplication state ──────────────────────────────
    logger.info("\n💾 STEP 4: Updating deduplication state...")
    tracker.mark_batch_processed(processed_ids)
    tracker.save()

    # ── Summary ─────────────────────────────────────────────────────────
    logger.info("\n" + "=" * 70)
    logger.info("PIPELINE COMPLETE — SUMMARY")
    logger.info("=" * 70)
    logger.info(f"  Total vulnerabilities found:    {len(vulnerabilities)}")
    logger.info(f"  Already processed (duplicates): {len(vulnerabilities) - len(new_vulns)}")
    logger.info(f"  New vulnerabilities processed:  {len(new_vulns)}")
    logger.info(f"  Advisories sent successfully:   {success_count}")
    logger.info(f"  Failed to send:                 {fail_count}")
    logger.info("=" * 70)

    if fail_count > 0:
        logger.warning(f"⚠️  {fail_count} advisories failed. Check logs above for details.")


def main():
    parser = argparse.ArgumentParser(
        description="Automated Vulnerability Advisory System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Production run (sends emails, looks back 4 hours)
  python main.py

  # Dry run (prints advisories, no emails sent)
  python main.py --dry-run

  # Look back 24 hours for testing
  python main.py --hours-back 24 --dry-run

  # Custom CVSS threshold
  python main.py --min-cvss 9.0

Environment Variables:
  GITHUB_TOKEN      - Required for AI advisory generation (auto-set in GitHub Actions)
  SMTP_HOST         - SMTP server hostname (default: smtp.gmail.com)
  SMTP_PORT         - SMTP server port (default: 587)
  SMTP_USERNAME     - SMTP login username (your Gmail address)
  SMTP_PASSWORD     - SMTP login password (Gmail App Password)
  SMTP_SENDER       - Sender email address (defaults to SMTP_USERNAME)
  RECIPIENT_EMAIL   - Recipient email address (your Accenture email)
        """,
    )
    parser.add_argument(
        "--hours-back",
        type=int,
        default=4,
        help="How many hours back to look for new CVEs (default: 4)",
    )
    parser.add_argument(
        "--min-cvss",
        type=float,
        default=7.0,
        help="Minimum CVSS score to include (default: 7.0)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print advisories to console instead of sending emails",
    )

    args = parser.parse_args()
    run_pipeline(
        hours_back=args.hours_back,
        min_cvss=args.min_cvss,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
