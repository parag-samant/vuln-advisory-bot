# 🛡️ Automated Vulnerability Advisory System

Automated pipeline that monitors CVE/KEV feeds every 4 hours, filters high-severity vulnerabilities (CVSS ≥ 7), generates AI-powered technical advisories using GitHub Models, and sends individual email alerts.

## Architecture

```
GitHub Actions (cron: every 4h)
    │
    ├─ 📡 Fetch CVEs from NVD API 2.0, CISA KEV, GitHub Advisory DB
    ├─ 🔍 Deduplicate against previously processed CVEs
    ├─ 🤖 Generate detailed advisory via GitHub Models AI (GPT-4o-mini)
    ├─ 📧 Send individual HTML emails for each vulnerability
    └─ 💾 Commit updated state to avoid duplicates on next run
```

## Data Sources

| Source | Description |
|--------|-------------|
| [NVD API 2.0](https://nvd.nist.gov/) | All CVEs with CVSS scores, descriptions, CPE data |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities (actively exploited) |
| [GitHub Advisory DB](https://github.com/advisories) | Security advisories from open-source ecosystem |

## Setup Guide

### 1. Create a GitHub Repository

```bash
cd "Project vulnerability advisory"
git init
git add .
git commit -m "Initial commit: vulnerability advisory automation"
git remote add origin https://github.com/YOUR_USERNAME/vuln-advisory-bot.git
git push -u origin main
```

> **Tip:** Make the repo **public** for unlimited free GitHub Actions minutes.

### 2. Set Up Gmail App Password (for sending emails)

1. Go to [Google Account → Security](https://myaccount.google.com/security)
2. Enable **2-Step Verification** if not already enabled
3. Go to [App Passwords](https://myaccount.google.com/apppasswords)
4. Create a new app password for "Mail" → "Other (Custom)" → name it "Vuln Advisory Bot"
5. Copy the 16-character password

### 3. Configure GitHub Secrets

Go to your repository → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

| Secret Name | Value | Example |
|-------------|-------|---------|
| `SMTP_HOST` | SMTP server | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_USERNAME` | Your Gmail address | `your.name@gmail.com` |
| `SMTP_PASSWORD` | Gmail App Password | `abcd efgh ijkl mnop` |
| `SMTP_SENDER` | Sender display address | `your.name@gmail.com` |
| `RECIPIENT_EMAIL` | Your Accenture email | `your.name@accenture.com` |

### 4. Enable GitHub Actions

1. Go to **Actions** tab in your repository
2. The workflow will auto-run every 4 hours
3. To test immediately: click **"Vulnerability Advisory Scan"** → **"Run workflow"** → **"Run workflow"**

## Local Testing

```bash
# Install dependencies
pip install -r requirements.txt

# Dry run (no emails, prints to console)
python src/main.py --dry-run

# Look back 24 hours for more results
python src/main.py --hours-back 24 --dry-run

# Only critical vulnerabilities
python src/main.py --min-cvss 9.0 --dry-run
```

For actual email sending locally, set environment variables:

```bash
# Windows PowerShell
$env:GITHUB_TOKEN = "your_github_pat_with_models_scope"
$env:SMTP_USERNAME = "your.email@gmail.com"
$env:SMTP_PASSWORD = "your_app_password"
$env:RECIPIENT_EMAIL = "your.name@accenture.com"

python src/main.py
```

## Email Preview

Each vulnerability generates a professional HTML email with:
- Severity-colored header banner (red for CRITICAL, orange for HIGH)
- CISA KEV badge for actively exploited vulnerabilities
- AI-generated 9-section advisory (executive summary, technical details, mitigations, etc.)
- Full CVSS vector breakdown
- Actionable remediation steps

## Customization

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--hours-back` | 4 | Time window to look back for new CVEs |
| `--min-cvss` | 7.0 | Minimum CVSS score threshold |
| `--dry-run` | false | Print advisories instead of sending emails |

## Project Structure

```
├── .github/workflows/
│   └── vulnerability-scan.yml    # GitHub Actions cron job
├── src/
│   ├── main.py                   # Pipeline orchestrator
│   ├── cve_fetcher.py            # NVD/CISA/GitHub API fetcher
│   ├── dedup.py                  # Deduplication tracker
│   ├── advisory_generator.py     # AI advisory generator
│   └── email_sender.py           # SMTP email sender
├── data/
│   └── processed_cves.json       # Tracks processed CVEs (auto-updated)
├── requirements.txt
└── README.md
```

## Cost

**$0.00** — Everything runs on free tiers:
- ✅ GitHub Actions: Free for public repos (2,000 min/month for private)
- ✅ GitHub Models AI: Free tier (GPT-4o-mini, rate-limited)
- ✅ NVD API: Free, no auth required
- ✅ CISA KEV: Free public feed
- ✅ Gmail SMTP: Free with App Password
