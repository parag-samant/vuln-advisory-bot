"""
AI Advisory Generator Module
Uses GitHub Models API (OpenAI-compatible) to generate detailed technical
vulnerability advisories for each CVE.
"""

import os
import logging
from openai import OpenAI
from typing import Optional

logger = logging.getLogger(__name__)

# GitHub Models API configuration
GITHUB_MODELS_URL = "https://models.github.ai/inference"
DEFAULT_MODEL = "openai/gpt-4o-mini"


def _get_client() -> OpenAI:
    """Create an OpenAI client configured for GitHub Models API."""
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise EnvironmentError(
            "GITHUB_TOKEN environment variable is required. "
            "In GitHub Actions, this is provided automatically."
        )
    return OpenAI(
        base_url=GITHUB_MODELS_URL,
        api_key=token,
    )


def _build_prompt(vuln) -> str:
    """Build a detailed prompt for advisory generation."""
    kev_status = "⚠️ YES - This vulnerability is in the CISA Known Exploited Vulnerabilities catalog. Active exploitation confirmed." if vuln.is_kev else "Not currently in CISA KEV catalog."

    affected = ", ".join(vuln.affected_products) if vuln.affected_products else "Not specified"
    weaknesses = ", ".join(vuln.weaknesses) if vuln.weaknesses else "Not specified"
    references = "\n".join(f"  - {ref}" for ref in vuln.references) if vuln.references else "  None available"

    prompt = f"""You are a senior security analyst at a Fortune 500 company's vulnerability management team. Generate a comprehensive, professional vulnerability advisory for the following CVE. The advisory should be actionable and suitable for distribution to IT security teams and system administrators.

## Vulnerability Data

- **CVE ID:** {vuln.cve_id}
- **CVSS Score:** {vuln.cvss_score}
- **Severity:** {vuln.severity}
- **CVSS Vector:** {vuln.cvss_vector or 'Not available'}
- **Attack Vector:** {vuln.attack_vector or 'Not specified'}
- **Attack Complexity:** {vuln.attack_complexity or 'Not specified'}
- **Privileges Required:** {vuln.privileges_required or 'Not specified'}
- **User Interaction:** {vuln.user_interaction or 'Not specified'}
- **Vendor:** {vuln.vendor or 'Not specified'}
- **Product:** {vuln.product or 'Not specified'}
- **Affected Products:** {affected}
- **Weaknesses (CWE):** {weaknesses}
- **Exploited in the Wild (KEV):** {kev_status}
- **Published Date:** {vuln.published_date}
- **Source:** {vuln.source}

## Original Description
{vuln.description}

## References
{references}

---

Generate a structured advisory with the following sections. Be thorough, technical, and precise:

### 1. EXECUTIVE SUMMARY
A 2-3 sentence high-level summary suitable for management. Include the CVE ID, severity, affected product, and potential business impact.

### 2. VULNERABILITY DETAILS
- Detailed technical explanation of the vulnerability
- Root cause analysis based on the CWE and available information
- Attack scenario walkthrough (how an attacker could exploit this)
- Pre-requisites for exploitation

### 3. CVSS SCORE BREAKDOWN
Break down the CVSS vector string into its individual metrics with explanations of what each metric means for this specific vulnerability.

### 4. AFFECTED PRODUCTS & VERSIONS
List all known affected products, versions, and configurations. If specific versions aren't available, note what vendor/product is affected.

### 5. EXPLOITATION STATUS
- Is this being actively exploited? (KEV status)
- Known proof-of-concept availability
- Threat actor activity (if any known)
- Likelihood of exploitation

### 6. IMPACT ASSESSMENT
- Confidentiality impact
- Integrity impact
- Availability impact
- Potential business consequences

### 7. RECOMMENDED MITIGATIONS
Provide specific, actionable steps in priority order:
- Immediate actions (within 24-48 hours)
- Short-term mitigations
- Long-term remediation
- Compensating controls if patching is not immediately possible

### 8. DETECTION GUIDANCE
- How to detect if systems are vulnerable
- How to detect if exploitation has occurred
- Relevant log entries or indicators of compromise (IOCs) to look for

### 9. REFERENCES & RESOURCES
List the provided reference URLs with brief descriptions of what each contains.

Format the output as clean, professional text suitable for an email advisory. Use clear headers and bullet points."""

    return prompt


def generate_advisory(vuln, model: str = DEFAULT_MODEL) -> Optional[str]:
    """
    Generate a detailed technical advisory for a vulnerability using GitHub Models AI.

    Args:
        vuln: VulnerabilityRecord object
        model: The model to use from GitHub Models catalog

    Returns:
        Generated advisory text, or None if generation fails
    """
    logger.info(f"Generating advisory for {vuln.cve_id} (CVSS: {vuln.cvss_score}, Source: {vuln.source})")

    try:
        client = _get_client()
        prompt = _build_prompt(vuln)

        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert cybersecurity analyst specializing in vulnerability assessment "
                        "and security advisory creation. You work for a leading global professional services "
                        "company's security advisory team. Your advisories are thorough, technically accurate, "
                        "and actionable. You write in a professional, clear tone."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            temperature=0.3,  # Low temperature for factual, consistent output
            max_tokens=4000,
        )

        advisory_text = response.choices[0].message.content
        logger.info(f"Successfully generated advisory for {vuln.cve_id} ({len(advisory_text)} chars)")
        return advisory_text

    except Exception as e:
        logger.error(f"Failed to generate advisory for {vuln.cve_id}: {e}")
        return None


def generate_fallback_advisory(vuln) -> str:
    """
    Generate a basic advisory without AI if the API call fails.
    This ensures an advisory is always sent even if the AI is unavailable.
    """
    kev_warning = "\n⚠️ ACTIVELY EXPLOITED: This vulnerability is listed in CISA's Known Exploited Vulnerabilities catalog.\n" if vuln.is_kev else ""

    affected = "\n".join(f"  • {p}" for p in vuln.affected_products) if vuln.affected_products else "  • Not specified"
    weaknesses = ", ".join(vuln.weaknesses) if vuln.weaknesses else "Not specified"
    references = "\n".join(f"  • {ref}" for ref in vuln.references) if vuln.references else "  • None available"

    advisory = f"""
═══════════════════════════════════════════════════════════════
                    VULNERABILITY ADVISORY
═══════════════════════════════════════════════════════════════

CVE ID:          {vuln.cve_id}
CVSS Score:      {vuln.cvss_score} ({vuln.severity})
CVSS Vector:     {vuln.cvss_vector or 'N/A'}
Published:       {vuln.published_date}
Source:          {vuln.source}
{kev_warning}
───────────────────────────────────────────────────────────────
DESCRIPTION
───────────────────────────────────────────────────────────────
{vuln.description}

───────────────────────────────────────────────────────────────
TECHNICAL DETAILS
───────────────────────────────────────────────────────────────
  Attack Vector:       {vuln.attack_vector or 'N/A'}
  Attack Complexity:   {vuln.attack_complexity or 'N/A'}
  Privileges Required: {vuln.privileges_required or 'N/A'}
  User Interaction:    {vuln.user_interaction or 'N/A'}
  Weaknesses (CWE):   {weaknesses}

───────────────────────────────────────────────────────────────
AFFECTED PRODUCTS
───────────────────────────────────────────────────────────────
{affected}

───────────────────────────────────────────────────────────────
RECOMMENDED ACTIONS
───────────────────────────────────────────────────────────────
  1. Identify all affected systems in your environment
  2. Apply vendor patches as soon as available
  3. Implement compensating controls if immediate patching is not possible
  4. Monitor for indicators of compromise
  5. Review network segmentation and access controls

───────────────────────────────────────────────────────────────
REFERENCES
───────────────────────────────────────────────────────────────
{references}

═══════════════════════════════════════════════════════════════
This advisory was auto-generated. AI-enriched advisory was unavailable.
═══════════════════════════════════════════════════════════════
"""
    return advisory.strip()
