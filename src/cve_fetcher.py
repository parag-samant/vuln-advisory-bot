"""
CVE/KEV Data Fetcher Module
Fetches vulnerability data from NVD API 2.0, CISA KEV, and GitHub Advisory Database.
Filters for CVSS >= 7.0 and returns unified VulnerabilityRecord objects.
"""

import requests
import logging
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityRecord:
    """Unified vulnerability record from any source."""
    cve_id: str
    cvss_score: float
    severity: str  # CRITICAL, HIGH
    description: str
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    source: str = ""  # NVD, CISA_KEV, GITHUB
    published_date: str = ""
    is_kev: bool = False
    attack_vector: str = ""
    attack_complexity: str = ""
    privileges_required: str = ""
    user_interaction: str = ""
    cvss_vector: str = ""
    weaknesses: List[str] = field(default_factory=list)
    vendor: str = ""
    product: str = ""


def _get_time_window(hours_back: int = 4) -> tuple:
    """Calculate the time window for fetching CVEs."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours_back)
    # NVD API expects ISO 8601 date-time with UTC offset
    fmt = "%Y-%m-%dT%H:%M:%S.000+00:00"
    return start_time.strftime(fmt), end_time.strftime(fmt)


def _parse_cvss_v3(metrics: dict) -> dict:
    """Extract CVSS v3.x data from NVD metrics."""
    result = {
        "score": 0.0,
        "severity": "",
        "vector": "",
        "attack_vector": "",
        "attack_complexity": "",
        "privileges_required": "",
        "user_interaction": "",
    }

    # Try CVSS 3.1 first, then 3.0
    for key in ["cvssMetricV31", "cvssMetricV30"]:
        if key in metrics and metrics[key]:
            metric = metrics[key][0]
            cvss_data = metric.get("cvssData", {})
            result["score"] = cvss_data.get("baseScore", 0.0)
            result["severity"] = cvss_data.get("baseSeverity", "")
            result["vector"] = cvss_data.get("vectorString", "")
            result["attack_vector"] = cvss_data.get("attackVector", "")
            result["attack_complexity"] = cvss_data.get("attackComplexity", "")
            result["privileges_required"] = cvss_data.get("privilegesRequired", "")
            result["user_interaction"] = cvss_data.get("userInteraction", "")
            break

    return result


def _parse_cvss_v2(metrics: dict) -> dict:
    """Fallback: extract CVSS v2 data from NVD metrics."""
    result = {"score": 0.0, "severity": "", "vector": ""}

    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        metric = metrics["cvssMetricV2"][0]
        cvss_data = metric.get("cvssData", {})
        score = cvss_data.get("baseScore", 0.0)
        result["score"] = score
        result["vector"] = cvss_data.get("vectorString", "")
        if score >= 9.0:
            result["severity"] = "CRITICAL"
        elif score >= 7.0:
            result["severity"] = "HIGH"

    return result


def fetch_nvd_cves(hours_back: int = 4, min_cvss: float = 7.0) -> List[VulnerabilityRecord]:
    """
    Fetch recent CVEs from the NVD API 2.0.
    Filters by publication date and CVSS score.
    """
    start_str, end_str = _get_time_window(hours_back)

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start_str,
        "pubEndDate": end_str,
        "resultsPerPage": 100,
    }

    logger.info(f"Fetching NVD CVEs from {start_str} to {end_str}")

    records = []
    start_index = 0

    while True:
        params["startIndex"] = start_index
        try:
            resp = requests.get(url, params=params, timeout=60)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
            break

        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)

        logger.info(f"NVD returned {total_results} total results (page at index {start_index})")

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            metrics = cve.get("metrics", {})

            # Parse CVSS score
            cvss = _parse_cvss_v3(metrics)
            if cvss["score"] == 0.0:
                cvss = _parse_cvss_v2(metrics)

            if cvss["score"] < min_cvss:
                continue

            # Description
            desc_list = cve.get("descriptions", [])
            description = ""
            for d in desc_list:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break
            if not description and desc_list:
                description = desc_list[0].get("value", "")

            # References
            refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

            # Affected products from CPE configurations
            affected = []
            configurations = cve.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        criteria = cpe_match.get("criteria", "")
                        # Parse CPE string: cpe:2.3:a:vendor:product:version:...
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
                            version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""
                            affected_str = f"{vendor}:{product}"
                            if version:
                                affected_str += f":{version}"
                            if affected_str not in affected:
                                affected.append(affected_str)

            # Weaknesses (CWE IDs)
            weaknesses = []
            for w in cve.get("weaknesses", []):
                for wd in w.get("description", []):
                    cwe = wd.get("value", "")
                    if cwe and cwe not in weaknesses:
                        weaknesses.append(cwe)

            # Published date
            pub_date = cve.get("published", "")

            # Vendor/product from first affected entry
            vendor = ""
            product = ""
            if affected:
                parts = affected[0].split(":")
                vendor = parts[0] if len(parts) >= 1 else ""
                product = parts[1] if len(parts) >= 2 else ""

            record = VulnerabilityRecord(
                cve_id=cve_id,
                cvss_score=cvss["score"],
                severity=cvss["severity"],
                description=description,
                affected_products=affected,
                references=refs[:10],  # Limit to 10 references
                source="NVD",
                published_date=pub_date,
                is_kev=False,
                attack_vector=cvss.get("attack_vector", ""),
                attack_complexity=cvss.get("attack_complexity", ""),
                privileges_required=cvss.get("privileges_required", ""),
                user_interaction=cvss.get("user_interaction", ""),
                cvss_vector=cvss.get("vector", ""),
                weaknesses=weaknesses,
                vendor=vendor,
                product=product,
            )
            records.append(record)

        # Pagination
        if start_index + len(vulnerabilities) >= total_results:
            break
        start_index += len(vulnerabilities)

    logger.info(f"Fetched {len(records)} high-severity CVEs from NVD")
    return records


def fetch_cisa_kev(hours_back: int = 4) -> List[VulnerabilityRecord]:
    """
    Fetch recently added entries from the CISA Known Exploited Vulnerabilities catalog.
    """
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    logger.info("Fetching CISA KEV catalog")

    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        logger.error(f"CISA KEV request failed: {e}")
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_back)
    records = []

    for vuln in data.get("vulnerabilities", []):
        # CISA KEV uses dateAdded field
        date_added_str = vuln.get("dateAdded", "")
        if not date_added_str:
            continue

        try:
            date_added = datetime.strptime(date_added_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            continue

        # Check if added within the time window
        if date_added < cutoff:
            continue

        cve_id = vuln.get("cveID", "")
        vendor = vuln.get("vendorProject", "")
        product = vuln.get("product", "")
        description = vuln.get("shortDescription", "")
        action = vuln.get("requiredAction", "")

        record = VulnerabilityRecord(
            cve_id=cve_id,
            cvss_score=0.0,  # KEV doesn't include CVSS; will be enriched from NVD
            severity="CRITICAL",  # All KEVs are actively exploited
            description=f"{description}\n\nRequired Action: {action}",
            affected_products=[f"{vendor}:{product}"],
            references=[],
            source="CISA_KEV",
            published_date=date_added_str,
            is_kev=True,
            vendor=vendor,
            product=product,
        )
        records.append(record)

    logger.info(f"Fetched {len(records)} recent KEV entries from CISA")
    return records


def fetch_github_advisories(hours_back: int = 4, min_cvss: float = 7.0) -> List[VulnerabilityRecord]:
    """
    Fetch recent security advisories from GitHub Advisory Database.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_back)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

    url = "https://api.github.com/advisories"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    logger.info(f"Fetching GitHub advisories since {cutoff_str}")

    # GitHub API requires separate requests per severity level
    advisories = []
    for severity_level in ["high", "critical"]:
        params = {
            "type": "reviewed",
            "severity": severity_level,
            "per_page": 100,
            "sort": "published",
            "direction": "desc",
        }
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=60)
            resp.raise_for_status()
            advisories.extend(resp.json())
        except requests.RequestException as e:
            logger.warning(f"GitHub Advisory API request failed for severity '{severity_level}': {e}")
            continue

    records = []

    for adv in advisories:
        published = adv.get("published_at", "")
        if not published:
            continue

        try:
            pub_dt = datetime.strptime(published, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            continue

        if pub_dt < cutoff:
            continue

        cve_id = adv.get("cve_id", "")
        if not cve_id:
            continue

        cvss_score = adv.get("cvss", {}).get("score", 0.0) if adv.get("cvss") else 0.0
        if cvss_score < min_cvss:
            continue

        severity = adv.get("severity", "").upper()
        description = adv.get("description", "") or adv.get("summary", "")
        cvss_vector = adv.get("cvss", {}).get("vector_string", "") if adv.get("cvss") else ""

        # Affected packages
        affected = []
        for vuln in adv.get("vulnerabilities", []):
            pkg = vuln.get("package", {})
            ecosystem = pkg.get("ecosystem", "")
            name = pkg.get("name", "")
            if name:
                affected.append(f"{ecosystem}:{name}" if ecosystem else name)

        # References
        refs = [r.get("url", "") for r in adv.get("references", []) if r.get("url")]

        # CWEs
        weaknesses = [c.get("cwe_id", "") for c in adv.get("cwes", []) if c.get("cwe_id")]

        record = VulnerabilityRecord(
            cve_id=cve_id,
            cvss_score=cvss_score,
            severity=severity if severity in ("CRITICAL", "HIGH") else "HIGH",
            description=description,
            affected_products=affected,
            references=refs[:10],
            source="GITHUB",
            published_date=published,
            is_kev=False,
            cvss_vector=cvss_vector,
            weaknesses=weaknesses,
        )
        records.append(record)

    logger.info(f"Fetched {len(records)} high-severity advisories from GitHub")
    return records


def fetch_all_vulnerabilities(hours_back: int = 4, min_cvss: float = 7.0) -> List[VulnerabilityRecord]:
    """
    Fetch and merge vulnerabilities from all sources.
    CISA KEV entries enrich matching NVD/GitHub records with the is_kev flag.
    """
    logger.info(f"=== Fetching vulnerabilities from all sources (last {hours_back}h, CVSS >= {min_cvss}) ===")

    # Fetch from all sources
    nvd_records = fetch_nvd_cves(hours_back=hours_back, min_cvss=min_cvss)
    kev_records = fetch_cisa_kev(hours_back=hours_back)
    github_records = fetch_github_advisories(hours_back=hours_back, min_cvss=min_cvss)

    # Build a lookup by CVE ID
    merged = {}

    # NVD records as the base (most complete data)
    for r in nvd_records:
        merged[r.cve_id] = r

    # Merge GitHub records (add if not from NVD, or enrich)
    for r in github_records:
        if r.cve_id not in merged:
            merged[r.cve_id] = r
        else:
            existing = merged[r.cve_id]
            # Add any references from GitHub not already present
            for ref in r.references:
                if ref not in existing.references:
                    existing.references.append(ref)
            # Add any affected products from GitHub
            for prod in r.affected_products:
                if prod not in existing.affected_products:
                    existing.affected_products.append(prod)

    # Mark KEV entries
    kev_cve_ids = {r.cve_id for r in kev_records}
    for cve_id, record in merged.items():
        if cve_id in kev_cve_ids:
            record.is_kev = True

    # Add KEV-only entries (not found in NVD or GitHub)
    for r in kev_records:
        if r.cve_id not in merged:
            merged[r.cve_id] = r

    all_records = list(merged.values())

    # Sort by CVSS score descending, KEV first
    all_records.sort(key=lambda x: (x.is_kev, x.cvss_score), reverse=True)

    logger.info(f"=== Total unique vulnerabilities: {len(all_records)} ===")
    return all_records
