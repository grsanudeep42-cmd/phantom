"""
phantom/core/cve.py

CVE intelligence layer — queries NVD API (free, no key required).

API reference: https://services.nvd.nist.gov/rest/json/cves/2.0

Provides:
  cve_lookup(cve_id)              → CVEResult for a specific CVE
  version_cves(product, version)  → list[CVEResult] for product+version
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CVEResult:
    id: str
    description: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / NONE
    cvss_score: float      # 0.0 – 10.0
    cvss_version: str      # "3.1" | "3.0" | "2.0"
    published: str
    modified: str
    cwe: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    has_public_exploit: bool = False   # based on EPSS or reference patterns
    epss_score: float = 0.0            # 0.0 – 1.0 probability of exploitation

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "description": self.description[:300],
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_version": self.cvss_version,
            "published": self.published,
            "modified": self.modified,
            "cwe": self.cwe,
            "has_public_exploit": self.has_public_exploit,
            "epss_score": self.epss_score,
            "references_count": len(self.references),
        }


# ─────────────────────────────────────────────────────────────────────────────
# NVD API client
# ─────────────────────────────────────────────────────────────────────────────

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_EPSS_BASE = "https://api.first.org/data/v1/epss"

# Patterns in references that suggest a public exploit exists
_EXPLOIT_PATTERNS = re.compile(
    r"exploit|poc|proof.of.concept|metasploit|rapid7|github\.com.*cve|"
    r"exploit-db|edb-id|packetstorm",
    re.IGNORECASE,
)


async def cve_lookup(cve_id: str) -> Optional[CVEResult]:
    """
    Fetch a single CVE by ID from NVD.
    Returns None if not found or API is unreachable.
    """
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    params = f"?cveId={cve_id}"

    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                _NVD_BASE + params,
                timeout=aiohttp.ClientTimeout(total=15),
                headers={"User-Agent": "PHANTOM-Security-Scanner/0.2"},
            ) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()
    except Exception:
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    return _parse_nvd_vuln(vulns[0])


async def version_cves(
    product: str,
    version: str,
    max_results: int = 10,
) -> list[CVEResult]:
    """
    Find CVEs affecting a product+version using NVD keyword search.
    Returns up to max_results results, sorted by CVSS score descending.
    """
    keyword = f"{product} {version}"
    params = f"?keywordSearch={keyword.replace(' ', '%20')}&resultsPerPage={max_results}"

    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                _NVD_BASE + params,
                timeout=aiohttp.ClientTimeout(total=20),
                headers={"User-Agent": "PHANTOM-Security-Scanner/0.2"},
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
    except Exception:
        return []

    results = [
        _parse_nvd_vuln(v)
        for v in data.get("vulnerabilities", [])
    ]

    # Fetch EPSS scores in parallel (best-effort)
    if results:
        cve_ids = [r.id for r in results]
        epss = await _fetch_epss(cve_ids)
        for r in results:
            r.epss_score = epss.get(r.id, 0.0)
            if r.epss_score > 0.5:
                r.has_public_exploit = True

    results.sort(key=lambda x: x.cvss_score, reverse=True)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_nvd_vuln(vuln_entry: dict) -> CVEResult:
    cve = vuln_entry.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")
    published = cve.get("published", "")
    modified = cve.get("lastModified", "")

    # Description (English preferred)
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else ""
    )

    # CVSS score — prefer v3.1 > v3.0 > v2.0
    metrics = cve.get("metrics", {})
    severity = "NONE"
    cvss_score = 0.0
    cvss_version = "unknown"

    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(version_key, [])
        if metric_list:
            m = metric_list[0]
            cvss_data = m.get("cvssData", {})
            cvss_score = float(cvss_data.get("baseScore", 0.0))
            severity = cvss_data.get("baseSeverity", "NONE").upper()
            cvss_version = cvss_data.get("version", "unknown")
            break

    # CWE
    weaknesses = cve.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("lang") == "en" and d.get("value", "").startswith("CWE"):
                cwes.append(d["value"])

    # References
    refs = [r.get("url", "") for r in cve.get("references", [])]

    # Heuristic: does any reference suggest an exploit exists?
    has_exploit = any(_EXPLOIT_PATTERNS.search(ref) for ref in refs)

    return CVEResult(
        id=cve_id,
        description=description,
        severity=severity,
        cvss_score=cvss_score,
        cvss_version=cvss_version,
        published=published[:10],
        modified=modified[:10],
        cwe=cwes[:5],
        references=refs[:10],
        has_public_exploit=has_exploit,
    )


async def _fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS probability scores from FIRST.org API."""
    if not cve_ids:
        return {}
    params = "?cve=" + ",".join(cve_ids[:20])
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                _EPSS_BASE + params,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    return {}
                data = await resp.json()
                return {
                    item["cve"]: float(item.get("epss", 0.0))
                    for item in data.get("data", [])
                }
    except Exception:
        return {}
