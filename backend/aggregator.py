"""
aggregator.py — Runs all four data sources in parallel and combines results.

Categories:
  credential_exposure  — HIBP breach lookup
  saas_stack_exposure  — Job posting SaaS inference
  code_exposure        — GitHub public repo + secret scan
  org_intel            — DNS enumeration (MX, SPF, subdomains, WHOIS)

Any category returning NO_DATA is omitted from the report and score
so unknown companies never show misleading zeros.
"""

import asyncio
from hibp        import check_breaches
from job_scraper import scrape_job_postings, NO_DATA as JOB_NO_DATA
from github_scan import scan_github,          NO_DATA as GH_NO_DATA
from dns_scan    import scan_dns,             NO_DATA as DNS_NO_DATA


async def run_all_sources(domain: str) -> dict:
    """
    Fire all four modules simultaneously. Each module handles its own
    errors and returns empty results or NO_DATA on failure — this
    function never raises.
    """
    (
        (breach_findings,  breach_score),
        (job_findings,     job_score),
        (github_findings,  github_score),
        (dns_findings,     dns_score),
    ) = await asyncio.gather(
        check_breaches(domain),
        scrape_job_postings(domain),
        scan_github(domain),
        scan_dns(domain),
    )

    categories   = {}
    all_findings = []

    # Credential exposure — 0 is valid (no breaches found), always include
    categories["credential_exposure"] = breach_score
    all_findings.extend(breach_findings)

    # SaaS stack — omit if no job data available for this company
    if job_score != JOB_NO_DATA:
        categories["saas_stack_exposure"] = job_score
        all_findings.extend(job_findings)

    # Code exposure — omit if no GitHub presence found
    if github_score != GH_NO_DATA:
        categories["code_exposure"] = github_score
        all_findings.extend(github_findings)

    # Org intel — omit if domain doesn't resolve
    if dns_score != DNS_NO_DATA:
        categories["org_intel"] = dns_score
        all_findings.extend(dns_findings)

    # Overall = average of present categories only
    overall = (
        round(sum(categories.values()) / len(categories))
        if categories else 0
    )

    print(f"[Aggregator] {domain} — score {overall}, "
          f"{len(all_findings)} findings, "
          f"categories: {list(categories.keys())}")

    return {
        "domain":       domain,
        "overall_score": overall,
        "categories":   categories,
        "findings":     all_findings,
    }
