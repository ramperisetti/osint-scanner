"""
aggregator.py — Runs all data source modules in parallel and combines results.

Why parallel (asyncio.gather)?
  Each data source makes a network request that takes 1–5 seconds.
  If we ran them one after another, a 4-source scan would take 4–20 seconds.
  Running them simultaneously means the total wait time = the slowest single
  source, not the sum of all sources. For a live demo, this is the difference
  between a 3-second scan and a 15-second scan.

How to add a new module (Week 2):
  1. Import it at the top
  2. Add it to the asyncio.gather() call in run_all_sources()
  3. Unpack its results and add findings/score to the right category
  That's it — the rest of the app doesn't need to change.
"""

import asyncio
from hibp import check_breaches
from job_scraper import scrape_job_postings

# Week 2 imports — uncomment as each module is built:
# from github_scan import scan_github
# from dns_scan import scan_dns


async def run_all_sources(domain: str) -> dict:
    """
    Fire all data source modules simultaneously and wait for all to finish.
    If one source fails or times out, it returns empty results — the scan
    still completes with data from the other sources.

    Returns a dict matching the ScanResponse schema in main.py.
    """

    # asyncio.gather runs all coroutines at the same time.
    # Each module handles its own exceptions internally and returns
    # empty results on failure, so gather() never crashes here.
    (
        (breach_findings, breach_score),
        (job_findings, job_score),
        # Week 2: add (github_findings, github_score) here
        # Week 2: add (dns_findings, dns_score) here
    ) = await asyncio.gather(
        check_breaches(domain),
        scrape_job_postings(domain),
        # Week 2: scan_github(domain),
        # Week 2: scan_dns(domain),
    )

    # Combine all findings into one flat list
    all_findings = breach_findings + job_findings
    # Week 2: + github_findings + dns_findings

    # Category scores — one score per data source
    categories = {
        "credential_exposure": breach_score,
        "saas_stack_exposure": job_score,
        "code_exposure": 0,       # github_scan.py — Week 2
        "org_intel": 0,           # dns_scan.py — Week 2
    }

    # Overall score = average of categories that have data (ignore zeros
    # for modules not yet built so the score isn't artificially dragged down)
    active_scores = [s for s in categories.values() if s > 0]
    overall = round(sum(active_scores) / len(active_scores)) if active_scores else 0

    return {
        "domain": domain,
        "overall_score": overall,
        "categories": categories,
        "findings": all_findings,
    }
