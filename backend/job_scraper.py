"""
job_scraper.py — Infer a company's internal SaaS stack from public job postings.

How it works:
1. Hits the Adzuna job API (free account at developer.adzuna.com) to fetch
   job postings for a given company name extracted from the domain.
2. Scans each job description for known SaaS tool names using a keyword list.
3. Returns a list of findings — each tool found is a potential attack surface
   because an attacker can use it to craft convincing phishing emails
   (e.g. a fake Workday password reset, a fake AWS billing alert).

Why this matters for security:
  Job postings are public intelligence. Attackers read them before targeting
  a company. A posting saying "must know Okta and Salesforce" tells an
  attacker exactly which login portals to spoof.

Setup (free):
  1. Register at https://developer.adzuna.com (takes 2 minutes, free)
  2. Copy your App ID and App Key into .env:
       ADZUNA_APP_ID=your_id_here
       ADZUNA_APP_KEY=your_key_here
  3. Without keys, the scraper uses demo fallback data for known companies.
"""

import httpx
import os
import re
from typing import Tuple
from dotenv import load_dotenv

load_dotenv()

ADZUNA_BASE = "https://api.adzuna.com/v1/api/jobs/us/search/1"
ADZUNA_APP_ID = os.getenv("ADZUNA_APP_ID", "")
ADZUNA_APP_KEY = os.getenv("ADZUNA_APP_KEY", "")

# Demo fallback — pre-populated for major companies used in the live demo.
# Each entry reflects real publicly known tech stacks.
# Add any company you plan to demo here.
DEMO_SAAS_DATA = {
    "adobe": ["Salesforce", "AWS", "Microsoft Teams", "Workday", "GitHub", "Slack", "Jira"],
    "microsoft": ["Azure", "GitHub", "Jira", "Salesforce", "Workday", "ServiceNow", "Slack"],
    "linkedin": ["AWS", "Salesforce", "Workday", "Okta", "Slack", "GitHub", "Tableau"],
    "twitter": ["AWS", "GitHub", "Slack", "Google Cloud", "Jira", "Databricks"],
    "dropbox": ["AWS", "Okta", "GitHub", "Slack", "Jira", "Workday", "Salesforce"],
    "salesforce": ["AWS", "GitHub", "Slack", "Okta", "Workday", "Tableau", "ServiceNow"],
    "google": ["GCP", "GitHub", "Salesforce", "Workday", "Jira", "Slack"],
}

# Master list of SaaS tools and cloud platforms to scan for.
# Each entry is (tool_name, category, severity).
# severity = how useful this is to an attacker:
#   high   = login portal to spoof, sensitive data platform
#   medium = reveals tech stack or cloud provider
#   low    = general productivity tool
SAAS_KEYWORDS = [
    # Identity & Access
    ("Okta", "Identity & Access", "high"),
    ("OneLogin", "Identity & Access", "high"),
    ("Azure AD", "Identity & Access", "high"),
    ("Active Directory", "Identity & Access", "high"),

    # CRM & Sales
    ("Salesforce", "CRM", "high"),
    ("HubSpot", "CRM", "medium"),
    ("Zoho", "CRM", "medium"),

    # HR & Payroll
    ("Workday", "HR & Payroll", "high"),
    ("ADP", "HR & Payroll", "high"),
    ("BambooHR", "HR & Payroll", "medium"),
    ("Greenhouse", "HR & Payroll", "medium"),
    ("Lever", "HR & Payroll", "medium"),

    # Cloud Infrastructure
    ("AWS", "Cloud", "high"),
    ("Amazon Web Services", "Cloud", "high"),
    ("Google Cloud", "Cloud", "high"),
    ("GCP", "Cloud", "high"),
    ("Azure", "Cloud", "high"),
    ("Kubernetes", "Cloud", "medium"),
    ("Terraform", "Cloud", "medium"),

    # DevOps & Code
    ("GitHub", "DevOps", "high"),
    ("GitLab", "DevOps", "high"),
    ("Jenkins", "DevOps", "medium"),
    ("CircleCI", "DevOps", "medium"),
    ("Jira", "Project Management", "medium"),
    ("Confluence", "Project Management", "medium"),

    # Communication
    ("Slack", "Communication", "high"),
    ("Microsoft Teams", "Communication", "medium"),
    ("Zoom", "Communication", "medium"),

    # Finance
    ("QuickBooks", "Finance", "high"),
    ("NetSuite", "Finance", "high"),
    ("SAP", "Finance", "high"),
    ("Stripe", "Finance", "medium"),

    # Security
    ("CrowdStrike", "Security", "medium"),
    ("Splunk", "Security", "medium"),
    ("Palo Alto", "Security", "medium"),

    # Storage & Productivity
    ("Snowflake", "Data", "medium"),
    ("Databricks", "Data", "medium"),
    ("Tableau", "Data", "low"),
    ("Google Workspace", "Productivity", "medium"),
    ("Microsoft 365", "Productivity", "medium"),
    ("Dropbox", "Storage", "medium"),
    ("Box", "Storage", "medium"),
    ("ServiceNow", "IT", "high"),
    ("Zendesk", "Support", "medium"),
]


def _extract_company_name(domain: str) -> str:
    """
    Turn 'acme.com' into 'acme' for use in job search queries.
    Strips subdomains and TLDs.
    Example: 'mail.google.com' → 'google'
    """
    parts = domain.split(".")
    # Handle subdomains: take the second-to-last part (the actual company name)
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


def _scan_text_for_tools(text: str) -> list[dict]:
    """
    Scan a block of text for SaaS tool names.
    Uses word-boundary regex so 'AWS' doesn't match 'JAWS'.
    Returns a list of unique matched tools.
    """
    text_lower = text.lower()
    found = {}  # tool_name → finding dict (deduplicate across multiple postings)

    for tool_name, category, severity in SAAS_KEYWORDS:
        # Word boundary match, case-insensitive
        pattern = r'\b' + re.escape(tool_name.lower()) + r'\b'
        if re.search(pattern, text_lower):
            if tool_name not in found:
                found[tool_name] = {
                    "type": "saas_tool",
                    "detail": (
                        f"{tool_name} ({category}) detected in job postings. "
                        f"Attackers can use this to craft targeted phishing — "
                        f"e.g. a fake {tool_name} login page or notification email."
                    ),
                    "severity": severity,
                    "tool": tool_name,
                    "category": category,
                }

    return list(found.values())


async def scrape_job_postings(domain: str) -> Tuple[list[dict], int]:
    """
    Main entry point. Fetches job postings for a company and scans them
    for SaaS tool mentions.

    Returns:
        findings  — list of Finding-compatible dicts, one per detected tool
        score     — 0–100 SaaS stack exposure score
    """
    company = _extract_company_name(domain)

    if ADZUNA_APP_ID and ADZUNA_APP_KEY:
        return await _query_adzuna(company)

    print(f"[JobScraper] No Adzuna credentials — using demo data for {company}")
    return _demo_fallback(company)


async def _query_adzuna(company: str) -> Tuple[list[dict], int]:
    params = {
        "app_id": ADZUNA_APP_ID,
        "app_key": ADZUNA_APP_KEY,
        "results_per_page": 10,
        "what_or": company,
        "content-type": "application/json",
    }

    raw_text = ""

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(ADZUNA_BASE, params=params)

            if response.status_code == 200:
                data = response.json()
                for job in data.get("results", []):
                    raw_text += " " + job.get("title", "")
                    raw_text += " " + job.get("description", "")
            else:
                print(f"[JobScraper] Adzuna returned {response.status_code}")

    except httpx.TimeoutException:
        print(f"[JobScraper] Timeout for {company}")
    except Exception as e:
        print(f"[JobScraper] Error: {e}")

    findings = _scan_text_for_tools(raw_text)
    return findings, _tool_count_to_score(len(findings))


def _demo_fallback(company: str) -> Tuple[list[dict], int]:
    """
    Return findings from pre-populated demo data for known companies.
    For unknown companies, returns empty — scan still completes cleanly.
    """
    tool_names = DEMO_SAAS_DATA.get(company.lower(), [])
    findings = []

    for tool_name in tool_names:
        # Look up the category and severity from SAAS_KEYWORDS
        meta = next((s for s in SAAS_KEYWORDS if s[0] == tool_name), None)
        category = meta[1] if meta else "SaaS"
        severity = meta[2] if meta else "medium"

        findings.append({
            "type": "saas_tool",
            "detail": (
                f"{tool_name} ({category}) detected in job postings. "
                f"Attackers can use this to craft targeted phishing — "
                f"e.g. a fake {tool_name} login page or notification email."
            ),
            "severity": severity,
            "tool": tool_name,
            "category": category,
        })

    return findings, _tool_count_to_score(len(findings))


def _tool_count_to_score(count: int) -> int:
    """
    More exposed SaaS tools = higher attack surface score.
    A company using 8+ platforms has a significantly larger
    social engineering surface than one using 2.
    """
    if count == 0:
        return 0
    elif count <= 2:
        return 20
    elif count <= 4:
        return 40
    elif count <= 7:
        return 60
    else:
        return 80
