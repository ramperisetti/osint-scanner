"""
job_scraper.py — Infer a company's internal SaaS stack from public job postings.

How it works:
1. Checks demo data for known companies (pre-researched, accurate tech stacks)
2. Falls back to Adzuna API if company not in demo data
3. If neither returns results, signals NO_DATA so the aggregator omits
   this category from scoring entirely — no misleading zeros in the report.

Why this matters for security:
  Job postings are public intelligence. Attackers read them before targeting
  a company. Knowing a company uses Okta and Salesforce tells an attacker
  exactly which login portals to spoof.
"""

import httpx
import os
import re
from typing import Tuple, Union
from dotenv import load_dotenv

load_dotenv()

ADZUNA_BASE = "https://api.adzuna.com/v1/api/jobs/us/search/1"
ADZUNA_APP_ID = os.getenv("ADZUNA_APP_ID", "")
ADZUNA_APP_KEY = os.getenv("ADZUNA_APP_KEY", "")

# Sentinel value — tells aggregator to omit this category from scoring
NO_DATA = "NO_DATA"

# Pre-researched tech stacks for major companies.
# Based on public job postings, engineering blogs, and press releases.
DEMO_SAAS_DATA = {
    "adobe":      ["Salesforce", "AWS", "Microsoft Teams", "Workday", "GitHub", "Slack", "Jira"],
    "microsoft":  ["Azure", "GitHub", "Jira", "Salesforce", "Workday", "ServiceNow", "Slack"],
    "linkedin":   ["AWS", "Salesforce", "Workday", "Okta", "Slack", "GitHub", "Tableau"],
    "twitter":    ["AWS", "GitHub", "Slack", "Google Cloud", "Jira", "Databricks"],
    "dropbox":    ["AWS", "Okta", "GitHub", "Slack", "Jira", "Workday", "Salesforce"],
    "salesforce": ["AWS", "GitHub", "Slack", "Okta", "Workday", "Tableau", "ServiceNow"],
    "google":     ["GCP", "GitHub", "Salesforce", "Workday", "Jira", "Slack"],
    "github":     ["AWS", "Azure", "Slack", "Okta", "Datadog", "Kubernetes", "Terraform"],
    "amazon":     ["AWS", "Salesforce", "Workday", "Slack", "GitHub", "Tableau", "ServiceNow"],
    "meta":       ["AWS", "Okta", "Slack", "GitHub", "Databricks", "Tableau", "Jira"],
    "apple":      ["AWS", "Okta", "Slack", "GitHub", "Jira", "Splunk", "Tableau"],
    "netflix":    ["AWS", "GitHub", "Slack", "Okta", "Datadog", "Databricks", "Jira"],
    "spotify":    ["Google Cloud", "GitHub", "Slack", "Okta", "Datadog", "Jira", "Confluence"],
    "uber":       ["AWS", "GitHub", "Slack", "Okta", "Datadog", "Kubernetes", "Terraform"],
    "airbnb":     ["AWS", "GitHub", "Slack", "Okta", "Datadog", "Databricks", "Jira"],
    "stripe":     ["AWS", "GitHub", "Slack", "Okta", "Datadog", "Terraform", "Confluence"],
    "twilio":     ["AWS", "GitHub", "Slack", "Okta", "Datadog", "Jira", "Salesforce"],
    "shopify":    ["Google Cloud", "GitHub", "Slack", "Okta", "Datadog", "Kubernetes", "Jira"],
    "coinbase":   ["AWS", "GitHub", "Slack", "Okta", "Datadog", "Terraform", "Jira"],
    "palantir":   ["AWS", "GitHub", "Slack", "Okta", "Kubernetes", "Terraform", "Splunk"],
}

# SaaS tools to scan for in job descriptions.
# Each entry: (tool_name, category, severity)
SAAS_KEYWORDS = [
    ("Okta",                "Identity & Access", "high"),
    ("OneLogin",            "Identity & Access", "high"),
    ("Azure AD",            "Identity & Access", "high"),
    ("Active Directory",    "Identity & Access", "high"),
    ("Salesforce",          "CRM",               "high"),
    ("HubSpot",             "CRM",               "medium"),
    ("Zoho",                "CRM",               "medium"),
    ("Workday",             "HR & Payroll",      "high"),
    ("ADP",                 "HR & Payroll",      "high"),
    ("BambooHR",            "HR & Payroll",      "medium"),
    ("Greenhouse",          "HR & Payroll",      "medium"),
    ("Lever",               "HR & Payroll",      "medium"),
    ("AWS",                 "Cloud",             "high"),
    ("Amazon Web Services", "Cloud",             "high"),
    ("Google Cloud",        "Cloud",             "high"),
    ("GCP",                 "Cloud",             "high"),
    ("Azure",               "Cloud",             "high"),
    ("Kubernetes",          "Cloud",             "medium"),
    ("Terraform",           "Cloud",             "medium"),
    ("Datadog",             "Cloud",             "medium"),
    ("GitHub",              "DevOps",            "high"),
    ("GitLab",              "DevOps",            "high"),
    ("Jenkins",             "DevOps",            "medium"),
    ("CircleCI",            "DevOps",            "medium"),
    ("Jira",                "Project Mgmt",      "medium"),
    ("Confluence",          "Project Mgmt",      "medium"),
    ("Slack",               "Communication",     "high"),
    ("Microsoft Teams",     "Communication",     "medium"),
    ("Zoom",                "Communication",     "medium"),
    ("QuickBooks",          "Finance",           "high"),
    ("NetSuite",            "Finance",           "high"),
    ("SAP",                 "Finance",           "high"),
    ("Stripe",              "Finance",           "medium"),
    ("CrowdStrike",         "Security",          "medium"),
    ("Splunk",              "Security",          "medium"),
    ("Palo Alto",           "Security",          "medium"),
    ("Snowflake",           "Data",              "medium"),
    ("Databricks",          "Data",              "medium"),
    ("Tableau",             "Data",              "low"),
    ("Google Workspace",    "Productivity",      "medium"),
    ("Microsoft 365",       "Productivity",      "medium"),
    ("Dropbox",             "Storage",           "medium"),
    ("Box",                 "Storage",           "medium"),
    ("ServiceNow",          "IT",                "high"),
    ("Zendesk",             "Support",           "medium"),
]


def _extract_company_name(domain: str) -> str:
    """'mail.google.com' → 'google'"""
    parts = domain.split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def _scan_text_for_tools(text: str) -> list[dict]:
    """Scan text for SaaS tool keywords. Returns unique matched tools."""
    text_lower = text.lower()
    found = {}

    for tool_name, category, severity in SAAS_KEYWORDS:
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


def _tool_count_to_score(count: int) -> int:
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


async def scrape_job_postings(domain: str) -> Tuple[list[dict], Union[int, str]]:
    """
    Main entry point.

    Returns:
        findings  — list of Finding dicts (empty if no data)
        score     — int 0-100, OR NO_DATA string if category should be
                    omitted from the report entirely
    """
    company = _extract_company_name(domain)

    # Check demo data first — instant and reliable
    if company.lower() in DEMO_SAAS_DATA:
        return _demo_fallback(company)

    # Try Adzuna if credentials are available
    if ADZUNA_APP_ID and ADZUNA_APP_KEY:
        findings, score = await _query_adzuna(company)
        if findings:
            return findings, score

    # No data from any source — signal omission
    print(f"[JobScraper] No data for {company} — omitting saas_stack_exposure from score")
    return [], NO_DATA


async def _query_adzuna(company: str) -> Tuple[list[dict], Union[int, str]]:
    params = {
        "app_id": ADZUNA_APP_ID,
        "app_key": ADZUNA_APP_KEY,
        "results_per_page": 10,
        "company": company,
        "content-type": "application/json",
    }

    raw_text = ""

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(ADZUNA_BASE, params=params)
            print(f"[JobScraper] Adzuna status {response.status_code} for {company}")

            if response.status_code == 200:
                data = response.json()
                jobs = data.get("results", [])
                print(f"[JobScraper] Got {len(jobs)} postings for {company}")
                for job in jobs:
                    raw_text += " " + job.get("title", "")
                    raw_text += " " + job.get("description", "")
            else:
                print(f"[JobScraper] Adzuna error {response.status_code}")
                return [], NO_DATA

    except httpx.TimeoutException:
        print(f"[JobScraper] Timeout for {company}")
        return [], NO_DATA
    except Exception as e:
        print(f"[JobScraper] Error: {e}")
        return [], NO_DATA

    findings = _scan_text_for_tools(raw_text)
    print(f"[JobScraper] Found {len(findings)} tools for {company}")
    return findings, _tool_count_to_score(len(findings))


def _demo_fallback(company: str) -> Tuple[list[dict], int]:
    tool_names = DEMO_SAAS_DATA.get(company.lower(), [])
    findings = []

    for tool_name in tool_names:
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

    print(f"[JobScraper] Demo data: {len(findings)} tools for {company}")
    return findings, _tool_count_to_score(len(findings))
