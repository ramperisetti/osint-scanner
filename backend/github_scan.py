"""
github_scan.py — Scan public GitHub for exposed org data and secrets.

Uses the GitHub REST API (free, no auth needed for public data).
Set GITHUB_TOKEN in .env for higher rate limits (5000/hr vs 60/hr).

What it checks:
1. Org existence + public repo count (org intel)
2. Recent commit patches scanned for secret patterns
3. Demo fallback for known companies
"""

import httpx
import os
import re
from typing import Tuple, Union
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_BASE  = "https://api.github.com"
NO_DATA      = "NO_DATA"

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}',
        "AWS Access Key ID", "high"),
    (r'(?i)aws[_\-\s]*(secret[_\-\s]*access[_\-\s]*key|secret)[_\-\s]*[=:][_\-\s]*["\']?[A-Za-z0-9/+=]{40}',
        "AWS Secret Key", "high"),
    (r'(?i)(api[_\-]?key|apikey)\s*[=:]\s*["\'][A-Za-z0-9_\-]{20,}["\']',
        "API Key", "high"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']',
        "Hardcoded Password", "high"),
    (r'(?i)(db|database)[_\-]?(url|uri|conn)\s*[=:]\s*["\'][^"\']{10,}["\']',
        "Database Connection String", "high"),
    (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
        "Private Key", "high"),
    (r'(?i)secret[_\-]?key\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}["\']',
        "Secret Key", "high"),
    (r'(?i)(slack|discord)[_\-]?(token|webhook)\s*[=:]\s*["\'][A-Za-z0-9_\-/]+["\']',
        "Chat Platform Token", "medium"),
    (r'(?i)github[_\-]?token\s*[=:]\s*["\'][A-Za-z0-9_]{20,}["\']',
        "GitHub Token", "medium"),
    (r'(?i)(staging|dev|internal|corp)\.[a-z0-9\-]+\.[a-z]{2,6}',
        "Internal Hostname", "medium"),
]

# Pre-researched GitHub presence for demo companies
DEMO_GITHUB_DATA = {
    "github":     {"org": "github",     "repos": 371,  "has_secrets": False},
    "microsoft":  {"org": "microsoft",  "repos": 4800, "has_secrets": False},
    "google":     {"org": "google",     "repos": 2400, "has_secrets": False},
    "meta":       {"org": "facebook",   "repos": 300,  "has_secrets": False},
    "netflix":    {"org": "netflix",    "repos": 250,  "has_secrets": False},
    "airbnb":     {"org": "airbnb",     "repos": 120,  "has_secrets": False},
    "stripe":     {"org": "stripe",     "repos": 95,   "has_secrets": False},
    "shopify":    {"org": "shopify",    "repos": 180,  "has_secrets": False},
    "uber":       {"org": "uber-go",    "repos": 130,  "has_secrets": False},
    "linkedin":   {"org": "linkedin",   "repos": 90,   "has_secrets": False},
    "dropbox":    {"org": "dropbox",    "repos": 80,   "has_secrets": False},
    "adobe":      {"org": "adobe",      "repos": 420,  "has_secrets": False},
    "twitter":    {"org": "twitter",    "repos": 210,  "has_secrets": False},
    "coinbase":   {"org": "coinbase",   "repos": 175,  "has_secrets": False},
    "spotify":    {"org": "spotify",    "repos": 200,  "has_secrets": False},
}


def _headers() -> dict:
    h = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "OSINT-Scanner-HackathonProject/1.0",
    }
    if GITHUB_TOKEN:
        h["Authorization"] = f"token {GITHUB_TOKEN}"
    return h


def _scan_text(text: str, source: str) -> list[dict]:
    findings = []
    seen = set()
    for pattern, label, severity in SECRET_PATTERNS:
        if label in seen:
            continue
        if re.search(pattern, text):
            findings.append({
                "type": "code_exposure",
                "detail": (
                    f"{label} potentially exposed in public GitHub ({source}). "
                    f"Attackers can use this for direct system access."
                ),
                "severity": severity,
            })
            seen.add(label)
    return findings


def _score(findings: list[dict]) -> int:
    high   = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    low    = sum(1 for f in findings if f["severity"] == "low")
    return min((high * 30) + (medium * 15) + (low * 5), 95)


async def scan_github(domain: str) -> Tuple[list[dict], Union[int, str]]:
    company = domain.split(".")[0].lower()

    # Always try live scan first now that GITHUB_TOKEN is set
    if GITHUB_TOKEN:
        result = await _live_scan(domain, company)
        # If live scan returns data, use it
        if result[0]:
            return result

    # Fall back to demo data if live scan returns nothing
    if company in DEMO_GITHUB_DATA:
        return _demo_fallback(company)

    return [], NO_DATA


async def _live_scan(domain: str, company: str) -> Tuple[list[dict], Union[int, str]]:
    print(f"[GitHub] Starting live scan for {company}, token set: {bool(GITHUB_TOKEN)}")
    findings = []


    try:
        async with httpx.AsyncClient(timeout=8.0, headers=_headers()) as client:

            # 1. Try direct org lookup
            r = await client.get(f"{GITHUB_BASE}/orgs/{company}")

            if r.status_code == 404:
                # Try search fallback
                r2 = await client.get(
                    f"{GITHUB_BASE}/search/users",
                    params={"q": f"{company} type:org", "per_page": 1}
                )
                if r2.status_code == 200 and r2.json().get("items"):
                    login = r2.json()["items"][0]["login"]
                    r = await client.get(f"{GITHUB_BASE}/orgs/{login}")

            if r.status_code == 200:
                org = r.json()
                login    = org.get("login", company)
                repos    = org.get("public_repos", 0)
                members  = org.get("public_members_url", "")

                findings.append({
                    "type": "code_exposure",
                    "detail": (
                        f"GitHub org '{login}' found with {repos} public repos. "
                        f"Attackers can enumerate contributors, internal tooling, "
                        f"and commit history for intelligence gathering."
                    ),
                    "severity": "low",
                })

                # 2. Scan recent commits for secrets
                secret_hits = await _scan_commits(client, login)
                findings.extend(secret_hits)

            elif r.status_code == 403:
                print(f"[GitHub] Rate limited for {company}")
                return [], NO_DATA

    except httpx.TimeoutException:
        print(f"[GitHub] Timeout for {domain}")
        return [], NO_DATA
    except Exception as e:
        print(f"[GitHub] Error: {e}")
        return [], NO_DATA

    if not findings:
        return [], NO_DATA

    return findings, _score(findings)


async def _scan_commits(client: httpx.AsyncClient, org: str) -> list[dict]:
    findings = []
    try:
        r = await client.get(
            f"{GITHUB_BASE}/orgs/{org}/repos",
            params={"sort": "pushed", "per_page": 3, "type": "public"}
        )
        if r.status_code != 200:
            return findings

        for repo in r.json():
            full_name = repo.get("full_name", "")
            commits_r = await client.get(
                f"{GITHUB_BASE}/repos/{full_name}/commits",
                params={"per_page": 3}
            )
            if commits_r.status_code != 200:
                continue

            for commit in commits_r.json():
                sha = commit.get("sha", "")
                detail_r = await client.get(
                    f"{GITHUB_BASE}/repos/{full_name}/commits/{sha}"
                )
                if detail_r.status_code != 200:
                    continue
                for f in detail_r.json().get("files", []):
                    hits = _scan_text(f.get("patch", ""), full_name)
                    findings.extend(hits)
                if findings:
                    return findings

    except Exception as e:
        print(f"[GitHub] Commit scan error: {e}")

    return findings


def _demo_fallback(company: str) -> Tuple[list[dict], int]:
    data = DEMO_GITHUB_DATA[company]
    findings = [{
        "type": "code_exposure",
        "detail": (
            f"GitHub org '{data['org']}' found with {data['repos']} public repos. "
            f"Attackers can enumerate contributors, commit history, and internal "
            f"tooling references across all public repositories."
        ),
        "severity": "low",
    }]
    print(f"[GitHub] Demo fallback: {len(findings)} findings for {company}")
    return findings, _score(findings)
