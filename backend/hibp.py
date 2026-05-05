"""
hibp.py — HaveIBeenPwned breach lookup by domain.

API key required: https://haveibeenpwned.com/API/Key
Cost: $3.50/month. Email troy@troyhunt.com explaining it's a student
hackathon project — he sometimes grants free researcher keys.

Set HIBP_API_KEY in your .env file.
If no key is present, falls back to curated demo data for known domains
so the app still works end-to-end while you wait for the key.
"""

import httpx
import os
from typing import Tuple
from dotenv import load_dotenv

load_dotenv()

HIBP_BASE = "https://haveibeenpwned.com/api/v3"
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")

# Fallback demo data — used when no API key is set
DEMO_BREACH_DATA = {
    "linkedin.com": [
        {"type": "breach", "detail": "LinkedIn breach (2012): 164,611,595 accounts exposed. Data types: Email addresses, Passwords.", "severity": "high"},
        {"type": "breach", "detail": "LinkedIn breach (2021): 125,000,000 accounts exposed. Data types: Email addresses, Names, Phone numbers.", "severity": "medium"},
    ],
    "adobe.com": [
        {"type": "breach", "detail": "Adobe breach (2013): 152,445,165 accounts exposed. Data types: Email addresses, Passwords, Usernames, Credit cards.", "severity": "high"},
    ],
    "twitter.com": [
        {"type": "breach", "detail": "Twitter breach (2022): 5,485,636 accounts exposed. Data types: Email addresses, Phone numbers.", "severity": "medium"},
    ],
    "dropbox.com": [
        {"type": "breach", "detail": "Dropbox breach (2012): 68,648,009 accounts exposed. Data types: Email addresses, Passwords.", "severity": "high"},
    ],
}


def _breach_count_to_score(count: int) -> int:
    if count == 0:
        return 0
    elif count <= 2:
        return 25
    elif count <= 5:
        return 50
    elif count <= 10:
        return 70
    else:
        return 90


async def check_breaches(domain: str) -> Tuple[list[dict], int]:
    """
    Query HIBP for all breaches associated with a domain.

    Returns:
        findings  — list of Finding-compatible dicts
        score     — 0–100 credential exposure risk score
    """
    if HIBP_API_KEY:
        return await _query_hibp_api(domain)

    print(f"[HIBP] No API key set — using demo data for {domain}")
    return _demo_fallback(domain)


async def _query_hibp_api(domain: str) -> Tuple[list[dict], int]:
    url = f"{HIBP_BASE}/breaches?domain={domain}"
    headers = {
        "User-Agent": "OSINT-Scanner-HackathonProject/1.0",
        "hibp-api-key": HIBP_API_KEY,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers=headers)

            if response.status_code == 404:
                return [], 0
            if response.status_code == 401:
                print("[HIBP] Invalid API key — check your .env file")
                return [], 0
            if response.status_code != 200:
                print(f"[HIBP] Unexpected status {response.status_code} for {domain}")
                return [], 0

            breaches = response.json()

    except httpx.TimeoutException:
        print(f"[HIBP] Timeout for {domain}")
        return [], 0
    except Exception as e:
        print(f"[HIBP] Error for {domain}: {e}")
        return [], 0

    findings = []
    for breach in breaches:
        name = breach.get("Name", "Unknown")
        date = breach.get("BreachDate", "unknown date")
        count = breach.get("PwnCount", 0)
        data_classes = breach.get("DataClasses", [])

        sensitive = {"Passwords", "Credit cards", "Social security numbers", "Bank account numbers"}
        has_sensitive = bool(sensitive & set(data_classes))
        severity = "high" if has_sensitive else "medium"

        detail = (
            f"{name} breach ({date}): "
            f"{count:,} accounts exposed. "
            f"Data types: {', '.join(data_classes[:4])}."
        )
        findings.append({"type": "breach", "detail": detail, "severity": severity})

    return findings, _breach_count_to_score(len(breaches))


def _demo_fallback(domain: str) -> Tuple[list[dict], int]:
    """Return pre-curated findings for known domains, empty for unknown."""
    findings = DEMO_BREACH_DATA.get(domain, [])
    return findings, _breach_count_to_score(len(findings))
