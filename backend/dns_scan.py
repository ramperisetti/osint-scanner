"""
dns_scan.py — DNS enumeration and org intelligence.

Checks:
1. MX records — identifies email provider (Google vs Microsoft vs custom)
2. SPF record — missing/weak SPF means email spoofing is possible
3. Subdomain enumeration — dev/staging/vpn/admin exposure
4. Domain age via WHOIS

Handles timeouts gracefully — a timeout returns no finding for that
check rather than a false positive.
"""

import asyncio
import dns.resolver
import dns.exception
from typing import Tuple, Union
from datetime import datetime

NO_DATA = "NO_DATA"

SUBDOMAINS = [
    "dev", "staging", "stage", "test", "qa",
    "api", "internal", "intranet", "vpn", "remote",
    "admin", "portal", "dashboard", "jenkins",
    "gitlab", "jira", "mail", "smtp", "legacy",
]

HIGH_VALUE_SUBS = {
    "dev", "staging", "stage", "vpn", "admin",
    "internal", "intranet", "rdp", "jenkins", "gitlab",
}

MX_PROVIDERS = {
    "google":      ("Google Workspace", "Craft fake Google login or Drive sharing notifications."),
    "googlemail":  ("Google Workspace", "Craft fake Google login or Drive sharing notifications."),
    "outlook":     ("Microsoft 365",    "Craft fake M365 login, Teams notification, or SharePoint alert."),
    "microsoft":   ("Microsoft 365",    "Craft fake M365 login, Teams notification, or SharePoint alert."),
    "protection":  ("Microsoft 365",    "Craft fake M365 login, Teams notification, or SharePoint alert."),
    "mimecast":    ("Mimecast",         "Craft fake Mimecast security alert or quarantine notification."),
    "proofpoint":  ("Proofpoint",       "Craft fake Proofpoint quarantine release notification."),
    "amazonses":   ("Amazon SES",       "Reveals AWS usage — confirms AWS as a platform target."),
    "sendgrid":    ("SendGrid",         "Reveals email delivery stack."),
}


def _resolve(qname: str, rtype: str, timeout: float = 4.0) -> list[str]:
    """DNS lookup with timeout. Returns empty list on any failure."""
    try:
        answers = dns.resolver.resolve(qname, rtype, lifetime=timeout)
        return [str(r) for r in answers]
    except Exception:
        return []


async def scan_dns(domain: str) -> Tuple[list[dict], Union[int, str]]:
    """
    Run all DNS checks concurrently.
    Returns (findings, score) or ([], NO_DATA) if domain doesn't resolve.
    """
    # Quick check — does the domain resolve at all?
    a_records = await asyncio.to_thread(_resolve, domain, "A")
    if not a_records:
        print(f"[DNS] {domain} does not resolve — skipping")
        return [], NO_DATA

    # Run all checks concurrently
    mx_f, spf_f, sub_f, age_f = await asyncio.gather(
        asyncio.to_thread(_check_mx,      domain),
        asyncio.to_thread(_check_spf,     domain),
        asyncio.to_thread(_check_subs,    domain),
        asyncio.to_thread(_check_age,     domain),
    )

    findings = mx_f + spf_f + sub_f + age_f
    score    = _score(findings)
    print(f"[DNS] {len(findings)} findings for {domain}, score: {score}")
    return findings, score


def _check_mx(domain: str) -> list[dict]:
    records = _resolve(domain, "MX")
    if not records:
        return []

    for record in records:
        rl = record.lower()
        for keyword, (name, attack) in MX_PROVIDERS.items():
            if keyword in rl:
                return [{
                    "type": "org_intel",
                    "detail": (
                        f"Email provider: {name} (MX: {record.strip()}). "
                        f"Attacker can {attack}"
                    ),
                    "severity": "medium",
                }]

    # Unknown provider
    host = records[0].split()[-1] if records else "unknown"
    return [{
        "type": "org_intel",
        "detail": f"Custom MX: {host}. May indicate self-hosted mail infrastructure.",
        "severity": "low",
    }]


def _check_spf(domain: str) -> list[dict]:
    records = _resolve(domain, "TXT")
    if not records:
        # Timeout or no records — don't report false positive
        return []

    spf = next((r for r in records if "v=spf1" in r.lower()), None)

    if spf is None:
        return [{
            "type": "org_intel",
            "detail": (
                f"No SPF record on {domain}. Attackers may send spoofed emails "
                f"appearing to come from @{domain} — highly effective for phishing."
            ),
            "severity": "high",
        }]

    if "+all" in spf or "?all" in spf:
        return [{
            "type": "org_intel",
            "detail": (
                f"Permissive SPF (+all or ?all) on {domain}. "
                f"Any server can send mail as @{domain}."
            ),
            "severity": "high",
        }]

    if "~all" in spf:
        return [{
            "type": "org_intel",
            "detail": (
                f"Soft-fail SPF (~all) on {domain}. "
                f"Spoofed emails may still reach some inboxes."
            ),
            "severity": "medium",
        }]

    # -all = properly configured, no finding
    return []


def _check_subs(domain: str) -> list[dict]:
    findings = []
    for sub in SUBDOMAINS:
        fqdn    = f"{sub}.{domain}"
        records = _resolve(fqdn, "A", timeout=2.0)
        if records:
            severity = "high" if sub in HIGH_VALUE_SUBS else "medium"
            findings.append({
                "type": "org_intel",
                "detail": (
                    f"Subdomain '{fqdn}' resolves publicly ({records[0]}). "
                    f"Exposed {sub} environment may be an accessible attack surface."
                ),
                "severity": severity,
            })
    return findings


def _check_age(domain: str) -> list[dict]:
    try:
        import whois
        w    = whois.whois(domain)
        date = w.creation_date
        if isinstance(date, list):
            date = date[0]
        if not date:
            return []

        days  = (datetime.now() - date).days
        years = days // 365

        if days < 365:
            return [{
                "type": "org_intel",
                "detail": (
                    f"{domain} registered only {days} days ago — "
                    f"unusually new for a legitimate organization."
                ),
                "severity": "medium",
            }]
        else:
            return [{
                "type": "org_intel",
                "detail": (
                    f"{domain} registered ~{years} year{'s' if years != 1 else ''} ago. "
                    f"Established domain with likely large employee base and "
                    f"extensive public footprint."
                ),
                "severity": "low",
            }]
    except Exception:
        return []


def _score(findings: list[dict]) -> int:
    high   = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    low    = sum(1 for f in findings if f["severity"] == "low")
    return min((high * 25) + (medium * 15) + (low * 5), 95)
