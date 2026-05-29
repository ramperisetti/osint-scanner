"""
ai_synthesis.py — Generate attacker narrative using Claude API.

Takes all findings from the four data sources and produces:
1. A 3-paragraph attacker narrative — specific, alarming, grounded
   only in the data collected. Written from a red team perspective.
2. A realistic sample phishing email an attacker would send using
   only the intelligence gathered by this tool.
3. Three prioritized remediation actions specific to the findings.

The narrative is the centerpiece of the product. It transforms raw
data points into a story that makes judges stop and read.
"""

import os
import json
from anthropic import AsyncAnthropic
from dotenv import load_dotenv

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

client = AsyncAnthropic(api_key=ANTHROPIC_API_KEY) if ANTHROPIC_API_KEY else None


def _format_findings(findings: list[dict], categories: dict) -> str:
    """Format findings into a clean summary for the prompt."""
    lines = []

    # Category scores
    lines.append("RISK SCORES:")
    for cat, score in categories.items():
        lines.append(f"  {cat.replace('_', ' ').title()}: {score}/100")

    lines.append("")

    # Group findings by type
    breaches  = [f for f in findings if f["type"] == "breach"]
    saas      = [f for f in findings if f["type"] == "saas_tool"]
    code      = [f for f in findings if f["type"] == "code_exposure"]
    dns       = [f for f in findings if f["type"] == "org_intel"]

    if breaches:
        lines.append("DATA BREACHES:")
        for f in breaches:
            lines.append(f"  [{f['severity'].upper()}] {f['detail']}")

    if saas:
        lines.append("SAAS TOOLS IN USE (inferred from job postings):")
        tools = [f.get("tool", f["detail"].split("(")[0].strip()) for f in saas]
        lines.append(f"  {', '.join(tools)}")

    if code:
        lines.append("CODE / GITHUB EXPOSURE:")
        for f in code:
            lines.append(f"  [{f['severity'].upper()}] {f['detail']}")

    if dns:
        lines.append("DNS / ORG INTELLIGENCE:")
        for f in dns:
            lines.append(f"  [{f['severity'].upper()}] {f['detail']}")

    return "\n".join(lines)


SYSTEM_PROMPT = """You are a senior red team security analyst writing threat intelligence briefings.
Your job is to analyze OSINT findings about a target organization and produce a realistic,
specific attacker narrative grounded ONLY in the data provided.

Rules:
- Be specific. Reference actual findings by name (tool names, subdomain names, breach names).
- Never invent data not present in the findings.
- Write from the perspective of a sophisticated attacker planning a campaign.
- The narrative should make a security professional stop and take action.
- Keep language professional but direct — this is a threat brief, not a marketing document.
- The phishing email must use ONLY details from the findings — no invented information."""


async def generate_narrative(
    domain: str,
    findings: list[dict],
    categories: dict,
) -> dict:
    """
    Call Claude API to generate attacker narrative and phishing email.

    Returns dict with:
        narrative      — 3-paragraph threat brief
        phishing_email — realistic sample attack email
        remediations   — 3 specific, prioritized actions
    """
    if not client:
        print("[AI] No Anthropic API key — using placeholder narrative")
        return _placeholder(domain, findings, categories)

    findings_text = _format_findings(findings, categories)

    user_prompt = f"""Analyze this OSINT scan of {domain} and produce a threat intelligence brief.

{findings_text}

Produce a JSON response with exactly these three fields:

1. "narrative": Three paragraphs.
   - Paragraph 1: What an attacker learns from this data in their first 30 minutes of recon.
     Be specific — name the tools, breaches, subdomains found.
   - Paragraph 2: The most likely attack vector given these specific findings.
     Choose the highest-probability path: which tool would they spoof, which subdomain
     would they target, which employees are most vulnerable.
   - Paragraph 3: What a successful attack looks like end-to-end using only this data.
     Walk through the kill chain from initial phishing to likely goal.

2. "phishing_email": A realistic phishing email an attacker would send to a {domain} employee
   using ONLY the intelligence gathered above. Include:
   - A "from" line spoofing a known service (use the email provider and SaaS tools found)
   - A subject line
   - A short, convincing body (3-5 sentences max)
   - A call to action with a fake but plausible URL
   Make it scary-realistic. This is the demo moment that makes judges lean forward.

3. "remediations": An array of exactly 3 strings. Each is a specific, prioritized
   action that directly addresses the highest-severity findings above.
   Be concrete — not "improve security" but "immediately rotate credentials for the
   152M accounts exposed in the 2013 Adobe breach and enforce MFA on all Okta logins."

Return ONLY valid JSON. No markdown, no explanation, no backticks."""

    try:
        response = await client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )

        raw = response.content[0].text.strip()

        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()

        result = json.loads(raw)

        # Validate all three fields are present
        if not all(k in result for k in ["narrative", "phishing_email", "remediations"]):
            raise ValueError("Missing required fields in AI response")

        print(f"[AI] Narrative generated for {domain}")
        return result

    except json.JSONDecodeError as e:
        print(f"[AI] JSON parse error: {e} — using placeholder")
        return _placeholder(domain, findings, categories)
    except Exception as e:
        print(f"[AI] Error: {e} — using placeholder")
        return _placeholder(domain, findings, categories)


def _placeholder(domain: str, findings: list[dict], categories: dict) -> dict:
    """
    Fallback when no API key is set or the call fails.
    Returns a structured placeholder so the app still works.
    """
    tools  = [f.get("tool", "") for f in findings if f["type"] == "saas_tool"]
    tools  = [t for t in tools if t]
    breach = next((f for f in findings if f["type"] == "breach"), None)
    vpn    = next((f for f in findings if "vpn" in f.get("detail", "").lower()), None)

    tool_str   = ", ".join(tools[:3]) if tools else "internal platforms"
    breach_str = breach["detail"][:60] + "..." if breach else "no breaches found"

    narrative = (
        f"An attacker targeting {domain} would begin by reviewing the {len(findings)} "
        f"data points collected in this scan. Key intelligence includes: {breach_str}. "
        f"The organization uses {tool_str}, providing multiple spoofing opportunities.\n\n"
        f"The highest-probability attack vector is a spear-phishing campaign impersonating "
        f"one of the identified SaaS platforms. "
        f"{'An exposed VPN subdomain provides a potential network entry point. ' if vpn else ''}"
        f"Employees with credentials in known breach databases are primary targets.\n\n"
        f"A successful campaign would likely begin with a credential phishing email, "
        f"escalate to internal network access, and pivot toward sensitive data exfiltration. "
        f"Full AI narrative requires ANTHROPIC_API_KEY to be set in environment variables."
    )

    phishing_email = (
        f"From: security-noreply@{tools[0].lower().replace(' ', '') + '.com' if tools else 'platform.com'}\n"
        f"Subject: Action Required: Verify your {tools[0] if tools else 'account'} login\n\n"
        f"Your {tools[0] if tools else 'account'} session has expired. "
        f"Please verify your credentials to maintain access.\n\n"
        f"[Verify Account] → https://{tools[0].lower().replace(' ', '') if tools else 'secure'}"
        f"-{domain.split('.')[0]}-auth.com/verify\n\n"
        f"Full AI-generated phishing email requires ANTHROPIC_API_KEY."
    )

    remediations = [
        f"Immediately audit all accounts associated with {domain} against known breach databases and force password resets.",
        f"Restrict public access to exposed subdomains and enforce VPN-only access for internal services.",
        f"Implement DMARC/DKIM email authentication to prevent spoofing of @{domain} addresses.",
    ]

    return {
        "narrative":      narrative,
        "phishing_email": phishing_email,
        "remediations":   remediations,
    }
