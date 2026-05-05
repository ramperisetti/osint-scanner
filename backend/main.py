from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio

from hibp import check_breaches

app = FastAPI(title="OSINT Attack Surface Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this before production
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    domain: str


class Finding(BaseModel):
    type: str
    detail: str
    severity: str  # "high" | "medium" | "low"


class ScanResponse(BaseModel):
    domain: str
    overall_score: int
    categories: dict
    findings: list[Finding]
    narrative: str
    remediations: list[str]


def compute_overall_score(categories: dict) -> int:
    """Average of all category scores, rounded to int."""
    if not categories:
        return 0
    return round(sum(categories.values()) / len(categories))


@app.get("/")
def root():
    return {"status": "OSINT Scanner API is running"}


@app.post("/scan", response_model=ScanResponse)
async def scan_domain(req: ScanRequest):
    domain = req.domain.strip().lower()

    # Basic validation — strip http/https if someone pastes a URL
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Invalid domain format")

    # --- Run data sources (add more here as you build them) ---
    breach_findings, breach_score = await check_breaches(domain)

    # Placeholder scores for sources not yet built (Week 2)
    categories = {
        "credential_exposure": breach_score,
        "saas_stack_exposure": 0,   # job_scraper.py — Week 2
        "code_exposure": 0,         # github_scan.py — Week 2
        "org_intel": 0,             # dns_scan.py — Week 2
    }

    all_findings = breach_findings
    # Week 2: extend all_findings with results from other modules

    overall = compute_overall_score({k: v for k, v in categories.items() if v > 0})

    # Placeholder narrative and remediations — Claude API replaces this in Week 3
    narrative = (
        f"Preliminary scan of {domain} complete. "
        f"Credential exposure score: {breach_score}/100. "
        f"Full AI-generated attacker narrative will appear here in Week 3."
    )

    remediations = [
        "Enable multi-factor authentication across all employee accounts.",
        "Subscribe to breach monitoring and force resets for exposed emails.",
        "Audit third-party SaaS access and revoke unused OAuth tokens.",
    ]

    return ScanResponse(
        domain=domain,
        overall_score=overall,
        categories=categories,
        findings=all_findings,
        narrative=narrative,
        remediations=remediations,
    )
