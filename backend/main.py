from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from aggregator import run_all_sources

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

    # Run all data sources in parallel via the aggregator
    scan_data = await run_all_sources(domain)

    categories = scan_data["categories"]
    all_findings = scan_data["findings"]
    overall = scan_data["overall_score"]

    # Placeholder narrative and remediations — Claude API replaces this in Week 3
    narrative = (
        f"Preliminary scan of {domain} complete. "
        f"Credential exposure score: {categories['credential_exposure']}/100. "
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
