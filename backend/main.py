from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from aggregator    import run_all_sources
from ai_synthesis  import generate_narrative

app = FastAPI(title="OSINT Attack Surface Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    domain: str


class Finding(BaseModel):
    type: str
    detail: str
    severity: str


class ScanResponse(BaseModel):
    domain:        str
    overall_score: int
    categories:    dict
    findings:      list[Finding]
    narrative:     str
    phishing_email: str
    remediations:  list[str]


@app.get("/")
def root():
    return {"status": "OSINT Scanner API is running"}


@app.post("/scan", response_model=ScanResponse)
async def scan_domain(req: ScanRequest):
    domain = req.domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Invalid domain format")

    # Run all four data sources in parallel
    scan_data = await run_all_sources(domain)

    categories   = scan_data["categories"]
    all_findings = scan_data["findings"]
    overall      = scan_data["overall_score"]

    # Generate AI narrative — falls back to placeholder if no API key
    ai = await generate_narrative(domain, all_findings, categories)

    return ScanResponse(
        domain         = domain,
        overall_score  = overall,
        categories     = categories,
        findings       = all_findings,
        narrative      = ai["narrative"],
        phishing_email = ai["phishing_email"],
        remediations   = ai["remediations"],
    )
