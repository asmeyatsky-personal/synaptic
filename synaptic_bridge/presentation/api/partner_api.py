"""
Partner API

Following PRD Phase 4: Partner API for ISVs (Independent Software Vendors).
REST API for partners to integrate with SynapticBridge.
"""

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Any, Optional
from datetime import datetime, UTC
import hashlib
import secrets


app = FastAPI(title="SynapticBridge Partner API", version="1.0.0")


PARTNER_API_KEYS = {}


class PartnerRegistration(BaseModel):
    organization_name: str
    contact_email: str
    website: str
    use_case: str


class PartnerAPIKey(BaseModel):
    partner_id: str
    api_key: str
    created_at: str
    expires_at: str
    rate_limit: int = 1000


class PartnerToolRegistration(BaseModel):
    tool_name: str
    tool_description: str
    capabilities: list[str]
    endpoint: str
    authentication_type: str


class UsageReport(BaseModel):
    partner_id: str
    period_start: str
    period_end: str
    total_requests: int
    total_errors: int
    avg_latency_ms: float


@app.post("/partners/register", tags=["Partners"])
async def register_partner(registration: PartnerRegistration) -> dict:
    """Register a new partner organization."""
    partner_id = f"partner_{secrets.token_hex(8)}"

    api_key = f"sk_live_{secrets.token_hex(32)}"

    expires_at = datetime.now(UTC)
    from datetime import timedelta

    expires_at = (expires_at + timedelta(days=365)).isoformat()

    partner = PartnerAPIKey(
        partner_id=partner_id,
        api_key=api_key,
        created_at=datetime.now(UTC).isoformat(),
        expires_at=expires_at,
    )

    PARTNER_API_KEYS[api_key] = partner

    return {
        "partner_id": partner_id,
        "api_key": api_key,
        "status": "active",
        "expires_at": expires_at,
    }


def verify_partner_api_key(api_key: str = Header(...)) -> PartnerAPIKey:
    """Verify partner API key."""
    if api_key not in PARTNER_API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")

    partner = PARTNER_API_KEYS[api_key]

    expires = datetime.fromisoformat(partner.expires_at)
    if datetime.now(UTC) > expires:
        raise HTTPException(status_code=401, detail="API key expired")

    return partner


@app.post("/partners/tools", tags=["Partner Tools"])
async def register_partner_tool(
    tool: PartnerToolRegistration,
    partner: PartnerAPIKey = Depends(verify_partner_api_key),
) -> dict:
    """Register a partner's tool for SynapticBridge."""
    return {
        "status": "registered",
        "tool_id": f"partner_tool_{secrets.token_hex(8)}",
        "partner_id": partner.partner_id,
    }


@app.get("/partners/tools", tags=["Partner Tools"])
async def list_partner_tools(
    partner: PartnerAPIKey = Depends(verify_partner_api_key),
) -> list[dict]:
    """List all tools registered by a partner."""
    return [
        {
            "tool_id": f"partner_tool_{secrets.token_hex(4)}",
            "tool_name": "example.tool",
            "status": "active",
        }
    ]


@app.get("/partners/usage", tags=["Analytics"])
async def get_partner_usage(
    period: Optional[str] = "30d",
    partner: PartnerAPIKey = Depends(verify_partner_api_key),
) -> UsageReport:
    """Get usage statistics for a partner."""
    return UsageReport(
        partner_id=partner.partner_id,
        period_start=datetime.now(UTC).isoformat(),
        period_end=datetime.now(UTC).isoformat(),
        total_requests=1000,
        total_errors=5,
        avg_latency_ms=45.2,
    )


@app.get("/partners/cle/patterns", tags=["CLE"])
async def list_available_patterns(
    partner: PartnerAPIKey = Depends(verify_partner_api_key),
) -> list[dict]:
    """List CLE patterns available for partner use."""
    return [
        {
            "pattern_id": "pattern_001",
            "name": "File Read → Database Query",
            "success_rate": 0.85,
            "price": 0,
        }
    ]


@app.post("/partners/cle/patterns/import", tags=["CLE"])
async def import_cle_pattern(
    pattern_data: dict,
    partner: PartnerAPIKey = Depends(verify_partner_api_key),
) -> dict:
    """Import a CLE pattern for partner use."""
    return {
        "status": "imported",
        "local_pattern_id": f"imported_{secrets.token_hex(8)}",
    }


@app.get("/health", tags=["System"])
async def health_check():
    """Partner API health check."""
    return {"status": "healthy", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
