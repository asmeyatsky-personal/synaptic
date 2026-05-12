"""Coverage for error paths and middleware in presentation/api/main.py."""

import os

os.environ["TESTING"] = "1"

import pytest
from httpx import ASGITransport, AsyncClient

from synaptic_bridge.presentation.api.main import app


@pytest.mark.asyncio
async def test_security_headers_present():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get("/health/live")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Cache-Control"] == "no-store"


@pytest.mark.asyncio
async def test_request_too_large_rejected(monkeypatch):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post(
            "/sessions",
            content=b"x" * 10,
            headers={"content-length": str(10**7)},
        )
    assert r.status_code == 413


@pytest.mark.asyncio
async def test_missing_authorization_header():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get("/sessions/abc")
    assert r.status_code in (401, 422)


@pytest.mark.asyncio
async def test_invalid_bearer_token():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get("/sessions/abc", headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_invalid_scheme_rejected():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get("/sessions/abc", headers={"Authorization": "Basic xyz"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_invalid_session_request_payload():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post("/sessions", json={"agent_id": "", "created_by": "u"})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_invalid_tool_register_payload():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post(
            "/tools",
            headers={"Authorization": "Bearer garbage"},
            json={
                "tool_name": "ok",
                "version": "not-semver",
                "capabilities": [],
                "scope": "s",
            },
        )
    assert r.status_code in (401, 422)


@pytest.mark.asyncio
async def test_root_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get("/")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_readiness_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get("/health/ready")
    assert r.status_code in (200, 503)


@pytest.mark.asyncio
async def test_execute_unauthenticated():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.post("/execute", json={"session_id": "s", "tool_name": "t", "intent": "i"})
    assert r.status_code in (401, 422)


@pytest.mark.asyncio
async def test_execute_session_mismatch():
    import jwt

    from synaptic_bridge.presentation.api.main import get_secret_key

    token = jwt.encode(
        {"session_id": "session-A", "agent_id": "agent"},
        get_secret_key(),
        algorithm="HS256",
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Create real session
        sess_resp = await client.post(
            "/sessions", json={"agent_id": "agent-x", "created_by": "u-1"}
        )
        assert sess_resp.status_code == 200
        r = await client.post(
            "/execute",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "session_id": "session-B",
                "tool_name": "x.y",
                "parameters": {},
                "intent": "test intent",
            },
        )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_metrics_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get("/metrics")
    assert r.status_code == 200
