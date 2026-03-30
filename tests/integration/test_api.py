"""
Integration Tests

End-to-end tests for SynapticBridge API.
"""

import os

import jwt
import pytest

os.environ["TESTING"] = "1"

from httpx import ASGITransport, AsyncClient

from synaptic_bridge.presentation.api.main import app, get_secret_key


def _make_auth_header(session_id: str = "test-session") -> dict:
    """Create a valid JWT auth header for testing."""
    token = jwt.encode(
        {"session_id": session_id, "agent_id": "test-agent"},
        get_secret_key(),
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}

    token = jwt.encode(
        {"session_id": session_id, "agent_id": "test-agent"},
        get_secret_key(),  # use the same secret as the API
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


class TestHealthEndpoint:
    """Test health check endpoint."""

    @pytest.mark.asyncio
    async def test_health_check(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_root_endpoint(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/")
            assert response.status_code == 200
            data = response.json()
            assert data["name"] == "SynapticBridge"
            assert "version" in data

    @pytest.mark.asyncio
    async def test_security_headers(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")
            assert response.headers["X-Content-Type-Options"] == "nosniff"
            assert response.headers["X-Frame-Options"] == "DENY"
            assert response.headers["X-XSS-Protection"] == "1; mode=block"
            assert response.headers["Cache-Control"] == "no-store"


class TestSessionEndpoints:
    """Test session management endpoints."""

    @pytest.mark.asyncio
    async def test_create_session(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/sessions", json={"agent_id": "agent-1", "created_by": "admin"}
            )
            assert response.status_code == 200
            data = response.json()
            assert "session_id" in data
            assert "execution_token" in data

    @pytest.mark.asyncio
    async def test_create_session_validation(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/sessions", json={"agent_id": "", "created_by": "admin"})
            assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_get_session(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            create_response = await client.post(
                "/sessions", json={"agent_id": "agent-1", "created_by": "admin"}
            )
            session_id = create_response.json()["session_id"]

            headers = _make_auth_header(session_id)
            response = await client.get(f"/sessions/{session_id}", headers=headers)
            assert response.status_code == 200
            data = response.json()
            assert data["session_id"] == session_id

    @pytest.mark.asyncio
    async def test_get_session_requires_auth(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/sessions/some-id")
            assert response.status_code == 422  # missing auth header

    @pytest.mark.asyncio
    async def test_get_session_not_found(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = _make_auth_header()
            response = await client.get("/sessions/nonexistent", headers=headers)
            assert response.status_code == 404


class TestToolEndpoints:
    """Test tool management endpoints."""

    @pytest.mark.asyncio
    async def test_register_tool(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = _make_auth_header()
            response = await client.post(
                "/tools",
                json={
                    "tool_name": "filesystem.read",
                    "version": "1.0.0",
                    "capabilities": ["read"],
                    "scope": "workspace:current",
                    "ttl_seconds": 900,
                    "network_egress": False,
                    "audit_level": "summary",
                    "signature": "test-sig",
                },
                headers=headers,
            )
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_register_tool_requires_auth(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/tools",
                json={
                    "tool_name": "test.tool",
                    "version": "1.0.0",
                    "capabilities": ["read"],
                    "scope": "test",
                },
            )
            assert response.status_code == 422  # missing auth header

    @pytest.mark.asyncio
    async def test_list_tools(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/tools")
            assert response.status_code == 200
            data = response.json()
            assert "items" in data
            assert "total" in data

    @pytest.mark.asyncio
    async def test_list_tools_pagination(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/tools?limit=5&offset=0")
            assert response.status_code == 200
            data = response.json()
            assert "items" in data
            assert "total" in data


class TestPolicyEndpoints:
    """Test policy management endpoints."""

    @pytest.mark.asyncio
    async def test_add_policy(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = _make_auth_header()
            response = await client.post(
                "/policies",
                json={
                    "name": "Test Policy",
                    "description": "A test policy",
                    "rego_code": 'package test\ndeny { input.tool == "bad" }',
                    "effect": "deny",
                    "scope": "tool",
                    "tags": ["test"],
                },
                headers=headers,
            )
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_add_policy_requires_auth(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/policies",
                json={
                    "name": "Test",
                    "description": "Test",
                    "rego_code": "package test\nallow { true }",
                    "effect": "allow",
                    "scope": "tool",
                },
            )
            assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_list_policies(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/policies")
            assert response.status_code == 200
            data = response.json()
            assert "items" in data
            assert "total" in data


class TestCorrectionEndpoints:
    """Test correction capture endpoints."""

    @pytest.mark.asyncio
    async def test_capture_correction(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = _make_auth_header()
            response = await client.post(
                "/corrections",
                json={
                    "session_id": "session-1",
                    "agent_id": "agent-1",
                    "original_intent": "read file",
                    "inferred_context": "user wants data",
                    "original_tool": "bad.tool",
                    "corrected_tool": "good.tool",
                    "operator_identity": "admin",
                    "confidence_before": 0.5,
                    "confidence_after": 0.9,
                },
                headers=headers,
            )
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_capture_correction_requires_auth(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/corrections",
                json={
                    "session_id": "s1",
                    "agent_id": "a1",
                    "original_intent": "read",
                    "inferred_context": "ctx",
                    "original_tool": "old",
                    "corrected_tool": "new",
                    "operator_identity": "admin",
                    "confidence_before": 0.5,
                    "confidence_after": 0.9,
                },
            )
            assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_capture_correction_validation(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = _make_auth_header()
            response = await client.post(
                "/corrections",
                json={
                    "session_id": "s1",
                    "agent_id": "a1",
                    "original_intent": "read",
                    "inferred_context": "ctx",
                    "original_tool": "old",
                    "corrected_tool": "new",
                    "operator_identity": "admin",
                    "confidence_before": 1.5,  # invalid: > 1.0
                    "confidence_after": 0.9,
                },
                headers=headers,
            )
            assert response.status_code == 422


class TestGlobalErrorHandler:
    """Test the global error handler."""

    @pytest.mark.asyncio
    async def test_error_response_no_path_leak(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = _make_auth_header()
            response = await client.get("/sessions/nonexistent", headers=headers)
            data = response.json()
            assert "path" not in data
