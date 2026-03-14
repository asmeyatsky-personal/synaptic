"""
SynapticBridge Presentation Layer - FastAPI

REST API for SynapticBridge MCP orchestration platform.
"""

import os
import uuid
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from typing import Any, Optional
from typing_extensions import Annotated

from synaptic_bridge.infrastructure.config import create_container
from synaptic_bridge.infrastructure.mcp_servers import (
    SessionMCPServer,
    ToolMCPServer,
    CLEMPServer,
    PolicyMCPServer,
)

app = FastAPI(
    title="SynapticBridge API",
    version="1.0.0",
    description="MCP Orchestration Platform with Correction Learning Engine",
    docs_url="/docs",
    redoc_url="/redoc",
)

container = create_container()

session_server = SessionMCPServer(container)
tool_server = ToolMCPServer(container)
cle_server = CLEMPServer(container)
policy_server = PolicyMCPServer(container)


SECRET_KEY = os.environ.get("JWT_SECRET", "synaptic-bridge-change-me-in-production")


async def verify_token(authorization: Annotated[str, Header()]) -> str:
    """Verify JWT token from Authorization header."""
    import jwt

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = authorization[7:]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        session_id = payload.get("session_id")
        if not session_id:
            raise HTTPException(
                status_code=401, detail="Invalid token: missing session_id"
            )
        return session_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


class CreateSessionRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=100)
    created_by: str = Field(..., min_length=1, max_length=100)

    @field_validator("agent_id", "created_by")
    @classmethod
    def validate_alphanumeric(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Must be alphanumeric with - or _")
        return v


class ExecuteToolRequest(BaseModel):
    session_id: str = Field(..., min_length=1)
    tool_name: str = Field(..., min_length=1, max_length=100)
    parameters: dict = Field(default_factory=dict)
    intent: str = Field(..., min_length=1, max_length=1000)

    @field_validator("tool_name")
    @classmethod
    def validate_tool_name(cls, v: str) -> str:
        if not v.replace(".", "").replace("_", "").replace("-", "").isalnum():
            raise ValueError("Invalid tool name format")
        return v


class RegisterToolRequest(BaseModel):
    tool_name: str = Field(..., min_length=1, max_length=100)
    version: str = Field(..., pattern=r"^\d+\.\d+\.\d+$")
    capabilities: list[str] = Field(..., min_length=1)
    scope: str = Field(..., min_length=1, max_length=200)
    ttl_seconds: int = Field(default=900, ge=60, le=86400)
    network_egress: bool = Field(default=False)
    audit_level: str = Field(default="summary", pattern="^(none|summary|full)$")
    signature: str = Field(default="")

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, v: list[str]) -> list[str]:
        valid = {"read", "write", "execute", "network"}
        for cap in v:
            if cap not in valid:
                raise ValueError(f"Invalid capability: {cap}. Must be one of: {valid}")
        return v


class CaptureCorrectionRequest(BaseModel):
    session_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1, max_length=100)
    original_intent: str = Field(..., min_length=1, max_length=1000)
    inferred_context: str = Field(..., min_length=1, max_length=1000)
    original_tool: str = Field(..., min_length=1, max_length=100)
    corrected_tool: str = Field(..., min_length=1, max_length=100)
    correction_metadata: dict = Field(default_factory=dict)
    operator_identity: str = Field(..., min_length=1, max_length=100)
    confidence_before: float = Field(..., ge=0.0, le=1.0)
    confidence_after: float = Field(..., ge=0.0, le=1.0)


class AddPolicyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., min_length=1, max_length=500)
    rego_code: str = Field(..., min_length=1)
    effect: str = Field(..., pattern="^(allow|deny)$")
    scope: str = Field(..., pattern="^(tool|session|agent|network)$")
    tags: list[str] = Field(default_factory=list)


@app.get("/")
async def root():
    return {
        "name": "SynapticBridge",
        "version": "1.0.0",
        "description": "MCP Orchestration Platform with Correction Learning Engine",
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "synaptic-bridge", "version": "1.0.0"}


@app.post("/sessions")
async def create_session(request: CreateSessionRequest):
    """Create a new agent execution session."""
    try:
        result = await session_server.create_session(
            agent_id=request.agent_id,
            created_by=request.created_by,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.post("/execute")
async def execute_tool(
    request: ExecuteToolRequest,
    session_id_from_token: str = Depends(verify_token),
):
    """Execute a tool with policy checks and CLE."""
    if request.session_id != session_id_from_token:
        raise HTTPException(
            status_code=403, detail="Session ID in request does not match token"
        )

    try:
        result = await session_server.execute_tool(
            session_id=request.session_id,
            tool_name=request.tool_name,
            parameters=request.parameters,
            intent=request.intent,
        )
        return result
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.get("/sessions/{session_id}")
async def get_session(session_id: str):
    """Get session by ID."""
    result = await session_server.get_session(session_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return result


@app.post("/tools")
async def register_tool(request: RegisterToolRequest):
    """Register a new tool manifest."""
    try:
        result = await tool_server.register_tool(
            tool_name=request.tool_name,
            version=request.version,
            capabilities=request.capabilities,
            scope=request.scope,
            ttl_seconds=request.ttl_seconds,
            network_egress=request.network_egress,
            audit_level=request.audit_level,
            signature=request.signature,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.get("/tools")
async def list_tools():
    """List all registered tools."""
    return await tool_server.list_tools()


@app.post("/corrections")
async def capture_correction(request: CaptureCorrectionRequest):
    """Capture a human override/correction."""
    try:
        result = await cle_server.capture_correction(
            session_id=request.session_id,
            agent_id=request.agent_id,
            original_intent=request.original_intent,
            inferred_context=request.inferred_context,
            original_tool=request.original_tool,
            corrected_tool=request.corrected_tool,
            correction_metadata=request.correction_metadata,
            operator_identity=request.operator_identity,
            confidence_before=request.confidence_before,
            confidence_after=request.confidence_after,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.post("/policies")
async def add_policy(request: AddPolicyRequest):
    """Add a new OPA policy."""
    try:
        result = await policy_server.add_policy(
            name=request.name,
            description=request.description,
            rego_code=request.rego_code,
            effect=request.effect,
            scope=request.scope,
            tags=request.tags,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.get("/policies")
async def list_policies():
    """List all policies."""
    return await policy_server.list_policies()


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for unhandled errors."""
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "path": str(request.url),
        },
    )
