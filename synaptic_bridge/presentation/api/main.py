"""
SynapticBridge Presentation Layer - FastAPI

REST API for SynapticBridge MCP orchestration platform.
"""

import logging
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Header, Depends, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from typing import Any, Optional
from typing_extensions import Annotated

from synaptic_bridge.domain.constants import (
    API_VERSION,
    DEFAULT_TTL_SECONDS,
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
)
from synaptic_bridge.domain.exceptions import (
    ConfigurationError,
    PolicyViolationError,
    SessionNotFoundError,
    SessionExpiredError,
    ToolNotFoundError,
    SynapticBridgeError,
)
from synaptic_bridge.infrastructure.config import create_container
from synaptic_bridge.infrastructure.mcp_servers import (
    SessionMCPServer,
    ToolMCPServer,
    CLEMPServer,
    PolicyMCPServer,
)

logger = logging.getLogger("synaptic-bridge.api")


def _get_secret_key() -> str:
    """Get JWT secret key, failing fast if not configured."""
    key = os.environ.get("JWT_SECRET")
    if not key:
        raise ConfigurationError(
            "JWT_SECRET environment variable is required. "
            "Set it to a cryptographically strong random value."
        )
    return key


# Lazy-loaded secret key (validated on first use)
_secret_key: str | None = None


def get_secret_key() -> str:
    global _secret_key
    if _secret_key is None:
        # Allow unset in test environments
        _secret_key = os.environ.get("JWT_SECRET", "")
        if not _secret_key and os.environ.get("TESTING") != "1":
            raise ConfigurationError(
                "JWT_SECRET environment variable is required. "
                "Set it to a cryptographically strong random value."
            )
    return _secret_key


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown."""
    logger.info("SynapticBridge API starting up")
    yield
    logger.info("SynapticBridge API shutting down")
    # Close DuckDB connections if present
    try:
        store = container.resolve("correction_store")
        if hasattr(store, "close"):
            store.close()
    except Exception:
        pass


app = FastAPI(
    title="SynapticBridge API",
    version=API_VERSION,
    description="MCP Orchestration Platform with Correction Learning Engine",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware
allowed_origins = os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",")
allowed_origins = [o.strip() for o in allowed_origins if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins or [],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=3600,
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    if os.environ.get("ENFORCE_HTTPS"):
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


container = create_container()

session_server = SessionMCPServer(container)
tool_server = ToolMCPServer(container)
cle_server = CLEMPServer(container)
policy_server = PolicyMCPServer(container)


async def verify_token(authorization: Annotated[str, Header()]) -> str:
    """Verify JWT token from Authorization header."""
    import jwt

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = authorization[7:]
    try:
        secret = get_secret_key()
        payload = jwt.decode(token, secret, algorithms=["HS256"])
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
    ttl_seconds: int = Field(default=DEFAULT_TTL_SECONDS, ge=60, le=86400)
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
        "version": API_VERSION,
        "description": "MCP Orchestration Platform with Correction Learning Engine",
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "synaptic-bridge", "version": API_VERSION}


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
        logger.exception("Failed to create session")
        raise HTTPException(status_code=500, detail="Internal server error")


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
    except PolicyViolationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except (SessionNotFoundError, ToolNotFoundError) as e:
        raise HTTPException(status_code=404, detail=str(e))
    except SessionExpiredError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except (PermissionError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("Failed to execute tool")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/sessions/{session_id}")
async def get_session(
    session_id: str,
    _session_id_from_token: str = Depends(verify_token),
):
    """Get session by ID. Requires authentication."""
    result = await session_server.get_session(session_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return result


@app.post("/tools")
async def register_tool(
    request: RegisterToolRequest,
    _session_id_from_token: str = Depends(verify_token),
):
    """Register a new tool manifest. Requires authentication."""
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
        logger.exception("Failed to register tool")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/tools")
async def list_tools(
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
):
    """List all registered tools with pagination."""
    tools = await tool_server.list_tools()
    return {"items": tools[offset : offset + limit], "total": len(tools)}


@app.post("/corrections")
async def capture_correction(
    request: CaptureCorrectionRequest,
    _session_id_from_token: str = Depends(verify_token),
):
    """Capture a human override/correction. Requires authentication."""
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
        logger.exception("Failed to capture correction")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/policies")
async def add_policy(
    request: AddPolicyRequest,
    _session_id_from_token: str = Depends(verify_token),
):
    """Add a new OPA policy. Requires authentication."""
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
        logger.exception("Failed to add policy")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/policies")
async def list_policies(
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
):
    """List all policies with pagination."""
    policies = await policy_server.list_policies()
    return {"items": policies[offset : offset + limit], "total": len(policies)}


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled errors."""
    logger.exception("Unhandled exception")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )
