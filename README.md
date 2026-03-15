# SynapticBridge

![SynapticBridge Architecture](synaptic.jpg)

Autonomous, self-correcting MCP orchestration platform for AI agents with Correction Learning Engine (CLE).

## Overview

SynapticBridge is an enterprise-grade platform for deploying AI agents at scale with:
- **Secure Execution Fabric** - Tool manifests, JWT tokens, cryptographic audit logging
- **Correction Learning Engine (CLE)** - Learns from human overrides to predict corrections
- **Autonomous Routing** - Intent-to-tool mapping with multi-hop chain planning
- **Policy & Governance** - OPA policy engine with Rego policies

## Features

- 🔒 **Zero-Trust Security** - SPIFFE/SPIRE workload identity, no env credentials
- 📊 **Real-time Observability** - Call graph visualization, drift detection
- 🔄 **CLE Predictive Dispatch** - 70% reduction in human interruptions
- 🌐 **SIEM Integration** - Splunk, Datadog, GCP, Azure Sentinel
- 📦 **MCP Native** - Works with Claude Code, any MCP-compatible agent

## Quick Start

### Docker

```bash
docker-compose up -d
```

### Manual

```bash
pip install -e .
python -m uvicorn synaptic_bridge.presentation.api.main:app --reload
```

Visit http://localhost:8000/docs for API documentation.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Presentation Layer                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   FastAPI   │  │     CLI     │  │  Claude Code MCP   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐    │
│  │ Commands  │  │  Queries │  │  DAG Orchestration  │    │
│  └──────────┘  └──────────┘  └──────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      Domain Layer                           │
│  ┌───────┐ ┌──────────┐ ┌────────┐ ┌───────┐ ┌─────────┐  │
│  │Tools  │ │ Sessions │ │  CLE   │ │Policy │ │ Audit  │  │
│  └───────┘ └──────────┘ └────────┘ └───────┘ └─────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                  Infrastructure Layer                        │
│  ┌──────────┐  ┌────────┐  ┌────────┐  ┌──────────────┐  │
│  │  DuckDB  │  │  OPA   │  │ SPIFFE │  │ SIEM Connect│  │
│  └──────────┘  └────────┘  └────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## API Usage

### Create Session

```bash
curl -X POST http://localhost:8000/sessions \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "agent-1", "created_by": "admin"}'
```

### Execute Tool

```bash
curl -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "session_id": "session_xxx",
    "tool_name": "bash.execute",
    "parameters": {"command": "ls"},
    "intent": "list files in directory"
  }'
```

### Capture Correction

```bash
curl -X POST http://localhost:8000/corrections \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "session_xxx",
    "agent_id": "agent-1",
    "original_intent": "delete all files",
    "original_tool": "bash.execute",
    "corrected_tool": "bash.ls",
    "operator_identity": "admin",
    "confidence_before": 0.5,
    "confidence_after": 0.9
  }'
```

## CLI

```bash
# Register a tool
python -m synaptic_bridge.presentation.cli.main register-tool \
  --name my.tool --version 1.0.0 \
  --capabilities read write --scope workspace

# Add a policy
python -m synaptic_bridge.presentation.cli.main add-policy \
  --name "Deny Network" --rego 'package test\ndeny { input.tool == "network" }' \
  --effect deny --scope network

# Query logs
python -m synaptic_bridge.presentation.cli.main query-logs --session session_xxx
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | JWT signing secret | (development) |
| `DUCKDB_PATH` | DuckDB database path | `synaptic_bridge.duckdb` |
| `SPIRE_SOCKET_PATH` | SPIRE agent socket | `/tmp/spire-agent.sock` |
| `SPLUNK_ENDPOINT` | Splunk HEC endpoint | - |
| `DATADOG_API_KEY` | Datadog API key | - |
| `GCP_PROJECT_ID` | GCP project ID | - |

## Testing

```bash
# Unit tests
pytest tests/domain/ -v

# Integration tests
pytest tests/integration/ -v

# All tests with coverage
pytest --cov=synaptic_bridge
```

## PRD Conformance

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | Tool manifests, JWT tokens, audit | ✅ |
| 1 | CLE correction capture, patterns | ✅ |
| 1 | OPA policy engine | ✅ |
| 2 | CLE predictive dispatch | ✅ |
| 2 | Multi-hop chain planner | ✅ |
| 2 | Drift detection | ✅ |
| 3 | SIEM connectors | ✅ |
| 3 | WORM audit storage | ✅ |
| 4 | Claude Code integration | ✅ |
| 4 | CLE pattern marketplace | ✅ |
| 4 | Partner API | ✅ |

## License

Proprietary - All rights reserved
