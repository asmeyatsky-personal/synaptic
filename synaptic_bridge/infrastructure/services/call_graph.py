"""
Call Graph Service

Following PRD: Real-time DAG view of active tool chains; historical playback; correction overlays.
Provides call graph visualization data for the dashboard.
"""

import json
import uuid
from datetime import datetime, UTC
from dataclasses import dataclass, field
from typing import Any
from collections import defaultdict


@dataclass
class CallNode:
    """Represents a node in the call graph."""
    id: str
    tool_name: str
    session_id: str
    agent_id: str
    status: str
    started_at: str
    completed_at: str | None = None
    parameters: dict = field(default_factory=dict)
    result: Any = None
    error: str | None = None
    was_corrected: bool = False
    correction_id: str | None = None


@dataclass
class CallEdge:
    """Represents an edge in the call graph."""
    from_node: str
    to_node: str
    data_flow: dict = field(default_factory=dict)


class CallGraphService:
    """
    Service for managing call graphs.
    
    Following PRD: Real-time DAG view of active tool chains; historical playback; correction overlays.
    """
    
    def __init__(self):
        self._graphs: dict[str, dict] = {}
        self._active_sessions: set[str] = set()
    
    def start_session(self, session_id: str, agent_id: str) -> dict:
        """Initialize a new call graph for a session."""
        graph = {
            "session_id": session_id,
            "agent_id": agent_id,
            "nodes": [],
            "edges": [],
            "started_at": datetime.now(UTC).isoformat(),
            "status": "active",
        }
        
        self._graphs[session_id] = graph
        self._active_sessions.add(session_id)
        
        return graph
    
    def add_node(
        self,
        session_id: str,
        tool_name: str,
        parameters: dict,
        parent_node_id: str | None = None,
    ) -> str:
        """Add a node to the call graph."""
        if session_id not in self._graphs:
            raise ValueError(f"Session {session_id} not found")
        
        node_id = f"node_{uuid.uuid4().hex[:12]}"
        
        node = CallNode(
            id=node_id,
            tool_name=tool_name,
            session_id=session_id,
            agent_id=self._graphs[session_id]["agent_id"],
            status="in_progress",
            started_at=datetime.now(UTC).isoformat(),
            parameters=parameters,
        )
        
        self._graphs[session_id]["nodes"].append(node_id)
        self._graphs[session_id][node_id] = node
        
        if parent_node_id:
            edge = CallEdge(from_node=parent_node_id, to_node=node_id)
            self._graphs[session_id]["edges"].append({
                "from": edge.from_node,
                "to": edge.to_node,
            })
        
        return node_id
    
    def complete_node(
        self,
        session_id: str,
        node_id: str,
        result: Any,
        was_corrected: bool = False,
        correction_id: str | None = None,
    ) -> None:
        """Mark a node as completed."""
        if session_id not in self._graphs or node_id not in self._graphs[session_id]:
            raise ValueError(f"Node {node_id} not found in session {session_id}")
        
        node = self._graphs[session_id][node_id]
        node.status = "completed"
        node.completed_at = datetime.now(UTC).isoformat()
        node.result = result
        node.was_corrected = was_corrected
        node.correction_id = correction_id
    
    def fail_node(
        self,
        session_id: str,
        node_id: str,
        error: str,
    ) -> None:
        """Mark a node as failed."""
        if session_id not in self._graphs or node_id not in self._graphs[session_id]:
            raise ValueError(f"Node {node_id} not found in session {session_id}")
        
        node = self._graphs[session_id][node_id]
        node.status = "failed"
        node.completed_at = datetime.now(UTC).isoformat()
        node.error = error
    
    def end_session(self, session_id: str) -> dict:
        """End a session and return the final graph."""
        if session_id not in self._graphs:
            raise ValueError(f"Session {session_id} not found")
        
        self._active_sessions.discard(session_id)
        self._graphs[session_id]["status"] = "completed"
        self._graphs[session_id]["ended_at"] = datetime.now(UTC).isoformat()
        
        return self._graphs[session_id]
    
    def get_graph(self, session_id: str) -> dict:
        """Get the call graph for a session."""
        if session_id not in self._graphs:
            return None
        
        graph = self._graphs[session_id]
        
        nodes_data = []
        for node_id in graph["nodes"]:
            node = graph.get(node_id)
            if node:
                nodes_data.append({
                    "id": node.id,
                    "tool_name": node.tool_name,
                    "status": node.status,
                    "started_at": node.started_at,
                    "completed_at": node.completed_at,
                    "was_corrected": node.was_corrected,
                    "error": node.error,
                })
        
        return {
            "session_id": graph["session_id"],
            "agent_id": graph["agent_id"],
            "nodes": nodes_data,
            "edges": graph["edges"],
            "started_at": graph["started_at"],
            "status": graph["status"],
        }
    
    def get_active_sessions(self) -> list[dict]:
        """Get all active session graphs."""
        return [
            self.get_graph(session_id)
            for session_id in self._active_sessions
        ]
    
    def get_correction_overlay(self, session_id: str) -> list[dict]:
        """Get correction overlay data for visualization."""
        graph = self._graphs.get(session_id)
        if not graph:
            return []
        
        corrections = []
        
        for node_id in graph["nodes"]:
            node = graph.get(node_id)
            if node and node.was_corrected:
                corrections.append({
                    "node_id": node.id,
                    "tool_name": node.tool_name,
                    "correction_id": node.correction_id,
                    "original_tool": node.parameters.get("_original_tool"),
                })
        
        return corrections
    
    def get_historical(self, limit: int = 100) -> list[dict]:
        """Get historical call graphs."""
        historical = []
        
        for session_id in self._graphs:
            if session_id not in self._active_sessions:
                historical.append(self.get_graph(session_id))
        
        historical.sort(key=lambda x: x.get("started_at", ""), reverse=True)
        
        return historical[:limit]
    
    def get_statistics(self) -> dict:
        """Get call graph statistics."""
        total_sessions = len(self._graphs)
        active_count = len(self._active_sessions)
        
        tool_usage = defaultdict(int)
        correction_count = 0
        total_calls = 0
        
        for session_id, graph in self._graphs.items():
            for node_id in graph["nodes"]:
                node = graph.get(node_id)
                if node:
                    tool_usage[node.tool_name] += 1
                    total_calls += 1
                    if node.was_corrected:
                        correction_count += 1
        
        return {
            "total_sessions": total_sessions,
            "active_sessions": active_count,
            "completed_sessions": total_sessions - active_count,
            "total_calls": total_calls,
            "corrections_applied": correction_count,
            "tool_usage": dict(tool_usage),
        }
