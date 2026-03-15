"""
Infrastructure Adapter Tests

Comprehensive tests for DuckDB correction store, WORM audit log,
SPIFFE controller, call graph service, pattern marketplace, and SIEM connectors.

Following skill2026.md Rule 4 - Mandatory Testing Coverage.
"""

import os

os.environ["TESTING"] = "1"
os.environ["WORM_SECRET_KEY"] = "test-worm-secret-key"

import json
import stat
import time

import pytest
from datetime import datetime, UTC

from synaptic_bridge.infrastructure.adapters.duckdb_store import DuckDBCorrectionStore
from synaptic_bridge.infrastructure.adapters.worm_audit import (
    WORMAuditLog,
    WORMStorageBackend,
)
from synaptic_bridge.infrastructure.adapters.spiffe_controller import (
    SPIFFEController,
    MockSPIFFEController,
    WorkloadIdentity,
    CredentialInjector,
)
from synaptic_bridge.infrastructure.services.call_graph import CallGraphService
from synaptic_bridge.infrastructure.services.pattern_marketplace import (
    CLEPatternMarketplace,
)
from synaptic_bridge.infrastructure.adapters.siem_connectors import (
    SplunkConnector,
    DatadogConnector,
    SIEMEvent,
    SIEMDispatcher,
)
from synaptic_bridge.domain.entities import Correction, AuditEvent
from synaptic_bridge.domain.exceptions import ConfigurationError


# ---------------------------------------------------------------------------
# DuckDB Correction Store
# ---------------------------------------------------------------------------


class TestDuckDBCorrectionStore:
    """Tests for DuckDB-backed correction store."""

    def _make_store(self, tmp_path):
        db_path = str(tmp_path / "test.duckdb")
        return DuckDBCorrectionStore(db_path=db_path)

    def _make_correction(self, cid="corr_1", original="bad.tool", corrected="good.tool",
                         conf_before=0.4, conf_after=0.9):
        return Correction(
            correction_id=cid,
            session_id="session_1",
            agent_id="agent_1",
            original_intent="do something",
            inferred_context="user wants action",
            original_tool=original,
            corrected_tool=corrected,
            correction_metadata={"reason": "wrong tool"},
            operator_identity="admin",
            confidence_before=conf_before,
            confidence_after=conf_after,
            captured_at=datetime.now(UTC),
        )

    @pytest.mark.asyncio
    async def test_save_and_get_correction(self, tmp_path):
        store = self._make_store(tmp_path)
        try:
            correction = self._make_correction()
            await store.save_correction(correction)

            retrieved = await store.get_correction("corr_1")
            assert retrieved is not None
            assert retrieved.correction_id == "corr_1"
            assert retrieved.original_tool == "bad.tool"
            assert retrieved.corrected_tool == "good.tool"
        finally:
            store.close()

    @pytest.mark.asyncio
    async def test_get_nonexistent_correction(self, tmp_path):
        store = self._make_store(tmp_path)
        try:
            result = await store.get_correction("does_not_exist")
            assert result is None
        finally:
            store.close()

    @pytest.mark.asyncio
    async def test_pattern_created_on_save(self, tmp_path):
        store = self._make_store(tmp_path)
        try:
            await store.save_correction(self._make_correction())
            stats = await store.get_pattern_stats()
            assert stats["total_patterns"] >= 1
            assert stats["total_corrections"] == 1
        finally:
            store.close()

    @pytest.mark.asyncio
    async def test_pattern_updates_on_repeated_correction(self, tmp_path):
        store = self._make_store(tmp_path)
        try:
            await store.save_correction(self._make_correction("corr_1"))
            await store.save_correction(self._make_correction("corr_2"))

            stats = await store.get_pattern_stats()
            assert stats["total_corrections"] == 2
            # The pattern should have been updated (occurrence count incremented)
            assert len(stats["top_patterns"]) >= 1
            assert stats["top_patterns"][0]["count"] >= 2
        finally:
            store.close()

    @pytest.mark.asyncio
    async def test_cosine_similarity_identical_vectors(self, tmp_path):
        store = self._make_store(tmp_path)
        try:
            vec = (1.0, 0.0, 0.5)
            similarity = store._cosine_similarity(vec, vec)
            assert similarity == pytest.approx(1.0)
        finally:
            store.close()

    @pytest.mark.asyncio
    async def test_cosine_similarity_orthogonal_vectors(self, tmp_path):
        store = self._make_store(tmp_path)
        try:
            vec_a = (1.0, 0.0)
            vec_b = (0.0, 1.0)
            similarity = store._cosine_similarity(vec_a, vec_b)
            assert similarity == pytest.approx(0.0)
        finally:
            store.close()

    @pytest.mark.asyncio
    async def test_cosine_similarity_zero_vector(self, tmp_path):
        store = self._make_store(tmp_path)
        try:
            vec_a = (0.0, 0.0, 0.0)
            vec_b = (1.0, 2.0, 3.0)
            similarity = store._cosine_similarity(vec_a, vec_b)
            assert similarity == 0.0
        finally:
            store.close()

    @pytest.mark.asyncio
    async def test_cosine_similarity_mismatched_length(self, tmp_path):
        store = self._make_store(tmp_path)
        try:
            similarity = store._cosine_similarity((1.0, 2.0), (1.0,))
            assert similarity == 0.0
        finally:
            store.close()

    @pytest.mark.asyncio
    async def test_find_patterns(self, tmp_path):
        store = self._make_store(tmp_path)
        try:
            await store.save_correction(self._make_correction())
            # Use a zero vector which should get low similarity and be filtered
            from synaptic_bridge.domain.constants import EMBEDDING_DIM
            patterns = await store.find_patterns(tuple([0.0] * EMBEDDING_DIM))
            # Zero vs zero vector is 0 similarity, should not pass threshold
            assert isinstance(patterns, list)
        finally:
            store.close()

    @pytest.mark.asyncio
    async def test_metadata_preserved(self, tmp_path):
        store = self._make_store(tmp_path)
        try:
            correction = self._make_correction()
            await store.save_correction(correction)
            retrieved = await store.get_correction("corr_1")
            assert retrieved.correction_metadata == {"reason": "wrong tool"}
        finally:
            store.close()


# ---------------------------------------------------------------------------
# WORM Audit Log
# ---------------------------------------------------------------------------


class TestWORMAuditLog:
    """Tests for Write-Once-Read-Many audit log."""

    def _make_audit_event(self, event_id="evt_1", event_type="tool_call"):
        return AuditEvent(
            event_id=event_id,
            event_type=event_type,
            session_id="session_1",
            agent_id="agent_1",
            tool_name="filesystem.read",
            action="execute",
            actor="system",
            resource="/tmp/file",
            outcome="success",
            metadata={"key": "value"},
            timestamp=datetime.now(UTC),
            signature="placeholder",
        )

    @pytest.mark.asyncio
    async def test_append_event(self, tmp_path):
        worm = WORMAuditLog(
            storage_path=str(tmp_path / "audit"),
            secret_key="test-worm-secret-key",
        )
        event = self._make_audit_event()
        worm_event = await worm.append(event)

        assert worm_event.event_id == "evt_1"
        assert worm_event.sequence_number == 1
        assert worm_event.event_hash is not None
        assert worm_event.signature is not None

    @pytest.mark.asyncio
    async def test_chain_hashing(self, tmp_path):
        worm = WORMAuditLog(
            storage_path=str(tmp_path / "audit"),
            secret_key="test-worm-secret-key",
        )
        evt1 = await worm.append(self._make_audit_event("evt_1"))
        evt2 = await worm.append(self._make_audit_event("evt_2"))

        # The second event's previous_hash should be the first event's hash
        assert evt2.previous_hash == evt1.event_hash
        # Different events produce different hashes
        assert evt1.event_hash != evt2.event_hash

    @pytest.mark.asyncio
    async def test_integrity_verification_passes(self, tmp_path):
        worm = WORMAuditLog(
            storage_path=str(tmp_path / "audit"),
            secret_key="test-worm-secret-key",
        )
        await worm.append(self._make_audit_event("evt_1"))
        await worm.append(self._make_audit_event("evt_2"))

        results = await worm.verify_integrity()
        assert results["valid"] is True
        assert results["events_checked"] == 2
        assert results["events_valid"] == 2
        assert results["first_failure"] is None

    @pytest.mark.asyncio
    async def test_integrity_verification_detects_tampering(self, tmp_path):
        worm = WORMAuditLog(
            storage_path=str(tmp_path / "audit"),
            secret_key="test-worm-secret-key",
        )
        await worm.append(self._make_audit_event("evt_1"))

        # Tamper with the in-memory event hash
        worm._events[0].event_hash = "tampered_hash"

        results = await worm.verify_integrity()
        assert results["valid"] is False
        assert results["first_failure"] == 1

    @pytest.mark.asyncio
    async def test_file_permissions_read_only(self, tmp_path):
        audit_dir = str(tmp_path / "audit")
        worm = WORMAuditLog(
            storage_path=audit_dir,
            secret_key="test-worm-secret-key",
        )
        await worm.append(self._make_audit_event("evt_1"))

        # Find the written audit file
        import glob
        audit_files = glob.glob(os.path.join(audit_dir, "*.json"))
        assert len(audit_files) == 1

        file_stat = os.stat(audit_files[0])
        file_mode = file_stat.st_mode
        # Should be read-only for owner (0o400 / S_IRUSR)
        assert file_mode & stat.S_IRUSR  # owner can read
        assert not (file_mode & stat.S_IWUSR)  # owner cannot write
        assert not (file_mode & stat.S_IXUSR)  # owner cannot execute

    @pytest.mark.asyncio
    async def test_get_events_by_session(self, tmp_path):
        worm = WORMAuditLog(
            storage_path=str(tmp_path / "audit"),
            secret_key="test-worm-secret-key",
        )
        await worm.append(self._make_audit_event("evt_1"))
        await worm.append(self._make_audit_event("evt_2"))

        events = await worm.get_events(session_id="session_1")
        assert len(events) == 2

        events_other = await worm.get_events(session_id="other_session")
        assert len(events_other) == 0

    @pytest.mark.asyncio
    async def test_sequence_numbers_increment(self, tmp_path):
        worm = WORMAuditLog(
            storage_path=str(tmp_path / "audit"),
            secret_key="test-worm-secret-key",
        )
        e1 = await worm.append(self._make_audit_event("evt_1"))
        e2 = await worm.append(self._make_audit_event("evt_2"))
        e3 = await worm.append(self._make_audit_event("evt_3"))

        assert e1.sequence_number == 1
        assert e2.sequence_number == 2
        assert e3.sequence_number == 3

    def test_worm_requires_secret_key(self, tmp_path):
        # Temporarily clear the env var
        old_val = os.environ.pop("WORM_SECRET_KEY", None)
        try:
            with pytest.raises(ConfigurationError):
                WORMAuditLog(
                    storage_path=str(tmp_path / "audit"),
                    secret_key="",
                )
        finally:
            if old_val is not None:
                os.environ["WORM_SECRET_KEY"] = old_val


# ---------------------------------------------------------------------------
# SPIFFE Controller
# ---------------------------------------------------------------------------


class TestSPIFFEController:
    """Tests for SPIFFE workload identity controller."""

    @pytest.mark.asyncio
    async def test_get_workload_identity(self):
        controller = SPIFFEController()
        identity = await controller.get_workload_identity()

        assert identity.spiffe_id.startswith("spiffe://")
        assert identity.trust_domain == "example.org"
        assert identity.audience == "synaptic-bridge"
        assert identity.expires_at > identity.issued_at

    @pytest.mark.asyncio
    async def test_identity_caching(self):
        controller = SPIFFEController()
        id1 = await controller.get_workload_identity()
        id2 = await controller.get_workload_identity()

        # Should return the cached identity (same object)
        assert id1 is id2

    @pytest.mark.asyncio
    async def test_expired_identity_refetched(self):
        controller = SPIFFEController()
        identity = await controller.get_workload_identity()

        # Force expiration by setting expires_at in the past
        controller._cached_identity = WorkloadIdentity(
            spiffe_id=identity.spiffe_id,
            trust_domain=identity.trust_domain,
            issued_at=identity.issued_at,
            expires_at=int(time.time()) - 1000,  # expired
            audience=identity.audience,
            certificate=identity.certificate,
            private_key=identity.private_key,
        )

        new_identity = await controller.get_workload_identity()
        # Should be a new identity since the old one is expired
        assert new_identity.expires_at > int(time.time())

    @pytest.mark.asyncio
    async def test_mock_spiffe_controller(self):
        controller = MockSPIFFEController()
        identity = await controller.get_workload_identity()

        assert "mock-workload" in identity.spiffe_id
        assert "BEGIN CERTIFICATE" in identity.certificate

    @pytest.mark.asyncio
    async def test_credential_injector(self):
        controller = MockSPIFFEController()
        injector = CredentialInjector(spiffe_controller=controller)

        context = {"tool": "filesystem.read", "params": {}}
        enriched = await injector.inject_credentials("filesystem.read", context)

        assert "_credentials" in enriched
        assert "spiffe_id" in enriched["_credentials"]
        assert enriched["tool"] == "filesystem.read"  # original context preserved

    @pytest.mark.asyncio
    async def test_method_names_match_interface(self):
        controller = SPIFFEController()
        assert hasattr(controller, "get_workload_identity")
        assert hasattr(controller, "get_jwt_token")
        assert hasattr(controller, "verify_peer_certificate")


# ---------------------------------------------------------------------------
# Call Graph Service
# ---------------------------------------------------------------------------


class TestCallGraphService:
    """Tests for the call graph service."""

    def test_start_session(self):
        svc = CallGraphService()
        graph = svc.start_session("session_1", "agent_1")

        assert graph["session_id"] == "session_1"
        assert graph["agent_id"] == "agent_1"
        assert graph["status"] == "active"
        assert graph["nodes"] == []
        assert graph["edges"] == []

    def test_add_node(self):
        svc = CallGraphService()
        svc.start_session("session_1", "agent_1")
        node_id = svc.add_node("session_1", "filesystem.read", {"path": "/tmp"})

        assert node_id.startswith("node_")
        graph = svc.get_graph("session_1")
        assert len(graph["nodes"]) == 1
        assert graph["nodes"][0]["tool_name"] == "filesystem.read"

    def test_add_node_unknown_session_raises(self):
        svc = CallGraphService()
        with pytest.raises(ValueError, match="not found"):
            svc.add_node("nonexistent", "tool", {})

    def test_complete_node(self):
        svc = CallGraphService()
        svc.start_session("session_1", "agent_1")
        node_id = svc.add_node("session_1", "bash.execute", {"cmd": "ls"})
        svc.complete_node("session_1", node_id, result={"output": "file.txt"})

        graph = svc.get_graph("session_1")
        node = graph["nodes"][0]
        assert node["status"] == "completed"

    def test_fail_node(self):
        svc = CallGraphService()
        svc.start_session("session_1", "agent_1")
        node_id = svc.add_node("session_1", "http.request", {"url": "http://test"})
        svc.fail_node("session_1", node_id, "Connection timeout")

        graph = svc.get_graph("session_1")
        node = graph["nodes"][0]
        assert node["status"] == "failed"
        assert node["error"] == "Connection timeout"

    def test_end_session(self):
        svc = CallGraphService()
        svc.start_session("session_1", "agent_1")
        svc.add_node("session_1", "tool", {})

        result = svc.end_session("session_1")
        assert result["status"] == "completed"
        assert "ended_at" in result

    def test_end_session_unknown_raises(self):
        svc = CallGraphService()
        with pytest.raises(ValueError, match="not found"):
            svc.end_session("nonexistent")

    def test_get_graph_returns_none_for_unknown(self):
        svc = CallGraphService()
        assert svc.get_graph("nonexistent") is None

    def test_correction_overlay(self):
        svc = CallGraphService()
        svc.start_session("session_1", "agent_1")
        node_id = svc.add_node(
            "session_1", "good.tool",
            {"_original_tool": "bad.tool"},
        )
        svc.complete_node(
            "session_1", node_id, result="ok",
            was_corrected=True, correction_id="corr_1",
        )

        overlay = svc.get_correction_overlay("session_1")
        assert len(overlay) == 1
        assert overlay[0]["correction_id"] == "corr_1"
        assert overlay[0]["original_tool"] == "bad.tool"

    def test_statistics(self):
        svc = CallGraphService()
        svc.start_session("s1", "agent_1")
        n1 = svc.add_node("s1", "filesystem.read", {})
        svc.complete_node("s1", n1, result="data")
        n2 = svc.add_node("s1", "bash.execute", {})
        svc.complete_node("s1", n2, result="ok", was_corrected=True)
        svc.end_session("s1")

        stats = svc.get_statistics()
        assert stats["total_sessions"] == 1
        assert stats["total_calls"] == 2
        assert stats["corrections_applied"] == 1
        assert "filesystem.read" in stats["tool_usage"]

    def test_parent_node_creates_edge(self):
        svc = CallGraphService()
        svc.start_session("s1", "agent_1")
        parent = svc.add_node("s1", "filesystem.read", {})
        child = svc.add_node("s1", "bash.execute", {}, parent_node_id=parent)

        graph = svc.get_graph("s1")
        assert len(graph["edges"]) == 1
        assert graph["edges"][0]["from"] == parent
        assert graph["edges"][0]["to"] == child


# ---------------------------------------------------------------------------
# Pattern Marketplace
# ---------------------------------------------------------------------------


class TestCLEPatternMarketplace:
    """Tests for the CLE pattern marketplace."""

    def _create_listing(self, mp, org="org_1", name="Fix Read"):
        return mp.create_listing(
            org_id=org,
            pattern_id="pattern_1",
            name=name,
            description="Corrects filesystem.read to database.query",
            from_tool="filesystem.read",
            to_tool="database.query",
            success_rate=0.95,
            tags=["filesystem", "database"],
        )

    def test_create_listing(self):
        mp = CLEPatternMarketplace()
        listing = self._create_listing(mp)

        assert listing.listing_id.startswith("listing_")
        assert listing.owner_org == "org_1"
        assert listing.from_tool == "filesystem.read"
        assert listing.usage_count == 0

    def test_search_by_query(self):
        mp = CLEPatternMarketplace()
        self._create_listing(mp, name="Fix Read to Query")
        self._create_listing(mp, name="Email routing fix")

        results = mp.search_listings(query="email")
        assert len(results) == 1
        assert "Email" in results[0].name

    def test_search_by_from_tool(self):
        mp = CLEPatternMarketplace()
        self._create_listing(mp)

        results = mp.search_listings(from_tool="filesystem.read")
        assert len(results) == 1

        results = mp.search_listings(from_tool="nonexistent.tool")
        assert len(results) == 0

    def test_purchase_free_listing(self):
        mp = CLEPatternMarketplace()
        listing = self._create_listing(mp)

        result = mp.purchase_listing(listing.listing_id, "buyer_org")
        assert result["status"] == "success"

    def test_purchase_already_owned(self):
        mp = CLEPatternMarketplace()
        listing = self._create_listing(mp)
        mp.purchase_listing(listing.listing_id, "buyer_org")

        result = mp.purchase_listing(listing.listing_id, "buyer_org")
        assert result["status"] == "already_owned"

    def test_purchase_nonexistent_raises(self):
        mp = CLEPatternMarketplace()
        with pytest.raises(ValueError, match="Listing not found"):
            mp.purchase_listing("nonexistent", "org")

    def test_add_review(self):
        mp = CLEPatternMarketplace()
        listing = self._create_listing(mp)

        review = mp.add_review(listing.listing_id, "reviewer_org", 5, "Excellent!")
        assert review.rating == 5
        assert review.comment == "Excellent!"

        # Rating should update on the listing
        updated = mp.get_listing(listing.listing_id)
        assert updated.rating == 5.0

    def test_review_invalid_rating_raises(self):
        mp = CLEPatternMarketplace()
        listing = self._create_listing(mp)

        with pytest.raises(ValueError, match="Rating must be between"):
            mp.add_review(listing.listing_id, "org", 6, "Too high")

        with pytest.raises(ValueError, match="Rating must be between"):
            mp.add_review(listing.listing_id, "org", 0, "Too low")

    def test_export_and_import(self):
        mp = CLEPatternMarketplace()
        listing = self._create_listing(mp, org="exporter")

        export_data = mp.export_pattern(listing.listing_id, "exporter")
        assert export_data["format_version"] == "1.0"
        assert export_data["pattern"]["from_tool"] == "filesystem.read"
        assert "signature" in export_data

        new_listing_id = mp.import_pattern(export_data, "importer")
        imported = mp.get_listing(new_listing_id)
        assert imported.from_tool == "filesystem.read"
        assert imported.owner_org == "importer"

    def test_export_not_purchased_raises(self):
        mp = CLEPatternMarketplace()
        listing = self._create_listing(mp, org="owner")

        with pytest.raises(ValueError, match="Not purchased"):
            mp.export_pattern(listing.listing_id, "stranger")

    def test_statistics(self):
        mp = CLEPatternMarketplace()
        self._create_listing(mp, name="listing1")
        self._create_listing(mp, name="listing2")

        stats = mp.get_statistics()
        assert stats["total_listings"] == 2
        assert stats["free_listings"] == 2
        assert stats["paid_listings"] == 0


# ---------------------------------------------------------------------------
# SIEM Connectors
# ---------------------------------------------------------------------------


class TestSIEMConnectors:
    """Tests for SIEM connector implementations."""

    @pytest.mark.asyncio
    async def test_splunk_connector_send_no_endpoint(self):
        connector = SplunkConnector(endpoint="", api_key="")
        event = SIEMEvent(
            timestamp="2026-01-01T00:00:00Z",
            event_type="tool_call",
            source="system",
            destination="tool",
            action="execute",
            outcome="success",
            session_id="s1",
            agent_id="a1",
            tool_name="test.tool",
            metadata={},
            severity="low",
        )
        # Should return True even without endpoint (skip path)
        result = await connector.send(event)
        assert result is True

    @pytest.mark.asyncio
    async def test_splunk_connector_name(self):
        connector = SplunkConnector(endpoint="http://splunk", api_key="key")
        assert connector.name == "splunk"

    @pytest.mark.asyncio
    async def test_datadog_connector_send_no_endpoint(self):
        connector = DatadogConnector(endpoint="", api_key="")
        event = SIEMEvent(
            timestamp="2026-01-01T00:00:00Z",
            event_type="policy_violation",
            source="system",
            destination="",
            action="deny",
            outcome="denied",
            session_id=None,
            agent_id=None,
            tool_name=None,
            metadata={},
            severity="critical",
        )
        result = await connector.send(event)
        assert result is True

    @pytest.mark.asyncio
    async def test_datadog_connector_name(self):
        connector = DatadogConnector(endpoint="http://dd", api_key="k")
        assert connector.name == "datadog"

    def test_event_normalization(self):
        connector = SplunkConnector(endpoint="", api_key="")
        raw = {
            "event_type": "tool_call",
            "actor": "admin",
            "resource": "/api/endpoint",
            "action": "execute",
            "outcome": "success",
            "session_id": "s1",
            "agent_id": "a1",
            "tool_name": "http.request",
        }
        normalized = connector.normalize_event(raw)
        assert isinstance(normalized, SIEMEvent)
        assert normalized.source == "admin"
        assert normalized.destination == "/api/endpoint"

    def test_severity_calculation_failure(self):
        connector = SplunkConnector(endpoint="", api_key="")
        severity = connector._calculate_severity({"outcome": "failure"})
        assert severity == "high"

    def test_severity_calculation_policy_violation(self):
        connector = SplunkConnector(endpoint="", api_key="")
        severity = connector._calculate_severity({"event_type": "policy_violation"})
        assert severity == "critical"

    def test_severity_calculation_network_call(self):
        connector = SplunkConnector(endpoint="", api_key="")
        severity = connector._calculate_severity({"action": "network_call"})
        assert severity == "medium"

    def test_severity_calculation_normal(self):
        connector = SplunkConnector(endpoint="", api_key="")
        severity = connector._calculate_severity({"action": "read"})
        assert severity == "low"

    @pytest.mark.asyncio
    async def test_siem_dispatcher_no_connectors(self):
        dispatcher = SIEMDispatcher()
        # Without env vars, no connectors should be initialized
        assert len(dispatcher.connectors) == 0
        # dispatch should still work without error
        await dispatcher.dispatch({"event_type": "test", "action": "test"})

    @pytest.mark.asyncio
    async def test_splunk_send_with_endpoint(self):
        connector = SplunkConnector(endpoint="http://splunk:8088", api_key="token")
        event = SIEMEvent(
            timestamp="2026-01-01T00:00:00Z",
            event_type="tool_call",
            source="system",
            destination="tool",
            action="execute",
            outcome="success",
            session_id="s1",
            agent_id="a1",
            tool_name="test.tool",
            metadata={},
            severity="low",
        )
        # With endpoint, send should still succeed (logs only, no real HTTP)
        result = await connector.send(event)
        assert result is True

    @pytest.mark.asyncio
    async def test_send_batch(self):
        connector = SplunkConnector(endpoint="", api_key="")
        events = [
            SIEMEvent(
                timestamp="2026-01-01T00:00:00Z",
                event_type="tool_call",
                source="system",
                destination="",
                action="execute",
                outcome="success",
                session_id=f"s{i}",
                agent_id="a1",
                tool_name="test",
                metadata={},
                severity="low",
            )
            for i in range(3)
        ]
        result = await connector.send_batch(events)
        assert result is True
