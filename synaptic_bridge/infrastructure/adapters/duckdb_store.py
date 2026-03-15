"""
DuckDB Storage for Correction Learning Engine

Following PRD: CLE pattern store using DuckDB (embedded) with BigQuery sync capability.
"""

import os
import json
import uuid
from datetime import datetime, UTC
from typing import Any

import duckdb

from synaptic_bridge.domain.constants import EMBEDDING_DIM, PATTERN_SIMILARITY_THRESHOLD
from synaptic_bridge.domain.entities import Correction, CorrectionPattern


class DuckDBCorrectionStore:
    """
    DuckDB implementation of CorrectionStorePort.

    Following PRD: CLE pattern storage in DuckDB with zero-ops analytics.
    """

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or os.environ.get(
            "DUCKDB_PATH", "synaptic_bridge.duckdb"
        )
        self._conn = duckdb.connect(self.db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        """Initialize DuckDB schema for corrections and patterns."""
        self._conn.execute("""
            CREATE SEQUENCE IF NOT EXISTS correction_id_seq;
            CREATE SEQUENCE IF NOT EXISTS pattern_id_seq;
        """)

        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS corrections (
                correction_id VARCHAR PRIMARY KEY,
                session_id VARCHAR NOT NULL,
                agent_id VARCHAR NOT NULL,
                original_intent VARCHAR NOT NULL,
                inferred_context VARCHAR NOT NULL,
                original_tool VARCHAR NOT NULL,
                corrected_tool VARCHAR NOT NULL,
                correction_metadata JSON,
                operator_identity VARCHAR NOT NULL,
                confidence_before DOUBLE NOT NULL,
                confidence_after DOUBLE NOT NULL,
                captured_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS correction_patterns (
                pattern_id VARCHAR PRIMARY KEY,
                intent_vector JSON NOT NULL,
                original_tools JSON NOT NULL,
                corrected_tools JSON NOT NULL,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                avg_confidence_improvement DOUBLE NOT NULL DEFAULT 0.0,
                last_updated TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_corrections_session
            ON corrections(session_id);
        """)

        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_corrections_agent
            ON corrections(agent_id);
        """)

        self._conn.commit()

    async def save_correction(
        self, correction: Correction, *, intent_embedding: tuple[float, ...] | None = None
    ) -> None:
        """Save a correction to DuckDB."""
        metadata_json = json.dumps(correction.correction_metadata)

        self._conn.execute(
            """
            INSERT INTO corrections
            (correction_id, session_id, agent_id, original_intent, inferred_context,
             original_tool, corrected_tool, correction_metadata, operator_identity,
             confidence_before, confidence_after, captured_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            [
                correction.correction_id,
                correction.session_id,
                correction.agent_id,
                correction.original_intent,
                correction.inferred_context,
                correction.original_tool,
                correction.corrected_tool,
                metadata_json,
                correction.operator_identity,
                correction.confidence_before,
                correction.confidence_after,
                correction.captured_at,
            ],
        )

        self._conn.commit()

        await self._update_pattern_from_correction(correction, intent_embedding=intent_embedding)

    async def _update_pattern_from_correction(
        self, correction: Correction, *, intent_embedding: tuple[float, ...] | None = None
    ) -> None:
        """Update or create a pattern based on the correction."""
        vector = list(intent_embedding) if intent_embedding is not None else [0.0] * EMBEDDING_DIM

        existing = self._conn.execute(
            """
            SELECT pattern_id, occurrence_count, avg_confidence_improvement
            FROM correction_patterns
            WHERE list_contains(from_json_strict(original_tools, '["VARCHAR"]'), ?)
            AND list_contains(from_json_strict(corrected_tools, '["VARCHAR"]'), ?)
        """,
            [
                correction.original_tool,
                correction.corrected_tool,
            ],
        ).fetchone()

        improvement = correction.confidence_after - correction.confidence_before

        if existing:
            pattern_id, count, avg_improvement = existing
            new_count = count + 1
            new_avg = (avg_improvement * count + improvement) / new_count

            self._conn.execute(
                """
                UPDATE correction_patterns
                SET occurrence_count = ?,
                    avg_confidence_improvement = ?,
                    intent_vector = ?,
                    last_updated = ?
                WHERE pattern_id = ?
            """,
                [new_count, new_avg, json.dumps(vector), datetime.now(UTC), pattern_id],
            )
        else:
            pattern_id = f"pattern_{uuid.uuid4().hex[:8]}"

            self._conn.execute(
                """
                INSERT INTO correction_patterns
                (pattern_id, intent_vector, original_tools, corrected_tools,
                 occurrence_count, avg_confidence_improvement, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                [
                    pattern_id,
                    json.dumps(vector),
                    json.dumps([correction.original_tool]),
                    json.dumps([correction.corrected_tool]),
                    1,
                    improvement,
                    datetime.now(UTC),
                ],
            )

        self._conn.commit()

    async def get_correction(self, correction_id: str) -> Correction | None:
        """Get a correction by ID."""
        row = self._conn.execute(
            """
            SELECT * FROM corrections WHERE correction_id = ?
        """,
            [correction_id],
        ).fetchone()

        if not row:
            return None

        return self._row_to_correction(row)

    async def find_patterns(
        self, intent_vector: tuple[float, ...]
    ) -> list[CorrectionPattern]:
        """Find patterns matching the given intent vector using cosine similarity."""
        rows = self._conn.execute("""
            SELECT * FROM correction_patterns
            ORDER BY occurrence_count DESC
            LIMIT 10
        """).fetchall()

        patterns = []
        for row in rows:
            pattern = self._row_to_pattern(row)

            stored_vector = pattern.intent_vector
            similarity = self._cosine_similarity(intent_vector, stored_vector)

            if similarity > PATTERN_SIMILARITY_THRESHOLD:
                patterns.append(pattern)

        return patterns

    def _cosine_similarity(
        self, vec1: tuple[float, ...], vec2: tuple[float, ...]
    ) -> float:
        if len(vec1) != len(vec2) or len(vec1) == 0:
            return 0.0

        dot = sum(a * b for a, b in zip(vec1, vec2))
        mag1 = sum(a * a for a in vec1) ** 0.5
        mag2 = sum(b * b for b in vec2) ** 0.5

        if mag1 == 0 or mag2 == 0:
            return 0.0

        return dot / (mag1 * mag2)

    async def get_pattern_stats(self) -> dict:
        """Get statistics about stored patterns."""
        total_patterns = self._conn.execute("""
            SELECT COUNT(*) FROM correction_patterns
        """).fetchone()[0]

        total_corrections = self._conn.execute("""
            SELECT COUNT(*) FROM corrections
        """).fetchone()[0]

        top_patterns = self._conn.execute("""
            SELECT original_tools::JSON, corrected_tools::JSON, occurrence_count
            FROM correction_patterns
            ORDER BY occurrence_count DESC
            LIMIT 5
        """).fetchall()

        return {
            "total_patterns": total_patterns,
            "total_corrections": total_corrections,
            "top_patterns": [
                {
                    "from": row[0],
                    "to": row[1],
                    "count": row[2],
                }
                for row in top_patterns
            ],
        }

    def _row_to_correction(self, row: tuple) -> Correction:
        return Correction(
            correction_id=row[0],
            session_id=row[1],
            agent_id=row[2],
            original_intent=row[3],
            inferred_context=row[4],
            original_tool=row[5],
            corrected_tool=row[6],
            correction_metadata=json.loads(row[7]) if row[7] else {},
            operator_identity=row[8],
            confidence_before=row[9],
            confidence_after=row[10],
            captured_at=row[11],
        )

    def _row_to_pattern(self, row: tuple) -> CorrectionPattern:
        return CorrectionPattern(
            pattern_id=row[0],
            intent_vector=tuple(json.loads(row[1])),
            original_tools=tuple(json.loads(row[2])),
            corrected_tools=tuple(json.loads(row[3])),
            occurrence_count=row[4],
            avg_confidence_improvement=row[5],
            last_updated=row[6],
        )

    def close(self) -> None:
        """Close the DuckDB connection."""
        self._conn.close()
