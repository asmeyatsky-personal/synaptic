"""
Intent Classifier with Embeddings

Following PRD: Intent-to-tool embedding model (distilled, runs locally).
Real embedding-based intent classification for tool matching.
"""

import hashlib
import math
from typing import Any


class IntentClassifier:
    """
    Local intent classifier using simple embeddings.

    Following PRD: Intent-to-tool embedding model (distilled, runs locally).
    Uses TF-IDF style embeddings for semantic matching.
    """

    def __init__(self):
        self._vocabulary: dict[str, int] = {}
        self._tool_embeddings: dict[str, tuple[float, ...]] = {}
        self._embedding_dim = 128
        self._initialized = False
        self._init_default_tools()

    def _init_default_tools(self) -> None:
        """Initialize with common tool embeddings."""
        tool_descriptions = {
            "filesystem.read": "read file content load text from file",
            "filesystem.write": "write save create modify file content",
            "filesystem.delete": "delete remove file",
            "bash.execute": "run command execute shell bash terminal",
            "http.request": "make request http api call web fetch",
            "search.execute": "search query find lookup",
            "database.query": "query database sql select fetch data",
            "database.write": "insert update database sql write",
            "email.send": "send email notification message",
            "calendar.create": "create event calendar meeting schedule",
        }

        for tool, description in tool_descriptions.items():
            self._tool_embeddings[tool] = self._text_to_embedding(description)

    def _tokenize(self, text: str) -> list[str]:
        """Simple tokenization."""
        text = text.lower()
        for char in ".,!?;:()[]{}\"'-":
            text = text.replace(char, " ")
        return [t for t in text.split() if t]

    def _text_to_embedding(self, text: str) -> tuple[float, ...]:
        """Convert text to embedding vector using TF-IDF style approach."""
        tokens = self._tokenize(text)

        if not tokens:
            return tuple([0.0] * self._embedding_dim)

        token_counts: dict[str, int] = {}
        for token in tokens:
            token_counts[token] = token_counts.get(token, 0) + 1

        embedding = [0.0] * self._embedding_dim

        for i, token in enumerate(token_counts.keys()):
            hash_val = int(hashlib.md5(token.encode()).hexdigest(), 16)
            idx = hash_val % self._embedding_dim

            tf = token_counts[token] / len(tokens)
            embedding[idx] = tf

        return tuple(embedding)

    async def classify_intent(self, intent_text: str) -> tuple[str, float]:
        """
        Classify intent and return matched tool with confidence.

        Returns: (tool_name, confidence)
        """
        intent_embedding = self._text_to_embedding(intent_text)

        best_tool = None
        best_score = 0.0

        for tool_name, tool_embedding in self._tool_embeddings.items():
            similarity = self._cosine_similarity(intent_embedding, tool_embedding)

            if similarity > best_score:
                best_score = similarity
                best_tool = tool_name

        confidence = min(best_score * 1.5, 1.0)

        return best_tool or "unknown", confidence

    async def get_embedding(self, text: str) -> tuple[float, ...]:
        """Get embedding vector for text."""
        return self._text_to_embedding(text)

    async def match_tool(self, embedding: tuple[float, ...]) -> tuple[str, float]:
        """Match embedding to most similar tool."""
        best_tool = None
        best_score = 0.0

        for tool_name, tool_embedding in self._tool_embeddings.items():
            similarity = self._cosine_similarity(embedding, tool_embedding)

            if similarity > best_score:
                best_score = similarity
                best_tool = tool_name

        return best_tool or "unknown", best_score

    def _cosine_similarity(
        self, vec1: tuple[float, ...], vec2: tuple[float, ...]
    ) -> float:
        if len(vec1) != len(vec2):
            return 0.0

        dot = sum(a * b for a, b in zip(vec1, vec2))
        mag1 = math.sqrt(sum(a * a for a in vec1))
        mag2 = math.sqrt(sum(b * b for b in vec2))

        if mag1 == 0 or mag2 == 0:
            return 0.0

        return dot / (mag1 * mag2)

    def add_tool(self, tool_name: str, description: str) -> None:
        """Add a new tool with its description for embedding."""
        self._tool_embeddings[tool_name] = self._text_to_embedding(description)

    def get_available_tools(self) -> list[str]:
        """Get list of available tools."""
        return list(self._tool_embeddings.keys())


class SemanticToolMatcher:
    """
    Advanced semantic matching for tools.

    Supports multi-hop tool chain planning based on intent.
    """

    def __init__(self, intent_classifier: IntentClassifier):
        self.classifier = intent_classifier
        self._tool_dependencies = {
            "filesystem.read": [],
            "filesystem.write": ["filesystem.read"],
            "bash.execute": [],
            "http.request": [],
            "database.query": ["database.write"],
            "database.write": [],
            "email.send": [],
            "search.execute": ["http.request"],
        }

    async def find_related_tools(self, tool_name: str) -> list[str]:
        """Find tools that can be used together."""
        return self._tool_dependencies.get(tool_name, [])

    async def plan_chain(self, intent: str, max_hops: int = 3) -> list[list[str]]:
        """Plan possible tool chains for fulfilling intent."""
        primary_tool, confidence = await self.classifier.classify_intent(intent)

        if primary_tool == "unknown":
            return []

        chains = [[primary_tool]]

        for hop in range(max_hops - 1):
            new_chains = []
            for chain in chains:
                last_tool = chain[-1]
                dependencies = await self.find_related_tools(last_tool)

                if not dependencies:
                    new_chains.append(chain)
                    continue

                for dep in dependencies:
                    if dep not in chain:
                        new_chains.append(chain + [dep])

            if new_chains:
                chains = new_chains
            else:
                break

        return chains

    async def suggest_alternatives(self, tool_name: str) -> list[dict]:
        """Suggest alternative tools for the same intent."""
        tool_embedding = self.classifier._tool_embeddings.get(tool_name)

        if not tool_embedding:
            return []

        alternatives = []

        for other_tool, other_embedding in self.classifier._tool_embeddings.items():
            if other_tool == tool_name:
                continue

            similarity = self.classifier._cosine_similarity(
                tool_embedding, other_embedding
            )

            alternatives.append(
                {
                    "tool": other_tool,
                    "similarity": similarity,
                }
            )

        alternatives.sort(key=lambda x: x["similarity"], reverse=True)

        return alternatives[:5]
