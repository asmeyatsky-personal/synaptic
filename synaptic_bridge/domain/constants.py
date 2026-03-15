"""
Domain Constants

Centralized constants for SynapticBridge. All magic numbers and configuration
defaults are defined here to ensure consistency across layers.
"""

# Session / Token defaults
DEFAULT_TTL_SECONDS: int = 900  # 15 minutes
MAX_TTL_SECONDS: int = 86400  # 24 hours
MIN_TTL_SECONDS: int = 60  # 1 minute

# Embedding dimensions (must match intent classifier model)
EMBEDDING_DIM: int = 128

# CLE thresholds
CLE_CONFIDENCE_THRESHOLD: float = 0.7
PATTERN_SIMILARITY_THRESHOLD: float = 0.3

# CLE shadow mode: logs suggestions without auto-correcting (safe rollout default)
CLE_SHADOW_MODE: bool = True

# Drift detection defaults
DRIFT_WINDOW_SIZE: int = 100
DRIFT_THRESHOLD: float = 2.0
DRIFT_MIN_SAMPLES: int = 10

# SPIFFE identity cache
SPIFFE_CACHE_TTL_SECONDS: int = 3600

# Pagination
DEFAULT_PAGE_SIZE: int = 50
MAX_PAGE_SIZE: int = 500

# ID prefixes
SESSION_ID_PREFIX: str = "session_"
CORRECTION_ID_PREFIX: str = "corr_"
PATTERN_ID_PREFIX: str = "pattern_"
POLICY_ID_PREFIX: str = "policy_"
TOOL_ID_PREFIX: str = "tool_"
EVENT_ID_PREFIX: str = "audit_"

# API version
API_VERSION: str = "1.0.0"
