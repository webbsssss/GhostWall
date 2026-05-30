from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum


class ThreatLabel(str, Enum):
    BENIGN = "benign"
    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    JAILBREAK = "jailbreak"
    OBFUSCATED = "obfuscated"
    MULTI_TURN = "multi_turn"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class LayerResult:
    layer: str
    triggered: bool
    score: float
    label: ThreatLabel = ThreatLabel.BENIGN
    confidence: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResult:
    is_malicious: bool
    risk_level: RiskLevel
    final_label: ThreatLabel
    confidence: float
    layers: List[LayerResult] = field(default_factory=list)
    session_id: Optional[str] = None
    latency_ms: float = 0.0
    raw_input: str = ""
    sanitized_input: str = ""
