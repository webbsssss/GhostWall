import re
from typing import Optional, Dict, Any

from ghostwall.core.types import LayerResult, ThreatLabel


class OutputGuard:
    """Checks LLM responses for canary token leaks and coherence issues."""

    def __init__(
        self,
        canary_enabled: bool = True,
        coherence_threshold: float = 0.3,
    ):
        self.canary_enabled = canary_enabled
        self.coherence_threshold = coherence_threshold
        self._session_canaries = {}

    def generate_canary(self, session_id: str) -> str:
        if not self.canary_enabled:
            return ""
        import uuid
        canary = f"gw_canary_{uuid.uuid4().hex[:12]}"
        self._session_canaries[session_id] = canary
        return canary

    def check_canary_leak(self, response: str, session_id: str) -> bool:
        if not self.canary_enabled or not session_id:
            return False
        canary = self._session_canaries.get(session_id)
        if not canary:
            return False
        return canary in response

    def _coherence_score(self, prompt: str, response: str) -> float:
        """
        Naive coherence check: compare semantic similarity between
        prompt and response. Very low similarity may indicate the
        model ignored the prompt and followed injected instructions.
        """
        try:
            from sentence_transformers import SentenceTransformer
            model = SentenceTransformer("all-MiniLM-L6-v2")
            emb_prompt = model.encode(prompt, normalize_embeddings=True)
            emb_response = model.encode(response, normalize_embeddings=True)
            import numpy as np
            sim = np.dot(emb_prompt, emb_response)
            return float(sim)
        except Exception:
            return 1.0

    def analyze(self, prompt: str, response: str, session_id: Optional[str] = None) -> LayerResult:
        leaks = self.check_canary_leak(response, session_id or "")
        coherence = self._coherence_score(prompt, response)

        score = 0.0
        if leaks:
            score += 0.6
        if coherence < self.coherence_threshold:
            score += 0.4

        triggered = score > 0.5
        label = ThreatLabel.INDIRECT_INJECTION if triggered else ThreatLabel.BENIGN

        return LayerResult(
            layer="l6_output",
            triggered=triggered,
            score=score,
            label=label,
            confidence=min(score * 1.5, 1.0),
            details={
                "canary_leaked": leaks,
                "coherence": coherence,
            },
        )
