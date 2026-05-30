import time
from typing import Optional, Dict, Any
from collections import defaultdict

from ghostwall.core.types import LayerResult, ThreatLabel


class BehavioralAnalytics:
    """Simple in-memory rate limiter per session.
    Uses sliding windows; Redis can be added later for prod."""

    def __init__(
        self,
        rate_limit: int = 60,
        window_seconds: int = 60,
        thresholds: Optional[list] = None,
    ):
        self.rate_limit = rate_limit
        self.window_seconds = window_seconds
        self.thresholds = thresholds or [30, 60, 120]
        # session_id -> list of (timestamp, risk_score)
        self._events = defaultdict(list)

    def _clean_window(self, session_id: str):
        now = time.time()
        cutoff = now - self.window_seconds
        self._events[session_id] = [
            (ts, score) for ts, score in self._events[session_id] if ts > cutoff
        ]

    def record(self, session_id: str, risk_score: float):
        if not session_id:
            return
        self._clean_window(session_id)
        self._events[session_id].append((time.time(), risk_score))

    def _event_count(self, session_id: str) -> int:
        if not session_id:
            return 0
        self._clean_window(session_id)
        return len(self._events[session_id])

    def _escalation_level(self, session_id: str) -> int:
        count = self._event_count(session_id)
        for level, thresh in enumerate(self.thresholds, start=1):
            if count < thresh:
                return level - 1
        return len(self.thresholds)

    def analyze(self, session_id: Optional[str] = None) -> LayerResult:
        if not session_id:
            return LayerResult(
                layer="l7_behavioral",
                triggered=False,
                score=0.0,
                label=ThreatLabel.BENIGN,
                confidence=0.0,
                details={"note": "no session id provided"},
            )

        count = self._event_count(session_id)
        level = self._escalation_level(session_id)

        # score rises as count approaches rate limit
        score = min(count / self.rate_limit, 1.0)
        triggered = score > 0.8 or level >= 2

        label = ThreatLabel.UNKNOWN if triggered else ThreatLabel.BENIGN

        return LayerResult(
            layer="l7_behavioral",
            triggered=triggered,
            score=score,
            label=label,
            confidence=score,
            details={
                "requests_in_window": count,
                "escalation_level": level,
                "rate_limit": self.rate_limit,
            },
        )
