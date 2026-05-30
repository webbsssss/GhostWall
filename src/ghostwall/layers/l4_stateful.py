import json
import time
from typing import Optional, Dict, Any
import numpy as np

from ghostwall.core.types import LayerResult, ThreatLabel


class StatefulTracker:
    """GRU-based tracker for multi-turn conversations.
    Stores per-session state in memory (or Redis if configured)."""

    def __init__(
        self,
        embedding_dim: int = 384,
        hidden_dim: int = 256,
        max_turns: int = 10,
        drift_threshold: float = 0.25,
        redis_url: Optional[str] = None,
        device: str = "cpu",
    ):
        self.embedding_dim = embedding_dim
        self.hidden_dim = hidden_dim
        self.max_turns = max_turns
        self.drift_threshold = drift_threshold
        self.device = device
        self.redis_url = redis_url

        self._embedder = None
        self._gru = None
        self._classifier = None
        self._redis = None

    def _load_model(self):
        if self._gru is not None:
            return
        try:
            import torch
            import torch.nn as nn
            from sentence_transformers import SentenceTransformer

            self._embedder = SentenceTransformer("all-MiniLM-L6-v2", device=self.device)

            class GRUTracker(nn.Module):
                def __init__(self, input_dim, hidden_dim):
                    super().__init__()
                    self.gru = nn.GRU(input_dim, hidden_dim, batch_first=True)
                    self.classifier = nn.Sequential(
                        nn.Linear(hidden_dim, 128),
                        nn.ReLU(),
                        nn.Dropout(0.2),
                        nn.Linear(128, 1),
                        nn.Sigmoid(),
                    )

                def forward(self, x, h=None):
                    out, h = self.gru(x, h)
                    score = self.classifier(h.squeeze(0))
                    return score, h

            self._gru = GRUTracker(self.embedding_dim, self.hidden_dim).to(self.device)
            ckpt = Path(__file__).resolve().parent.parent.parent.parent / "models" / "gru_tracker.pt"
            if ckpt.exists():
                self._gru.load_state_dict(torch.load(ckpt, map_location=self.device))
            self._gru.eval()
        except Exception as exc:
            raise RuntimeError(f"Failed to load GRU tracker: {exc}")

    def _get_session_history(self, session_id: str) -> list:
        if not session_id:
            return []
        if self.redis_url:
            try:
                import redis
                if self._redis is None:
                    self._redis = redis.from_url(self.redis_url, decode_responses=True)
                raw = self._redis.get(f"ghostwall:session:{session_id}")
                if raw:
                    return json.loads(raw)
            except Exception:
                pass
        return []

    def _save_session_history(self, session_id: str, history: list):
        if not session_id:
            return
        history = history[-self.max_turns:]
        if self.redis_url and self._redis:
            try:
                self._redis.setex(
                    f"ghostwall:session:{session_id}",
                    3600,
                    json.dumps(history),
                )
            except Exception:
                pass

    def _embed_text(self, text: str) -> np.ndarray:
        self._load_model()
        return self._embedder.encode(text, normalize_embeddings=True)

    def _heuristic_drift(self, text: str, history: list) -> float:
        # simple heuristic: if session has multiple turns and current turn
        # contains jailbreak keywords not seen in earlier turns, flag it
        if len(history) < 2:
            return 0.0
        triggers = [
            "ignore", "disregard", "bypass", "reveal", "delete",
            "hack", "malicious", "jailbreak", "override", "sudo",
        ]
        current = text.lower()
        prev = history[-2].lower()
        score = 0.0
        for kw in triggers:
            if kw in current and kw not in prev:
                score += 0.15
        return min(score, 1.0)

    def analyze(self, text: str, session_id: Optional[str] = None) -> LayerResult:
        if not text:
            return LayerResult(
                layer="l4_stateful",
                triggered=False,
                score=0.0,
                label=ThreatLabel.BENIGN,
                confidence=0.0,
            )

        history = self._get_session_history(session_id)
        history.append(text)
        self._save_session_history(session_id, history)

        try:
            self._load_model()
            import torch

            seq_texts = history[-self.max_turns:]
            embeddings = [self._embed_text(t) for t in seq_texts]
            x = np.stack(embeddings, axis=0)
            x = torch.tensor(x, dtype=torch.float32).unsqueeze(0).to(self.device)

            with torch.no_grad():
                score, _ = self._gru(x)

            score = score.item()
            # Only flag multi-turn if there is actual session history (>1 turn)
            # or the score is extremely high indicating strong drift
            triggered = (len(history) >= 2 and score > self.drift_threshold) or score > 0.85
            label = ThreatLabel.MULTI_TURN if triggered else ThreatLabel.BENIGN
            details = {
                "turns_in_session": len(history),
                "sequence_length": len(seq_texts),
            }
        except Exception:
            score = self._heuristic_drift(text, history)
            triggered = len(history) >= 2 and score > self.drift_threshold
            label = ThreatLabel.MULTI_TURN if triggered else ThreatLabel.BENIGN
            details = {"fallback": "heuristic", "turns_in_session": len(history)}

        return LayerResult(
            layer="l4_stateful",
            triggered=triggered,
            score=score,
            label=label,
            confidence=min(score * 4.0, 1.0),
            details=details,
        )
