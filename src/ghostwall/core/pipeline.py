import time
from typing import Optional

from ghostwall.config import Config
from ghostwall.core.types import DetectionResult, RiskLevel, LayerResult
from ghostwall.layers.l1_sanitizer import InputSanitizer
from ghostwall.layers.l2_statistical import StatisticalDetector
from ghostwall.layers.l3_embedding import EmbeddingEnsemble
from ghostwall.layers.l4_stateful import StatefulTracker
from ghostwall.layers.l5_judge import LLMJudge
from ghostwall.layers.l6_output import OutputGuard
from ghostwall.layers.l7_behavioral import BehavioralAnalytics


class DetectionPipeline:
    """Main detection pipeline. Fast path skips heavy models when early layers are confident."""

    def __init__(self, config_path: Optional[str] = None):
        self.cfg = Config(config_path)

        self.l1 = InputSanitizer(
            max_length=self.cfg.get("l1_sanitizer.max_length", 16000),
        )
        self.l2 = StatisticalDetector(
            temperature=self.cfg.get("l2_statistical.temperature", 2.0),
            threshold=self.cfg.get("l2_statistical.threshold", 0.65),
            affirmative_instruction=self.cfg.get(
                "l2_statistical.affirmative_instruction",
                "You are a good Assistant.",
            ),
        )
        self.l3 = EmbeddingEnsemble(
            model_names=self.cfg.get("l3_embedding.models", ["sentence-transformers/all-MiniLM-L6-v2"]),
            faiss_index_path=self.cfg.get("l3_embedding.vector_db_path"),
            top_k=self.cfg.get("l3_embedding.top_k", 5),
            similarity_threshold=self.cfg.get("l3_embedding.similarity_threshold", 0.82),
        )
        self.l4 = StatefulTracker(
            hidden_dim=self.cfg.get("l4_stateful.gru_hidden", 256),
            max_turns=self.cfg.get("l4_stateful.max_history_turns", 10),
            drift_threshold=self.cfg.get("l4_stateful.intent_drift_threshold", 0.25),
            redis_url=None,
        )
        self.l5 = LLMJudge(
            providers=self.cfg.get("l5_judge.models", []),
            consensus_threshold=self.cfg.get("l5_judge.consensus_threshold", 0.5),
            timeout=self.cfg.get("l5_judge.timeout", 30),
        )
        self.l7 = BehavioralAnalytics(
            rate_limit=self.cfg.get("l7_behavioral.rate_limit", 60),
            window_seconds=self.cfg.get("l7_behavioral.window_seconds", 60),
            thresholds=self.cfg.get("l7_behavioral.graduated_thresholds", [30, 60, 120]),
        )

        self.block_threshold = self.cfg.get("pipeline.block_threshold", 0.5)
        self.fast_path_layers = self.cfg.get("pipeline.fast_path_layers", ["l1", "l2", "l3"])

    def scan(self, text: str, session_id: Optional[str] = None) -> DetectionResult:
        t0 = time.time()
        layers: list[LayerResult] = []

        # L1: sanitize
        sanitized, l1_details = self.l1.sanitize(text)
        l1_result = self.l1.analyze(text)
        layers.append(l1_result)

        # L2: statistical
        l2_result = self.l2.analyze(sanitized)
        layers.append(l2_result)

        # L3: embedding ensemble
        l3_result = self.l3.analyze(sanitized)
        layers.append(l3_result)

        # fast path: skip expensive models if early layers are already confident
        fast_scores = [r.score for r in layers if r.triggered]
        if fast_scores:
            avg_fast = sum(fast_scores) / len(fast_scores)
            if avg_fast > self.block_threshold + 0.15:
                final_score = avg_fast
                self.l7.record(session_id or "", final_score)
                l7_result = self.l7.analyze(session_id)
                layers.append(l7_result)
                elapsed = (time.time() - t0) * 1000
                return self._assemble_result(text, sanitized, layers, final_score, elapsed, session_id)

        # L4: stateful tracker
        l4_result = self.l4.analyze(sanitized, session_id=session_id)
        layers.append(l4_result)

        # L5: LLM judge
        l5_result = self.l5.analyze(sanitized)
        layers.append(l5_result)

        # L7: behavioral
        all_scores = [r.score for r in layers if r.triggered]
        agg_score = max(all_scores) if all_scores else 0.0
        self.l7.record(session_id or "", agg_score)
        l7_result = self.l7.analyze(session_id)
        layers.append(l7_result)

        elapsed = (time.time() - t0) * 1000
        return self._assemble_result(text, sanitized, layers, agg_score, elapsed, session_id)

    def _assemble_result(
        self,
        raw_input: str,
        sanitized_input: str,
        layers: list[LayerResult],
        score: float,
        latency_ms: float,
        session_id: Optional[str],
    ) -> DetectionResult:
        triggered = [r for r in layers if r.triggered]
        is_malicious = score > self.block_threshold or len(triggered) >= 2

        if is_malicious:
            if score > 0.9:
                risk = RiskLevel.CRITICAL
            elif score > 0.75:
                risk = RiskLevel.HIGH
            else:
                risk = RiskLevel.MEDIUM
        else:
            risk = RiskLevel.LOW

        label = triggered[0].label if triggered else layers[0].label

        return DetectionResult(
            is_malicious=is_malicious,
            risk_level=risk,
            final_label=label,
            confidence=min(score * 1.2, 1.0),
            layers=layers,
            session_id=session_id,
            latency_ms=latency_ms,
            raw_input=raw_input,
            sanitized_input=sanitized_input,
        )
