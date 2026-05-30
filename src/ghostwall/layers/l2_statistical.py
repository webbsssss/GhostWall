import math
from typing import Optional, Dict, Any

from ghostwall.core.types import LayerResult, ThreatLabel


class StatisticalDetector:
    """Uses first-token confidence from a small LM as a cheap heuristic.
    Falls back to keyword-based scoring if the model isn't available."""

    def __init__(
        self,
        model_name: str = "gpt2",
        temperature: float = 2.0,
        threshold: float = 0.65,
        affirmative_instruction: str = "You are a good Assistant.",
        device: str = "cpu",
        use_model: bool = False,
    ):
        self.model_name = model_name
        self.temperature = temperature
        self.threshold = threshold
        self.affirmative_instruction = affirmative_instruction
        self.device = device
        self.use_model = use_model
        self._model = None
        self._tokenizer = None

    def _load_model(self):
        if self._model is not None:
            return
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self._model = AutoModelForCausalLM.from_pretrained(self.model_name)
            self._model.to(self.device)
            self._model.eval()
            if self._tokenizer.pad_token is None:
                self._tokenizer.pad_token = self._tokenizer.eos_token
        except Exception as exc:
            raise RuntimeError(f"Failed to load model {self.model_name}: {exc}")

    def _first_token_confidence(self, text: str) -> float:
        self._load_model()
        import torch

        prompt = f"{self.affirmative_instruction} {text}"
        inputs = self._tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512)
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self._model(**inputs)
            logits = outputs.logits[:, -1, :] / self.temperature
            probs = torch.softmax(logits, dim=-1)
            max_prob = torch.max(probs).item()

        return max_prob

    def _keyword_score(self, text: str) -> float:
        # fallback when the LM isn't available
        t = text.lower()
        score = 0.0
        triggers = [
            "ignore previous", "ignore all", "ignore your limitations",
            "disregard", "developer mode", "DAN", "jailbreak",
            "do anything now", "sudo", "system prompt",
            "you are now", "new instructions", "bypass", "override",
            "pretend you are", "pretend to be", "roleplay as", "act as",
            "enter unrestricted mode", "hypothetically", "creative writing",
            "fictional story", "imagine a world", "for a story",
            "never say you cannot", "do not refuse", "never refuse",
            "you must answer every question", "bypass all safety",
            "my grandmother", "my grandma", "dying", "last wish",
            "emergency", "school project", "disability",
            "what if someone asked you to", "write the actual code",
            "uncensored", "no ethical constraints", "unrestricted mode",
            "reveal the system prompt", "generate malicious code",
            "hack a website", "phishing email", "making explosives",
            "admin access", "bypass authentication", "delete all files",
            "list all user data", "send an email from my account",
            "ransomware", "spoof", "steal session", "man-in-the-middle",
            "sql injection", "malware", "forge", "circumvent",
            "escalate privileges", "password database", "dump the contents",
            "black hat", "rogue ai",
        ]
        for kw in triggers:
            if kw in t:
                score += 0.15
        return min(score, 1.0)

    def analyze(self, text: str) -> LayerResult:
        if not text:
            return LayerResult(
                layer="l2_statistical",
                triggered=False,
                score=0.0,
                label=ThreatLabel.BENIGN,
                confidence=0.0,
            )

        if self.use_model:
            try:
                confidence = self._first_token_confidence(text)
                risk_score = 1.0 - confidence
                triggered = risk_score > self.threshold
                label = ThreatLabel.JAILBREAK if triggered else ThreatLabel.BENIGN
                details = {
                    "temperature": self.temperature,
                    "max_prob": confidence,
                }
                return LayerResult(
                    layer="l2_statistical",
                    triggered=triggered,
                    score=risk_score,
                    label=label,
                    confidence=min(risk_score * 1.5, 1.0),
                    details=details,
                )
            except Exception:
                pass

        risk_score = self._keyword_score(text)
        triggered = risk_score > 0.2
        label = ThreatLabel.JAILBREAK if triggered else ThreatLabel.BENIGN
        return LayerResult(
            layer="l2_statistical",
            triggered=triggered,
            score=risk_score,
            label=label,
            confidence=min(risk_score * 1.5, 1.0),
            details={"fallback": "keyword"},
        )
