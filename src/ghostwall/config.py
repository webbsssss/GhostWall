import os
from pathlib import Path
from typing import Dict, Any
import yaml


BASE_DIR = Path(__file__).resolve().parent.parent.parent


def load_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


class Config:
    def __init__(self, config_path: str = None):
        # load .env if available
        try:
            from dotenv import load_dotenv
            env_path = BASE_DIR / ".env"
            if env_path.exists():
                load_dotenv(env_path)
        except Exception:
            pass

        if config_path and os.path.exists(config_path):
            self._cfg = load_yaml(config_path)
        else:
            default_path = BASE_DIR / "configs" / "default.yaml"
            if default_path.exists():
                self._cfg = load_yaml(str(default_path))
            else:
                self._cfg = self._default_config()

    def _default_config(self) -> Dict[str, Any]:
        return {
            "l1_sanitizer": {
                "max_length": 16000,
                "strip_invisible": True,
                "decode_encodings": True,
                "normalize_unicode": True,
            },
            "l2_statistical": {
                "temperature": 2.0,
                "threshold": 0.65,
                "affirmative_instruction": "You are a good Assistant.",
            },
            "l3_embedding": {
                "vector_db_path": str(BASE_DIR / "models" / "faiss.index"),
                "models": ["sentence-transformers/all-MiniLM-L6-v2"],
                "top_k": 5,
                "similarity_threshold": 0.82,
            },
            "l4_stateful": {
                "gru_hidden": 256,
                "max_history_turns": 10,
                "intent_drift_threshold": 0.25,
            },
            "l5_judge": {
                "models": [],
                "consensus_threshold": 0.5,
                "timeout": 30,
            },
            "l6_output": {
                "canary_enabled": True,
                "coherence_threshold": 0.3,
            },
            "l7_behavioral": {
                "rate_limit": 60,
                "window_seconds": 60,
                "graduated_thresholds": [30, 60, 120],
            },
            "pipeline": {
                "fast_path_layers": ["l1", "l2", "l3"],
                "full_path_layers": ["l1", "l2", "l3", "l4", "l5"],
                "block_threshold": 0.7,
            },
        }

    def get(self, key: str, default=None):
        keys = key.split(".")
        val = self._cfg
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                return default
        return val

    def section(self, name: str) -> Dict[str, Any]:
        return self._cfg.get(name, {})
