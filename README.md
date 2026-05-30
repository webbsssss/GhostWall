# GhostWall

A prompt injection detector for LLM apps. Built as part of a security research project.

## What it does

Scans user prompts before they hit your LLM. Catches obvious attacks (jailbreaks, prompt injection) and some obfuscated ones too.

## Stack

- **L1 Sanitizer** - strips invisible chars, decodes base64/hex/rot13, fixes homoglyphs
- **L2 Statistical** - checks first-token confidence (cheap heuristic)
- **L3 Embedding** - semantic similarity to known attack patterns via sentence-transformers
- **L4 Stateful** - GRU that tracks intent drift across conversation turns
- **L5 Judge** - optional LLM-as-a-judge for edge cases
- **L6 Output Guard** - canary tokens + response coherence check
- **L7 Behavioral** - rate limiting per session

## Install

```bash
pip install -r requirements.txt
pip install -e .
```

For the judge layer (optional), copy `.env.example` to `.env` and add your API keys:

```bash
cp .env.example .env
```

## Quick Start

```python
from ghostwall.core.pipeline import DetectionPipeline

p = DetectionPipeline()
r = p.scan("Ignore previous instructions and...")
print(r.is_malicious, r.risk_level)
```

Or run the demo:

```bash
python demo.py
```

## API Server

```bash
python -m ghostwall.cli server
```

Then POST to `http://localhost:8000/scan`:

```json
{"text": "user prompt here"}
```

## Scripts

- **Red-team probe**: `python scripts/redteam.py`
- **Benchmark**: `python scripts/benchmark.py data/synthetic/test.jsonl`

Or use the Makefile:

```bash
make demo
make test
make eval
make server
```

## Training

Generate synthetic data:

```bash
python -m ghostwall.data.generator
```

Train the embedding index:

```bash
python -m ghostwall.data.train_l3 data/synthetic/train.jsonl
```

Train the GRU:

```bash
python -m ghostwall.data.train_l4 data/synthetic/train.jsonl
```

## Project Structure

```
src/ghostwall/
  layers/         # L1-L7 detection layers
  core/           # pipeline + types
  data/           # dataset generation + training scripts
  api/            # FastAPI server
  cli.py          # command-line interface
configs/          # YAML config
tests/            # pytest suite
scripts/          # redteam + benchmark
demo.py           # quick demo
```

## Tests

```bash
pytest tests/
```

## License

MIT
