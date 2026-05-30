.PHONY: install test demo train eval server

install:
	pip install -r requirements.txt
	pip install -e .

test:
	pytest tests/ -v

demo:
	python demo.py

train:
	python -m ghostwall.data.generator
	python -m ghostwall.data.train_l3 data/synthetic/train.jsonl
	python -m ghostwall.data.train_l4 data/synthetic/train.jsonl

eval:
	python -m ghostwall.data.evaluate data/synthetic/test.jsonl

server:
	python -m ghostwall.cli server
