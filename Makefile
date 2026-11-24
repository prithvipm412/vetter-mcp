.PHONY: install dev test lint demo

install:
	pip install -e ".[dev]"
	cd web && npm install

dev:
	./start.sh

test:
	pytest -q

lint:
	ruff check .
	ruff format --check .
	mypy .

demo:
	vetter demo
