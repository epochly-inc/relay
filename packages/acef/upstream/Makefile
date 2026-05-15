.PHONY: test lint format build install clean typecheck

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --tb=short

test-cov:
	pytest tests/ -v --tb=short --cov=acef --cov-report=term-missing --cov-report=json:coverage.json

test-unit:
	pytest tests/unit/ -v --tb=short

test-integration:
	pytest tests/integration/ -v --tb=short

test-conformance:
	pytest tests/conformance/ -v --tb=short

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

typecheck:
	mypy src/acef/

build:
	python -m build

clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info .pytest_cache .mypy_cache coverage.json
	find . -type d -name __pycache__ -exec rm -rf {} +
