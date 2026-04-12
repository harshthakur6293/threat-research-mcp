.PHONY: help install test lint format security ci clean

help:  ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:  ## Install package with dev dependencies
	python -m pip install -e ".[dev]"
	pre-commit install

test:  ## Run tests with coverage
	python -m pytest -q --maxfail=1 --cov=src/threat_research_mcp --cov-fail-under=70

lint:  ## Run ruff linter
	python -m ruff check .

format:  ## Format code with ruff
	python -m ruff format .

format-check:  ## Check if code is formatted
	python -m ruff format --check .

security:  ## Run security checks (bandit + pip-audit)
	python -m bandit -c pyproject.toml -r src
	python -m pip_audit

ci:  ## Run all CI checks locally (same as GitHub Actions)
	@echo "=== Running Ruff Linter ==="
	python -m ruff check .
	@echo "\n=== Checking Code Format ==="
	python -m ruff format --check .
	@echo "\n=== Running Tests ==="
	python -m pytest -q --maxfail=1 --cov=src/threat_research_mcp --cov-fail-under=70
	@echo "\n=== Security Checks ==="
	python -m bandit -c pyproject.toml -r src
	python -m pip_audit
	@echo "\n✅ All CI checks passed!"

clean:  ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info .pytest_cache .ruff_cache .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
