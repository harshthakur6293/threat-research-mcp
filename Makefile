            .PHONY: lint test build security

            lint:
	python -m ruff check .
	python -m ruff format --check .

            test:
	python -m pytest -q

            build:
	python -m build

            security:
	python -m bandit -r src
	python -m pip_audit
