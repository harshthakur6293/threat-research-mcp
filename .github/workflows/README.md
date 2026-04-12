# GitHub Actions Workflows

## Running CI Locally

### Option 1: Pre-commit Hooks (Fastest)
```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

### Option 2: Makefile (Recommended)
```bash
# Run all CI checks
make ci

# Or individual checks
make lint
make test
make security
```

### Option 3: Act (GitHub Actions locally)
```bash
# Install: https://github.com/nektos/act
# Windows: winget install nektos.act

# Run all workflows
act push

# Run specific workflow
act -j test
act -j security
```

### Option 4: Manual Commands (Same as CI)
```bash
# Linting
python -m ruff check .
python -m ruff format --check .

# Tests
python -m pytest -q --maxfail=1 --cov=src/threat_research_mcp --cov-fail-under=70

# Security
python -m bandit -c pyproject.toml -r src
python -m pip_audit
```

## Workflows

- **ci.yml** - Runs tests on Python 3.11 and 3.12
- **security.yml** - Runs bandit and pip-audit
- **build.yml** - Builds Python package
- **cache-hygiene.yml** - Cleans up old GitHub Actions caches
