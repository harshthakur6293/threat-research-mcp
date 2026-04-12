# Contributing to Threat Research MCP

Thank you for your interest in contributing! This document provides guidelines and tools to ensure your contributions pass CI checks.

## Quick Start for Contributors

```bash
# Clone and setup
git clone https://github.com/harshthakur6293/threat-research-mcp.git
cd threat-research-mcp
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Install pre-commit hooks (runs checks automatically before commits)
pip install pre-commit
pre-commit install
```

## Running CI Checks Locally

### Option 1: Makefile (Recommended)

```bash
# Run ALL CI checks (same as GitHub Actions)
make ci

# Or run individual checks
make lint      # Ruff linter
make format    # Auto-format code
make test      # Run tests with coverage
make security  # Bandit + pip-audit
```

### Option 2: Pre-commit Hooks

```bash
# Run all hooks on all files
pre-commit run --all-files

# Hooks run automatically on `git commit`
```

### Option 3: Manual Commands

```bash
# Linting
python -m ruff check .
python -m ruff format --check .

# Auto-fix linting issues
python -m ruff check --fix .
python -m ruff format .

# Tests
python -m pytest -q --maxfail=1 --cov=src/threat_research_mcp --cov-fail-under=70

# Security
python -m bandit -c pyproject.toml -r src
python -m pip_audit
```

## Before Pushing to GitHub

**Always run this before pushing:**

```bash
make ci
```

This runs the exact same checks as GitHub Actions and will catch failures locally.

## Code Style

- **Formatter:** Ruff (runs automatically via pre-commit)
- **Line length:** 100 characters
- **Python version:** 3.8+ (tests run on 3.11 and 3.12 in CI)

## Testing

- Write tests for new features in `tests/`
- Maintain >70% code coverage
- Tests must pass on Python 3.11 and 3.12

## Security

- Use `# nosec BXXX` comments for false positives (with explanation)
- Run `make security` before submitting PRs
- See `SECURITY.md` for scope and reporting

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run `make ci` to ensure all checks pass
5. Commit with clear messages (`git commit -m "feat: add amazing feature"`)
6. Push to your fork (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## Commit Message Format

We use conventional commits:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code refactoring
- `test:` Adding or updating tests
- `chore:` Maintenance tasks

## Getting Help

- Open an issue for bugs or feature requests
- Check existing issues before creating new ones
- See `docs/` for architecture and design decisions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
