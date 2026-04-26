# Local CI testing (before you push)

Use either **the same commands GitHub runs** (no Docker), or **`act`** (runs the YAML workflows inside Docker). For day-to-day work, mirroring CI with plain shell commands is fastest and most reliable.

---

## Option A — Mirror CI without Docker (recommended)

From the **repository root** (`threat-research-mcp/`), use a Python version that CI cares about (**3.11 or 3.12**). Your default `python` might be older (e.g. 3.8); use `py -3.11` on Windows or `python3.12` on Linux if you have them installed.

**1. Install runtime + dev dependencies (same as CI)**

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

**2. `ci` workflow — lint, format, tests + coverage**

```bash
python -m ruff check .
python -m ruff format --check .
python -m pytest -v --maxfail=1 --cov=src/threat_research_mcp --cov-fail-under=65 --tb=short
```

**3. `build` workflow — package builds**

```bash
python -m pip install build twine
python -m build
python -m twine check dist/*
```

**4. `security` workflow — Bandit + dependency audit**

```bash
python -m bandit -r src
python -m pip_audit
```

**One-liner copy-paste** (after `pip install -e ".[dev]"` once):

```bash
python -m ruff check . && python -m ruff format --check . && python -m pytest -v --maxfail=1 --cov=src/threat_research_mcp --cov-fail-under=65 --tb=short && python -m pip install build twine && python -m build && python -m twine check dist/* && python -m bandit -r src && python -m pip_audit
```

**What this does not run locally**

- **Matrix**: CI runs tests on **both** Python 3.11 and 3.12. Locally, run the block above under each version if you can (e.g. two venvs or `py -3.11` / `py -3.12`).
- **CodeQL** (`.github/workflows/codeql.yml`): analysis runs on GitHub; local parity is optional via the [CodeQL CLI](https://docs.github.com/en/code-security/codeql-cli) or the CodeQL VS Code extension, not required for every push.

---

## Option B — Run GitHub Actions YAML with `act`

This guide also covers how to test GitHub Actions workflows locally using **`act`**, which replays workflow steps in containers.

## Prerequisites

1. **Docker Desktop** - Must be installed and running
   - Windows: `winget install Docker.DockerDesktop`
   - macOS: `brew install --cask docker`
   - Linux: Follow [Docker installation guide](https://docs.docker.com/engine/install/)

2. **Act** - GitHub Actions runner
   - Already installed: `act version 0.2.87`
   - Windows: `winget install nektos.act`
   - macOS: `brew install act`
   - Linux: `curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash`

## Starting Docker

Before using `act`, ensure Docker Desktop is running:

```bash
# Check if Docker is running
docker ps

# If not running, start Docker Desktop from Start Menu or:
# Windows: Start-Process "Docker Desktop"
```

## Running Tests Locally with Act

### Test All Workflows

```bash
# Run all workflows (equivalent to GitHub Actions)
act
```

### Test Specific Workflow

```bash
# Test only the CI workflow (tests + linting)
act -W .github/workflows/ci.yml

# Test only on specific Python version
act -W .github/workflows/ci.yml -j "test (3.11)"
```

### Test Specific Job

```bash
# Run only the test job
act -j test

# Run only the security scan
act -j security
```

### Dry Run (List Jobs)

```bash
# See what would run without actually running it
act -l
```

### Run with Verbose Output

```bash
# Get detailed logs
act -v

# Even more verbose
act -vv
```

## Common Act Options

| Option | Description |
|--------|-------------|
| `-n` | Dry run mode - show what would run |
| `-l` | List workflows and jobs |
| `-j <job>` | Run specific job |
| `-W <workflow>` | Run specific workflow file |
| `-v` | Verbose output |
| `--pull` | Pull latest Docker images |
| `-P` | Specify platform (e.g., `-P ubuntu-latest=catthehacker/ubuntu:act-latest`) |

## Quick pre-push checklist

1. Run **Option A** (mirror commands) on **Python 3.11 or 3.12** — matches `ci.yml` / `security.yml`.
2. Optionally run **`act`** (Option B) if Docker is running and you want to validate the workflow files themselves.

```bash
# Optional: auto-fix Ruff issues before format check
python -m ruff check . --fix
python -m ruff format .
```

## Troubleshooting

### Docker Not Running

```
Error: Cannot connect to the Docker daemon
```

**Solution**: Start Docker Desktop

### Act Using Too Much Memory

```bash
# Use smaller Docker images
act -P ubuntu-latest=catthehacker/ubuntu:act-latest
```

### Act Taking Too Long

```bash
# Skip specific jobs
act -j test  # Only run tests, skip build/security
```

## CI Workflow Summary

Our `.github/workflows/ci.yml` runs:

1. **Test Job** (Python 3.11, 3.12)
   - Install dependencies
   - Run pytest with coverage (≥65%)
   - Upload coverage reports

2. **Build Job**
   - Verify package builds correctly
   - Check distribution files

3. **Security Job**
   - Run Bandit security scanner
   - Check for vulnerabilities

## Performance Tips

1. **First run is slow** - Act downloads Docker images (~2GB)
2. **Subsequent runs are fast** - Cached images and dependencies
3. **Use specific jobs** - Run only what you changed (e.g., `-j test`)
4. **Use `-n` for quick validation** - Dry run to check workflow syntax

## Example Workflow

```bash
# Make code changes
vim src/threat_research_mcp/agents/hunting_agent_v2.py

# Test locally (fast)
python -m pytest tests/test_hunting_agent_v2.py -v

# Run full CI locally (comprehensive)
act -W .github/workflows/ci.yml

# If everything passes, commit and push
git add .
git commit -m "feat: Add new hunting capability"
git push origin main
```

## Benefits of Local CI Testing

✅ **Catch CI failures before pushing**  
✅ **Faster feedback loop** (no waiting for GitHub)  
✅ **Save CI minutes** (especially important for private repos)  
✅ **Test workflow changes safely**  
✅ **Work offline** (after initial Docker image download)  

## Resources

- [Act Documentation](https://github.com/nektos/act)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Docker Documentation](https://docs.docker.com/)
