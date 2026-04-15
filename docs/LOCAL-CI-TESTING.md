# Local CI Testing with Act

This guide explains how to test GitHub Actions workflows locally using `act` before pushing to GitHub.

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

## Quick Pre-Push Checklist

Run these commands before pushing to GitHub:

```bash
# 1. Run tests locally
python -m pytest -q

# 2. Format code
python -m ruff format .

# 3. Check linting
python -m ruff check .

# 4. Run full CI locally with act
act -W .github/workflows/ci.yml
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
