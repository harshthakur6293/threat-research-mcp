# Local CI/CD Testing Script
# Quick commands to test GitHub Actions workflows locally

param(
    [string]$Workflow = "all",
    [switch]$List,
    [switch]$DryRun,
    [switch]$Help
)

$ErrorActionPreference = "Continue"

function Show-Help {
    Write-Host ""
    Write-Host "Local CI/CD Testing Script" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\local-ci-test.ps1 [options]" -ForegroundColor White
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Yellow
    Write-Host "  -Workflow <name>   Run specific workflow (ci, build, security, all)" -ForegroundColor White
    Write-Host "  -List              List all available workflows" -ForegroundColor White
    Write-Host "  -DryRun            Show what would run without executing" -ForegroundColor White
    Write-Host "  -Help              Show this help message" -ForegroundColor White
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  .\local-ci-test.ps1 -List" -ForegroundColor Gray
    Write-Host "  .\local-ci-test.ps1 -Workflow ci" -ForegroundColor Gray
    Write-Host "  .\local-ci-test.ps1 -Workflow build -DryRun" -ForegroundColor Gray
    Write-Host "  .\local-ci-test.ps1" -ForegroundColor Gray
    Write-Host ""
}

if ($Help) {
    Show-Help
    exit 0
}

Write-Host ""
Write-Host "=== Local CI/CD Testing ===" -ForegroundColor Cyan
Write-Host ""

# Check if act is installed
try {
    $actVersion = act --version 2>&1
    Write-Host "[OK] act is installed: $actVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] act is not installed" -ForegroundColor Red
    Write-Host "Run: .\setup-local-cicd.ps1" -ForegroundColor Yellow
    exit 1
}

# Check if Docker is running
try {
    docker ps | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Docker is not running" -ForegroundColor Red
        Write-Host "Start Docker Desktop and try again" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "[OK] Docker is running" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Docker is not available" -ForegroundColor Red
    Write-Host "Install Docker Desktop from: https://www.docker.com/products/docker-desktop" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# List workflows
if ($List) {
    Write-Host "Available workflows:" -ForegroundColor Yellow
    Write-Host ""
    act -l
    Write-Host ""
    Write-Host "Run a specific workflow with: .\local-ci-test.ps1 -Workflow <name>" -ForegroundColor Gray
    exit 0
}

# Dry run
if ($DryRun) {
    Write-Host "[DRY RUN] Would execute:" -ForegroundColor Yellow
    Write-Host ""
}

# Run workflows
switch ($Workflow) {
    "ci" {
        Write-Host "Running CI workflow..." -ForegroundColor Cyan
        if ($DryRun) {
            Write-Host "  act -W .github/workflows/ci.yml --dryrun" -ForegroundColor Gray
        } else {
            act -W .github/workflows/ci.yml
        }
    }
    "build" {
        Write-Host "Running Build workflow..." -ForegroundColor Cyan
        if ($DryRun) {
            Write-Host "  act -W .github/workflows/build.yml --dryrun" -ForegroundColor Gray
        } else {
            act -W .github/workflows/build.yml
        }
    }
    "security" {
        Write-Host "Running Security workflow..." -ForegroundColor Cyan
        if ($DryRun) {
            Write-Host "  act -W .github/workflows/security.yml --dryrun" -ForegroundColor Gray
        } else {
            act -W .github/workflows/security.yml
        }
    }
    "all" {
        Write-Host "Running all workflows..." -ForegroundColor Cyan
        if ($DryRun) {
            Write-Host "  act --dryrun" -ForegroundColor Gray
        } else {
            act
        }
    }
    default {
        Write-Host "[ERROR] Unknown workflow: $Workflow" -ForegroundColor Red
        Write-Host "Available: ci, build, security, all" -ForegroundColor Yellow
        Write-Host "Use -List to see all workflows" -ForegroundColor Gray
        exit 1
    }
}

Write-Host ""
Write-Host "=== Test Complete ===" -ForegroundColor Cyan
Write-Host ""
