# start-model.ps1 — start the Secure Assist model server (Docker).
#
# Usage (from anywhere):
#     .\start-model.ps1
#
# Stop the server with Ctrl+C in this window. The container is removed
# automatically (--rm); the downloaded model stays cached on disk, so
# every run after the first starts in seconds.

$image       = "secure-coding-llm"
# Absolute so the script works regardless of the current directory.
$secureAssist = "C:\temp\ai-secure-main\secure-assist"
$hfCache      = Join-Path $env:USERPROFILE ".cache\huggingface"

# Docker Desktop must be running before we can start anything.
# Docker writes harmless warnings to stderr, which PowerShell 5.1 would turn
# into terminating errors — so only the exit code is used to decide.
$ErrorActionPreference = "Continue"
$null = docker info 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker is not running. Start Docker Desktop, then try again." -ForegroundColor Red
    exit 1
}

# The image is built from llm-module/Dockerfile_updated (RTX 50-series build).
$exists = docker images -q $image 2>&1 | Where-Object { $_ -notmatch "WARNING" }
if (-not $exists) {
    Write-Host "Image '$image' not found. Build it first:" -ForegroundColor Yellow
    Write-Host "    cd C:\temp\ai-secure-main\llm-module"
    Write-Host "    docker build -f Dockerfile_updated -t $image ."
    exit 1
}

if (-not (Test-Path $hfCache)) {
    New-Item -ItemType Directory -Path $hfCache -Force | Out-Null
}

# A container from an earlier run may still hold port 8000.
$running = docker ps --filter "ancestor=$image" --format "{{.ID}} {{.Names}}" 2>&1 |
    Where-Object { $_ -notmatch "WARNING" }
if ($running) {
    Write-Host "The model server is already running:" -ForegroundColor Yellow
    Write-Host "    $running"
    Write-Host "It is serving on http://localhost:8000 - nothing to do."
    Write-Host "To restart it, stop the old container first:"
    Write-Host "    docker stop $(($running -split ' ')[0])"
    exit 0
}

Write-Host "Starting model server on http://localhost:8000 ..." -ForegroundColor Cyan
Write-Host "Wait for 'LLM service ready.' then press Ctrl+C to stop." -ForegroundColor DarkGray

# Build the mount arguments first - a braced variable followed by a colon is
# parsed as a scope qualifier, so compose the host/container pairs beforehand.
# huggingface mount   - reuse the downloaded model instead of fetching it again.
# secure-assist mount - evaluator.py requires the analyzer directory to exist.
$hfMount     = $hfCache + ":/root/.cache/huggingface"
$assistMount = $secureAssist + ":/secure-assist"

docker run --rm -it `
    --gpus all `
    -p 8000:8000 `
    -v $hfMount `
    -v $assistMount `
    $image
