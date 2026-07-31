# start-model.ps1 — start the Secure Assist model server (Docker).
#
# Usage (from anywhere):
#     .\start-model.ps1
#
# Stop the server with Ctrl+C in this window. The container is removed
# automatically (--rm); the downloaded model stays cached on disk, so
# every run after the first starts in seconds.

$ErrorActionPreference = "Stop"

$image       = "secure-coding-llm"
# Absolute so the script works regardless of the current directory.
$secureAssist = "C:\temp\ai-secure-main\secure-assist"
$hfCache      = Join-Path $env:USERPROFILE ".cache\huggingface"

# Docker Desktop must be running before we can start anything.
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker is not running. Start Docker Desktop, then try again." -ForegroundColor Red
    exit 1
}

# The image is built from llm-module/Dockerfile_updated (RTX 50-series build).
$exists = docker images -q $image
if (-not $exists) {
    Write-Host "Image '$image' not found. Build it first:" -ForegroundColor Yellow
    Write-Host "    cd C:\temp\ai-secure-main\llm-module"
    Write-Host "    docker build -f Dockerfile_updated -t $image ."
    exit 1
}

if (-not (Test-Path $hfCache)) {
    New-Item -ItemType Directory -Path $hfCache -Force | Out-Null
}

Write-Host "Starting model server on http://localhost:8000 ..." -ForegroundColor Cyan
Write-Host "Wait for 'LLM service ready.' — press Ctrl+C to stop." -ForegroundColor DarkGray

# -v huggingface : reuse the downloaded model instead of fetching it again.
# -v secure-assist: evaluator.py requires the analyzer directory to exist.
docker run --rm -it `
    --gpus all `
    -p 8000:8000 `
    -v "${hfCache}:/root/.cache/huggingface" `
    -v "${secureAssist}:/secure-assist" `
    $image
