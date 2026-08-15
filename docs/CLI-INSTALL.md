# CLI Local Installation with Docker

These steps install the `asc` command locally and run the model backend in Docker.

In this project, Docker is used for the LLM backend, not for the CLI command itself. The CLI is a local Python package from `cli/`, and it sends model requests to the Docker server at `http://127.0.0.1:8000/analyze`.

## Requirements

- Docker Desktop or Docker Engine
- NVIDIA GPU support for Docker, because the model image uses CUDA and 4-bit loading
- Python 3.8 or newer
- Node.js and npm

## 1. Open the repository root

Run all project commands from the repository root:

```bash
cd /path/to/AI-Secure-Coding
```

If you use PowerShell instead of WSL:

```powershell
cd C:\path\to\AI-Secure-Coding
```

## 2. Build the static analyzer used by the CLI

The CLI calls the TypeScript analyzer from `secure-assist/`. Build it once before using `asc analyze`:

```bash
cd secure-assist
npm install
npm run compile
cd ..
```

After this, the CLI can use `secure-assist/out/analyzer/analyzer_runner.js`.

## 3. Install the CLI locally

Install the Python CLI package from the `cli/` directory:

```bash
cd cli
python3 -m pip install -e .
cd ..
```

On Windows PowerShell, use:

```powershell
cd cli
py -m pip install -e .
cd ..
```

Check that the command is available:

```bash
asc -h
```

The command should start with `asc` directly. You do not need to run `python -m asc` after installation.

## 4. Build the Docker model backend

From the repository root:

```bash
docker build -t secure-coding-llm ./llm-module
```

The build installs the FastAPI server and model dependencies from `llm-module/Dockerfile`.

## 5. Start the model backend

From the repository root in WSL or Linux:

```bash
mkdir -p ~/.cache/huggingface

docker run --rm --gpus all -p 8000:8000 \
  -v "$HOME/.cache/huggingface:/root/.cache/huggingface" \
  -v "$(pwd)/secure-assist:/secure-assist:ro" \
  secure-coding-llm
```

From PowerShell:

```powershell
docker run --rm --gpus all -p 8000:8000 `
  -v "$env:USERPROFILE\.cache\huggingface:/root/.cache/huggingface" `
  -v "${PWD}\secure-assist:/secure-assist:ro" `
  secure-coding-llm
```

Keep this terminal open. The backend is ready when it prints:

```text
LLM service ready.
```

The first run can take time because Docker may need to download the Hugging Face model files.

You can test the backend from another terminal:

```bash
curl http://127.0.0.1:8000/health
```

Expected response:

```json
{"status":"ok"}
```

## 6. Run the CLI

Open a second terminal at the repository root:

```bash
cd /path/to/AI-Secure-Coding
```

Analyze a file and write a report:

```bash
asc analyze test.py -o report.json
```

View the report:

```bash
cat report.json
```

Apply the first suggested fix from the report:

```bash
asc apply report.json 1
```

The apply command reads `report.json`, uses the saved `metadata.source_path`, and applies the selected fix to that source file.

## Notes

- Run `asc analyze` from the repository root when using project-relative paths.
- If you run it from inside `cli/`, paths like `dataset/...` will be resolved relative to `cli/`, so they will not point to the repository dataset.
- The default model endpoint is `http://127.0.0.1:8000/analyze`.
- To use a different endpoint, set `ASC_MODEL_API_URL` before running the CLI:

```bash
export ASC_MODEL_API_URL="http://127.0.0.1:8000/analyze"
```

PowerShell:

```powershell
$env:ASC_MODEL_API_URL = "http://127.0.0.1:8000/analyze"
```
