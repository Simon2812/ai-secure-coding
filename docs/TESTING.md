# Testing

This document describes the project tests by component. It includes CLI software tests, VS Code extension tests, static-analyzer checks, benchmark/evaluation scripts, and model checkpoint testing.

## CLI

Install the CLI test dependency if needed:

PowerShell:

```powershell
python -m pip install pytest
```

Bash:

```bash
python3 -m pip install pytest
```

### `cli/tests/test_cli_workflow.py`

This test verifies the main command-line workflow. It creates a temporary Python file, runs the real `asc analyze` entry point with a mocked analysis pipeline, checks that a JSON report is written with metadata and finding ids, then runs `asc apply` on the generated report and confirms the selected fix changes the source file.

It checks CLI wiring and report/apply compatibility. It does not test model detection quality.

PowerShell:

```powershell
$env:PYTHONPATH = "cli"
python -m pytest cli/tests/test_cli_workflow.py
```

Bash:

```bash
PYTHONPATH=cli python3 -m pytest cli/tests/test_cli_workflow.py
```

### `cli/tests/test_apply_safety.py`

This test verifies safety behavior for automatic code changes. It checks that an invalid finding id gives a clear error, overlapping fixes are rejected before writing, and a Python fix that would break syntax is not written to the file.

It protects the most sensitive CLI behavior: modifying user source code.

PowerShell:

```powershell
$env:PYTHONPATH = "cli"
python -m pytest cli/tests/test_apply_safety.py
```

Bash:

```bash
PYTHONPATH=cli python3 -m pytest cli/tests/test_apply_safety.py
```

## VS Code Extension

Install extension dependencies if needed:

PowerShell and Bash:

```bash
cd secure-assist
npm install --legacy-peer-deps
```

### `secure-assist/src/test/extension.test.ts`

This test confirms that the VS Code extension test host starts correctly and can execute the extension test suite.

PowerShell and Bash:

```bash
cd secure-assist
npm test
```

### `secure-assist/src/test/softwareState.test.ts`

This test verifies extension state behavior used by the report UI. It checks that suppressions follow normalized code text instead of line number, that edited code is reported again, that disabled CWE settings filter extension findings and model vulnerability records, and that scoring uses the enabled findings.

PowerShell and Bash:

```bash
cd secure-assist
npm test
```

### `secure-assist/src/test/originMatch.test.ts`

This test verifies grounding of model-proposed fixes. It checks exact origin matching, whitespace-tolerant matching, escaped-newline matching, recovery of missing line numbers from a real origin snippet, and discarding a finding whose origin text is not present in the source file.

PowerShell and Bash:

```bash
cd secure-assist
npm test
```

## Static Analyzer

### `secure-assist/test-samples/run-tests.js`

This script runs the AST static analyzer against the sample files under `secure-assist/test-samples/`. For each sample, it checks whether the expected CWE for that directory is detected and prints a per-CWE summary.

This is a diagnostic/static-analyzer check, not a model benchmark.

PowerShell and Bash:

```bash
cd secure-assist
npm run compile
node test-samples/run-tests.js
```

### `secure-assist/src/scripts/eval/*.ts`

These scripts are evaluation and diagnostic utilities for specific analyzer experiments, such as fresh samples, RealVuln-style checks, Juliet/OWASP pilots, false-positive diagnosis, and CWE-specific comparisons.

They are useful when developing or validating analyzer rules. They are not part of the compact automated software test suite.

PowerShell and Bash:

```bash
cd secure-assist
npm run compile
node out/scripts/eval/<script-name>.js
```

Example:

```bash
node out/scripts/eval/_ast_test.js
```

### `secure-assist/src/scripts/dev/*.ts`

These are development checks and debugging utilities for individual analyzer rules. They are intended for local investigation when changing static-analysis behavior.

PowerShell and Bash:

```bash
cd secure-assist
npm run compile
node out/scripts/dev/<script-name>.js
```

Example:

```bash
node out/scripts/dev/test_cwe22.js
```

## Hybrid Static + Model Evaluation

### `secure-assist/bench/run.js`

This benchmark runner builds a corpus, runs the static analyzer, optionally sends the code and static findings to the model API, and writes cached JSONL results. It supports OWASP, Juliet, RealVuln-style, static-only, and model-assisted runs depending on options and available data.

This is the evaluation workflow used for recall, precision, false-positive analysis, and hybrid static plus model behavior. It is separate from the software tests above.

PowerShell and Bash:

```bash
cd secure-assist
npm run compile
node bench/run.js --dry-run
```

Static-only run:

```bash
node bench/run.js --static-only --out bench/results-static
```

Model-assisted run:

```bash
node bench/run.js --endpoint http://localhost:8000 --out bench/results
```

Useful options include:

- `--only GROUP` to restrict the corpus
- `--owasp-limit N` to limit OWASP cases
- `--juliet-limit N` to limit Juliet files
- `--fresh` to ignore previous cache
- `--retry-errors` to rerun failed cases

### `secure-assist/bench/score.js`

This script scores cached benchmark output. It recomputes metrics from saved results without rerunning inference.

PowerShell and Bash:

```bash
cd secure-assist
node bench/score.js bench/results
```

### `secure-assist/bench/results/` and `secure-assist/bench/results-realvuln/`

These folders contain saved benchmark outputs and summaries. They are evidence from prior evaluation runs, not source tests that need to be edited.

## Model

### `llm-module/test_model.py`

This script loads the Hugging Face model checkpoint, patches adapter configuration keys if needed for the installed PEFT version, loads the project test dataset from `secure-assist/enriched`, runs model testing, and writes `test_results.json` plus `training_config.json` under `llm-module/checkpoints/hf-latest-test/`.

This evaluates the model checkpoint. It does not train the model and does not test CLI or extension software behavior.

The script requires the model dependencies from `llm-module/requirements.txt` and access to the Hugging Face checkpoint.

PowerShell:

```powershell
cd llm-module
python -m pip install -r requirements.txt
python test_model.py
```

Bash:

```bash
cd llm-module
python3 -m pip install -r requirements.txt
python3 test_model.py
```

### `llm-module/checkpoints/best/test_results.json`

This file stores saved model test results for the best local checkpoint. It is an output artifact used for comparison, not a runnable test file.
