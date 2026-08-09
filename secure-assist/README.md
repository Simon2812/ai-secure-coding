# Secure Assist

Finds, explains and fixes security vulnerabilities while you write code.

A static analyzer runs as you type, using tree-sitter and taint tracking to
follow attacker-controlled data from where it enters your code to where it
does something dangerous. An optional locally-hosted language model reviews
the same file and proposes repairs. An AI assistant explains any finding in
plain language.

## What it detects

| CWE | Weakness | Python | Java | C |
|---|---|---|---|---|
| CWE-22 | Path traversal | yes | yes | — |
| CWE-78 | OS command injection | yes | yes | yes |
| CWE-89 | SQL injection | yes | yes | — |
| CWE-190 | Integer overflow | — | — | yes |
| CWE-259 | Hard-coded password | yes | yes | yes |
| CWE-321 | Hard-coded cryptographic key | yes | yes | yes |
| CWE-327 | Broken or risky cryptography | yes | yes | yes |
| CWE-328 | Reversible one-way hash | yes | yes | yes |
| CWE-416 | Use after free | — | — | yes |
| CWE-787 | Out-of-bounds write | — | — | yes |

## Features

**Live analysis.** Findings appear as you type. No GPU, no network, no
configuration — the analyzer is bundled and runs entirely locally.

**Project report.** A folder-by-folder view with a score per file and per
directory, a CWE breakdown, a score trend across scans, and an HTML export.

**AI repairs.** With a model server configured, "Scan with AI" reviews a file
and proposes fixes. Every fix is shown as a diff and applied only if you
accept it. Applied fixes can be reverted, which restores both the code and
the finding.

**False-positive suppression.** Dismiss a finding and it stays dismissed —
keyed to the code itself rather than the line number, so it survives edits
above it but reappears if that code genuinely changes.

**Explanations.** Ask the assistant about any finding: what an attacker would
do with it, why the suggested fix works, and whether dismissing it is safe.

## Requirements

The static analyzer needs nothing beyond VS Code.

The AI features need a model server exposing `POST /analyze` on
`http://localhost:8000` (configurable). The assistant needs an Anthropic API
key set in **user** settings — never commit it to a repository.

## Settings

| Setting | Default | Description |
|---|---|---|
| `secureAssist.liveMode` | `true` | Re-analyse as you type, rather than on save |
| `secureAssist.modelEndpoint` | `http://localhost:8000` | Model server for AI scans and fixes |
| `secureAssist.enabledCwes` | all enabled | Which CWEs are reported and counted in the score |
| `secureAssist.agentApiKey` | — | Anthropic API key for the assistant |

## Commands

- **Secure Assist: Deep Scan Project** — scan the workspace and open the report
- **Secure Assist: Scan with AI** — run the model over the active file
- **Secure Assist: Show AI Fixes** — the fixes panel for the active file
- **Secure Assist: Ask the Security Assistant** — open the assistant
- **Secure Assist: Settings** — CWE toggles, suppressions, stored data

## Known limitations

Analysis is **single-file**. Within a file it does follow data across
functions — parameters are treated as untrusted and calls to functions defined
in the same file are resolved — but flow that crosses file boundaries is not
tracked.

Reflective dispatch is not modelled, and neither is buffer-size arithmetic, so
size-mismatch overflows such as `memcpy` with an incorrect `sizeof` are missed.
Input parsed outside the standard framework request objects is not recognised
as a source.

AI-generated fixes are not always correct. They are always shown as a diff
first, and should be read before being applied.

## Privacy

The static analyzer runs entirely on your machine and sends nothing anywhere.
The AI scan sends the file to whatever endpoint you configure — by default a
model on localhost. The assistant sends the finding and the surrounding code
to the Anthropic API.
