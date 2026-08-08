# Technical Documentation

This document provides a concise technical overview of the SecureAssist system.

A detailed evaluation of the system, including benchmark methodology, performance results, comparison with other security tools, false-positive analysis, limitations, and future improvements, is available in the root-level [`SecureAssist_Paper.docx`](../SecureAssist_Paper.docx). 

## System Components

### Static Analyser

The static analyser uses AST-based and rule-based analysis to identify supported CWE categories in source code.

It provides the deterministic analysis layer of the system and supplies its findings to the rest of the SecureAssist pipeline.

### Model Service

The model service receives source code together with static-analysis context and returns detected vulnerabilities and suggested secure replacements.

The system uses a fine-tuned Qwen2.5-Coder model with a LoRA adapter. The trained adapter is stored on Hugging Face and loaded by the Python API service.

### CLI

The CLI provides a standalone interface for running SecureAssist.

It accepts either:

- a source-code file;
- source code provided directly as text.

The CLI runs the static analyser, calls the model API, combines the results, and presents the final vulnerability findings to the user.

### VS Code Extension

The VS Code extension integrates SecureAssist directly into the development environment.

It allows developers to analyse code from the editor and provides:

- detected vulnerabilities;
- CWE and vulnerability information;
- explanations;
- suggested fixes;
- automatic fix functionality;
- interaction with the AI security assistant.

## Result Classification

Analysis results are combined according to their detection source.

Findings may be:

- detected by both the static analyser and the model;
- detected only by the static analyser;
- detected only by the model.

This allows the user to distinguish findings supported by both analysis approaches from findings produced by only one component.

## External Services

The project uses:

- **Hugging Face** — model checkpoint storage;
- **RunPod** — deployment of the model API;
- **GitHub** — source control, branches, pull requests, tests, and project documentation;
- **Jira** — task planning, assignment, and development progress tracking.

## Main Technologies

- Python
- Python REST API
- TypeScript
- VS Code Extension API
- Tree-sitter / AST-based static analysis
- Hugging Face Transformers
- PEFT / LoRA
- Qwen2.5-Coder
