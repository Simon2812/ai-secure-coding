# AI Secure Coding Advisor

<p align="center">
  <b>AI-powered vulnerability detection & automated secure code fixing</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-Backend-blue"/>
  <img src="https://img.shields.io/badge/AI-LLM-purple"/>
  <img src="https://img.shields.io/badge/Security-CWE-red"/>
  <img src="https://img.shields.io/badge/Status-Active-brightgreen"/>
</p>

---

## Overview

The **AI Secure Coding Advisor** is a hybrid security analysis system that combines static analysis and a fine-tuned Large Language Model (LLM) to improve secure software development.

The system analyzes source code written in **Python**, **Java**, and **C/C++**, detects supported software vulnerabilities, explains their security impact, and assists developers in applying secure fixes through both a command-line interface (CLI) and a Visual Studio Code extension.

---

## Features

- Detects software vulnerabilities using AST-based static analysis
- Enhances vulnerability detection with a fine-tuned LLM
- Explains detected vulnerabilities through an integrated AI assistant
- Suggests secure code fixes with automatic application.
- Provides both a CLI tool and a VS Code extension
- Supports deep scan of entire projects and source code folders

---

## Architecture

The overall SecureAssist architecture is shown below.

<p align="center">
  <img src="https://github.com/user-attachments/assets/5d1587c8-9246-4a78-93ee-bfe695e8a1c5" width="850"/>
</p>

A detailed description of the system architecture and components is available in [`docs/technical-documentation.md`](docs/technical-documentation.md).

---

## Application Screenshots

### Settings Screen

<p align="center">
  <img src="https://github.com/user-attachments/assets/c7048c77-7831-4b0c-9f11-b91dd3f37624" width="850"/>
</p>

### Problem Highlight

<p align="center">
  <img src="https://github.com/user-attachments/assets/a716c476-fe7a-4881-ac09-2a97fefb1853" width="850"/>
</p>

### Learn More

<p align="center">
  <img src="https://github.com/user-attachments/assets/c1297e47-2528-43fe-b135-a7d73619a500" width="850"/>
</p>

### Autofix

<p align="center">
  <img src="https://github.com/user-attachments/assets/73aa67cc-6fd2-4488-b3b7-288aff8bd42d" width="850"/>
</p>

### AI Chat

<p align="center">
  <img src="https://github.com/user-attachments/assets/cf031f5d-d04c-45c0-98f1-275623c03fbf" width="850"/>
</p>

---
## Typical User Flow

### 1. Run Analysis

- Open the CLI or Visual Studio Code extension
- Select a source file or project
- Start the security analysis
- Review the detected vulnerabilities

### 2. Investigate Findings

- Select a reported vulnerability
- View the vulnerability description, CWE, and severity
- Read the AI-generated explanation
- Review the suggested secure fix

### 3. Remediate

- Apply the suggested fix manually or automatically
- Discard findings or disable selected CWE categories in settings
- Re-run the analysis to verify the remediation

---

## Documentation

Additional project documentation is available in the [`docs`](docs) directory.

| Document | Description |
|----------|-------------|
| [`testing.md`](docs/testing.md) | Testing strategy, implemented tests, and validation process |
| [`technical-documentation.md`](docs/technical-documentation.md) | Technical overview of the system architecture and components |
| [`project-management.md`](docs/project-management.md) | Development workflow using Jira and GitHub |

The repository also includes the complete project evaluation in
[`SecureAssist_Paper.docx`](SecureAssist_Paper.docx).

---
## Evaluation

SecureAssist has been evaluated using multiple third-party vulnerability detection benchmarks, including:

- RealVuln
- OWASP Benchmark
- NIST Juliet

The complete evaluation methodology, benchmark configuration, performance metrics,
comparison with existing tools, and discussion of limitations are documented in
[`SecureAssist_Paper.docx`](SecureAssist_Paper.docx).

---

## Future Work

Potential future improvements include:

- Support for additional CWE categories and programming languages
- Improved LLM fine-tuning and remediation quality
- Real-time project monitoring and continuous scanning
- Expanded IDE capabilities and user experience improvements

---

## Authors

- Simon Pakhtusov
- Denis Rozhansky

**Computer Science Students**  
**Bar-Ilan University**

---

## Why This Project

Unlike traditional security analysis tools, SecureAssist:

- ✅ Combines deterministic static analysis with AI reasoning
- ✅ Provides context-aware vulnerability explanations
- ✅ Suggests secure code fixes
- ✅ Integrates directly into the developer workflow through CLI and VS Code
- ✅ Is designed for both practical software development and security research

--- 

## Project Links

- GitHub repository: [Github](https://github.com/Simon2812/AI-Secure-Coding)
- Jira project: [Jira](https://aisecurecoding.atlassian.net/jira/software/projects/ASC/boards/1)
- Testing documentation: [docs/testing.md](docs/testing.md)
- Technical documentation: [docs/technical-documentation.md](docs/technical-documentation.md)
