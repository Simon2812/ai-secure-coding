<img width="1600" height="873" alt="ai-chat" src="https://github.com/user-attachments/assets/b27b376f-43ca-48a1-9f27-7a6e2fa6d284" />
<img width="1623" height="624" alt="architecture" src="https://github.com/user-attachments/assets/43f36e5f-bab8-42a4-8450-e789f782a62d" />
<img width="1280" height="492" alt="arch" src="https://github.com/user-attachments/assets/a806c04e-fcce-4ef1-b13d-639b12a06465" />
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
<img width="1280" height="492" alt="arch" src="https://github.com/user-attachments/assets/bf4050bb-67ec-4df9-a8c7-afc85ddf2734" />
</p>

A detailed description of the system architecture and components is available in [`docs/technical-documentation.md`](docs/technical-documentation.md).

---

## Application Screenshots

### Report Screen

<p align="center">
<img width="1600" height="871" alt="report" src="https://github.com/user-attachments/assets/0737a758-c766-4681-b83b-c1a984b5f24d" />
</p>

### Problem Highlight

<p align="center">
<img width="1162" height="416" alt="problem-highlight" src="https://github.com/user-attachments/assets/c9902b75-a981-43ef-bc1f-80e97a04536f" />
</p>

### Deep Scan Screen

<p align="center">
<img width="1600" height="956" alt="deep-scan" src="https://github.com/user-attachments/assets/be12c206-ab15-4ec7-8714-f67ac292fc85" />
</p>

### AI Chat

<p align="center">
<img width="1600" height="873" alt="ai-chat" src="https://github.com/user-attachments/assets/7d87e7b9-a7ac-43f6-9249-7a9c0e89418f" />
</p>

### Settings Window

<p align="center">
<img width="1600" height="870" alt="settings-screen" src="https://github.com/user-attachments/assets/7798e2a2-008e-4b0e-b23c-908ee14f7094" />
</p>


### Dismissed/Suppressed Findings

<p align="center">
<img width="1600" height="872" alt="dismissed-findings" src="https://github.com/user-attachments/assets/387b58a1-19d1-4e71-8058-ff13899a1c0e" />
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
