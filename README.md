<p align="center">
  <big><big><big><b>🛡️ AI Secure Coding Advisor</b></big></big></big>
</p>

<hr>

## Overview

The **AI Secure Coding Advisor** is a hybrid security analysis system that combines static analysis and a fine-tuned Large Language Model (LLM) to improve secure software development.

The system analyzes source code written in **Python**, **Java**, and **C/C++**, detects supported software vulnerabilities, explains their security impact, and assists developers in applying secure fixes through both a command-line interface (CLI) and a Visual Studio Code extension.

A complete demonstration of the system and its key features is available in the [project demo video](https://youtu.be/LwK77hh57A8?si=tmUODS5RWyVmHmh1).

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
<img width="1614" height="708" alt="final-architecture" src="https://github.com/user-attachments/assets/4388385e-415d-4b2c-a5c7-e5acbb047217" />
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


### CLI Analysis

<p align="center">
<img width="1886" height="910" alt="cli-analyze" src="https://github.com/user-attachments/assets/287a2aae-d56f-432c-a307-fadb00fdd69e" />
</p>

### CLI Apply & Help

<p align="center">
<img width="1698" height="852" alt="cli-apply" src="https://github.com/user-attachments/assets/01c2e5cc-bbec-4d9c-b32e-db64e2f602e8" />
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

## Installation

### Visual Studio Code Extension

SecureAssist can be used through either the **Visual Studio Code extension** or the **CLI tool**.

Follow the installation instructions in:

➡️ [`docs/INSTALL.md`](docs/INSTALL.md)

### CLI

For CLI installation, local model setup, and usage instructions, see:

➡️ [`docs/CLI-INSTALL.md`](docs/CLI-INSTALL.md)

---

## Documentation

Additional project documentation is available in the [`docs`](docs) directory.

| Document | Description |
|----------|-------------|
| [`TESTING.md`](docs/TESTING.md) | Testing strategy, implemented tests, and validation process |
| [`TODO.md`](docs/TODO.md) | Detailed future work plan |
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
  
The full future work plan, including detailed explanations, is documented in [`TODO.md`](docs/TODO.md)

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

- [GitHub Repository](https://github.com/Simon2812/ai-secure-coding)
- [Jira Project](https://aisecurecoding.atlassian.net/jira/software/projects/ASC/boards/1)
- [VS Code Extension Installation](docs/INSTALL.md)
- [CLI Installation](docs/CLI-INSTALL.md)
- [Testing Documentation](docs/TESTING.md)
- [Technical Documentation](docs/technical-documentation.md)
- [Project Demo Video](https://youtu.be/LwK77hh57A8?si=tmUODS5RWyVmHmh1)
