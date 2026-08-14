# AI Secure Coding Advisor

<p align="center">
  <b>AI-powered vulnerability detection & automated secure code fixing</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-Backend-blue"/>
  <img src="https://img.shields.io/badge/AI-LLM-purple"/>
  <img src="https://img.shields.io/badge/Security-CWE-red"/>
  <img src="https://img.shields.io/badge/Status-Active-brightgreen"/>
  [![Download](https://img.shields.io/badge/download-.vsix-3DDC97?style=flat-square)](https://github.com/Simon2812/ai-secure-coding/releases/tag/v0.0.1)
</p>

---

## Overview

The **AI Secure Coding Advisor** is an intelligent system that:

- Detects vulnerabilities in source code
- Explains why code is insecure
- Suggests secure fixes automatically

It combines:

- Static analysis
- Large Language Models (LLMs)
- Real-world datasets

The system provides context-aware security insights and targets vulnerabilities such as injections, hardcoded secrets, and weak cryptography.

---

## Problem

Modern development suffers from:

- Late vulnerability detection
- Static tools without context
- High false-positive rates

This makes real threats difficult to identify and fix efficiently.

---

## Objectives

- Build a static analyzer + LLM layer
- Train models on real datasets
- Provide a CLI tool
- Develop an IDE plugin

---

## Architecture

###  System Architecture (Entity Diagram)

<p align="center">
  <img src="https://github.com/user-attachments/assets/5d1587c8-9246-4a78-93ee-bfe695e8a1c5" width="850"/>
</p>

### Components

#### Data Sources
- NIST datasets
- OWASP Benchmark
- Open-source repositories

#### Analyzer Layer
- AST-based static analysis
- Rule-based detection
- LLM reasoning

#### Backend
- Python REST API

#### Interfaces
- CLI tool
- VS Code extension

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

### Run Analysis
- Open CLI or IDE plugin
- Select code/project
- Start analysis
- Receive vulnerability report

### Apply Fix
- Select vulnerability
- View details (type, CWE, severity)
- Review suggested fix
- Apply manually or use auto-fix

---

## User Stories

- Developer receives real-time warnings
- Student understands why code is insecure
- Junior developer gets auto-fix suggestions
- Security analyst sees risk scores
- Team lead manages findings as **To-Do** or **Ignore**

---

## Technologies

- **Backend:** Python (Flask)
- **Static Analysis:** AST + rule-based analysis
- **AI Layer:** LLM integration
- **IDE Plugin:** VS Code (TypeScript)
- **Data Sources:** NIST, OWASP, GitHub

---

## Future Work

- Full IDE integration
- Better LLM fine-tuning
- Real-time scanning
- Expanded CWE coverage

---

## Authors

- Simon Pakhtusov
- Denis Rozhansky

Computer Science Students (Bar-Ilan University)

---

## Why This Project

Unlike traditional tools, this system:

- ✅ Understands context
- ✅ Provides real fixes
- ✅ Reduces false positives
- ✅ Is designed for AI training and real usage
