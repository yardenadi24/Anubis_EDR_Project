# Anubis EDR

![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue?logo=windows)
![Language](https://img.shields.io/badge/Language-C%2B%2B17+-00599C?logo=cplusplus)
![Driver](https://img.shields.io/badge/Driver-WDK%20Kernel--Mode-orange)
![License](https://img.shields.io/badge/License-Educational%20%2F%20Research-green)

A modular **Endpoint Detection and Response** framework for Windows. Kernel-mode driver + user-mode agent for real-time process, filesystem, and network monitoring.

---

## Table of Contents

- [Overview](#overview)
- [Capabilities](#capabilities)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Installation & Running](#installation--running)
- [Configuration](#configuration)
- [License](#license)
- [Demo](#Demo)

---

## Overview

**Anubis EDR** is a Windows security framework split into two components:

| Component | Mode | Description |
|-----------|------|-------------|
| `AnubisEdr.sys` | Kernel | Lightweight driver that hooks process, filesystem, and network events using OS callbacks and waits for verdicts |
| `AnubisAgent.exe` | User | Service-based agent that receives events, applies detection logic, and returns allow/block decisions |

The kernel driver is intentionally thin — all decision-making lives in user mode, making it easy to update rules and add detection modules without reloading the driver.

---

## Capabilities

### Process Monitoring

Intercepts process creation via `PsSetCreateProcessNotifyRoutineEx`.

- Evaluates new processes against configurable **blocklists** (by name or image path)
- Also use Anti-malware flow to scan and evaluate verdict.
- Returns an **allow/block verdict** to the driver **before** the process is permitted to run
- Agent PID is registered with the driver to avoid self-monitoring

### Filesystem Monitoring

Windows **minifilter driver**

- Hooks `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, and `IRP_MJ_SET_INFORMATION` (rename / delete)
- On file create or write — we can trigger an **anti-malware scan pipeline** and can **block** the operation
- Rename, delete, and set-info events are captured for auditing
- Supports path exclusions, extension exclusions, and protected directory rules

### Network Monitoring

Kernel-mode hooks via the **Windows Filtering Platform (WFP)**.

- Captures **bind**, **connect**, **accept**, **established**, and **disconnect** events
- Full 5-tuple metadata: source/dest IP, port, protocol (TCP/UDP), direction
- Blocking rules by **remote IP**, **remote port**, **local port**, or **process name**

### Anti-Malware Engine

Pluggable, priority-ordered scanning pipeline with a dedicated async worker thread.
Ships with two built-in modules:
| Module | Detection Method | Details |
|--------|-----------------|---------|
| **YARA Module** | Signature-based static analysis | Loads `.yar` rule files from a configurable directory |
| **Verdict DB Module** | SHA-256 hash lookup | JSON database of known-good (allow) and known-bad (block) hashes |

New modules (cloud lookup, ML model, etc.) are added by implementing the `ISecurityModule` interface.

### Event System

- **SecurityEventService** — centralized event bus with severity levels (`Info`, `Warning`, `Error`, `Critical`)
- **EventPersistenceService** — serializes security events to JSON files on disk
- **MonitoringEventService** — high-volume telemetry into a **cyclic file buffer** (10 x 50 MB rotating logs)

### Key Design Principles

- **Modular services** — every capability is an `IService` that can be independently started, stopped, and configured
- **Pluggable security modules** — the anti-malware pipeline accepts any `ISecurityModule`, sorted by priority
- **Thin kernel, smart user-mode** — the driver captures events and waits; all logic lives in the agent
- **Async verdict loop** — monitor services poll via IOCTL, evaluate, and post verdicts back
- **Self-deadlock prevention** — the agent registers its PID so the minifilter skips its own I/O

---

## Prerequisites

- **OS:** Windows 10 / 11 (x64)
- **IDE:** Visual Studio 2019 or later
- **Workloads:**
  - Desktop development with C++
  - Windows Driver Kit (WDK) — matching the installed Windows SDK version
- **Third-party libraries:**
  - [YARA](https://github.com/VirusTotal/yara) — compiled `.lib` + headers
  - [RapidJSON](https://github.com/Tencent/rapidjson) — header-only
- **Runtime requirements:**
  - Administrator privileges (the agent opens `\\.\AnubisEdrDevice`)
  - Test-signing enabled or a valid kernel code-signing certificate

---
## Building

```bash
# 1. Clone the repository
git clone https://github.com//anubis-edr.git
cd anubis-edr
```

1. Open the `.sln` in Visual Studio
2. Build the **kernel driver** project (defines `ANUBIS_DRV`) — produces `AnubisEdr.sys`
3. Build the **user-mode agent** project — produces `AnubisAgent.exe`

> **Note:** Make sure YARA lib/headers and RapidJSON headers are in your include/library paths.

---

## Installation & Running

### Step 1 — Install the Kernel Driver

```cmd
:: Enable test signing (development only, requires reboot)
bcdedit /set testsigning on

:: Create and start the driver service
sc create AnubisEdr type= kernel binPath= "C:\path\to\AnubisEdr.sys"
sc start AnubisEdr
```
### Step 2 — Run the Agent

```cmd
:: Default config path (C:\ProgramData\Anubis\Config\anubis_config.ini)
AnubisAgent.exe

:: Custom config path
AnubisAgent.exe "D:\MyConfig\anubis_config.ini"
```

> **Important:** The kernel driver must be loaded before starting the agent. The agent communicates with the driver via `\\.\AnubisEdrDevice`.

---

## Configuration

The agent reads an **INI file**. Each service has its own `[Section]`. Configuration can be **hot-reloaded** at runtime with the `reload` CLI command.

## License

This project is provided for **educational and research purposes**.

## Demo
[![Watch Demo](https://img.shields.io/badge/▶_Watch_Demo-Streamable-blue?style=for-the-badge)](https://streamable.com/94yf24)
