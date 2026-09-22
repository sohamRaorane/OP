# JEV Sentinel — AI Coding Agent Guardian

> **AI proposes. Sentinel verifies. Policy decides.**

JEV Sentinel is a model-agnostic verification and governance layer between AI coding agents and software repositories. It combines deterministic validation (build, tests, static analysis, Git), security analysis, probabilistic JEV assessment, risk scoring, and policy-driven decisions.

```
USER → AI AGENT → Proposed Changes → JEV SENTINEL → ACCEPT / REVISE / BLOCK / HUMAN_REVIEW → Repository
```

## Core Principle

Deterministic evidence + Security findings + JEV evaluation + Risk + Policy = Final Decision

JEV is one signal, not the sole authority.

## Quick Start

```bash
# Install
pip install -e .

# Or with Docker
docker compose up -d

# Inspect a repository
jev-sentinel inspect --repo /path/to/repo

# Status
jev-sentinel status --repo /path/to/repo

# Diff
jev-sentinel diff --repo /path/to/repo

# Validate
jev-sentinel validate --repo /path/to/repo

# Full verification
jev-sentinel verify --repo /path/to/repo --task "Add logout endpoint"
```

## Architecture

```
sentinel/
  core/        — domain models, interfaces, exceptions, config
  repository/  — repo discovery & analysis
  git/         — Git operations, ChangeSet, checkpoint/rollback
  diff/        — diff parsing & classification
  validation/  — deterministic validation engine
  sandbox/     — Docker-secured execution
  security/    — security analyzers (9 categories)
  jev/         — JEV client (mock → real), evaluation
  risk/        — explainable risk assessment
  policy/      — YAML policy engine
  decision/    — deterministic decision engine
  agents/      — AgentAdapter (Generic/OpenCode first)
  approval/    — human approval workflow
  audit/       — immutable audit trail
  api/         — FastAPI REST API (/api/v1)
  cli/         — Typer CLI
```

## Operating Modes

- `gated` (default): block until ACCEPT
- `advisory`: analyze + report, never block
- `strict`: high/critical → human approval

## Requirements

- Python 3.12+
- PostgreSQL 15+ (or SQLite for dev)
- Docker Desktop (Windows/macOS/Linux) for sandboxed validation
- Git 2.30+

## Documentation

See `docs/` for threat model, API spec, and benchmark guide.

## License

MIT
