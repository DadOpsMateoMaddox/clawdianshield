# ClawdianShield

Detection engineering lab. Builds a full adversary emulation pipeline — telemetry collection, synthetic attack scenarios, detection scoring — as a working portfolio project, not a slide deck.

---

## The Point

Most security portfolios are certs and writeups. This is different. The goal here is to build something that actually runs: a black-box adversary emulation system that induces defender-relevant artifacts on a controlled lab, measures whether your detection stack caught them, and scores the gaps.

The scenarios don't use real exploit or credential attack logic (but can be programmed to do so in a controlled, air-gapped environment). This version is designed to produce the *signals* that defenders care about — auth anomalies, file tampering chains, cross-host traces, staging activity, persistence-path writes, anti-forensics signals — without depending on target internals or shipping anything operationally abusive. The point is detection coverage and telemetry quality, not malware cosplay.

---

## How It's Built

The dev workflow is called **RE Claw Code** — reverse engineering discipline applied to software development. Every component maps to a Linear issue. Every branch names the issue. Every commit references it. Nothing gets built without a tracked reason.

**Claude (Anthropic)** acts as AI pair programmer via the Claude Code CLI for implementation, and as the red-team scenario generator via the API (wired in Phase 2 — `anthropic` SDK is now an active dependency). **GitHub Copilot** handles inline code review. Both are assistants. The engineering decisions are deliberate.

The project backlog was seeded programmatically via `scripts/linear-bootstrap.js`. The GitHub ↔ Linear sync is wired via `.github/workflows/linear-sync.yml` — PR merges close Linear issues automatically.

---

## Architecture

Four planes:

```
Control Plane       — load scenario JSON → validate safety constraints → build behavior plan
Execution Plane     — translate behaviors → docker exec commands → run against claudian_victim
Telemetry Plane     — collect, normalize, correlate events into JSONL
Evaluation Plane    — score expected vs observed, generate JSON report with coverage gaps
```

The execution flow:

```
scenarios/<id>.json
        │
        ▼
runner/executor.py          ← subprocess engine (Phase 2)
  safety gate
  behavior → command map
  docker exec claudian_victim sh -c "<cmd>"
        │
        ▼
reports/<run_id>_exec_log.json   ← step trace + telemetry coverage gaps
```

Scenarios are JSON files describing what behaviors to run, what telemetry to expect, and what the success criteria are. The runner is deterministic and replayable. Docker wraps it so it runs cleanly anywhere.

Full diagram: [`docs/architecture.puml`](docs/architecture.puml)  
Bootstrap sequence: [`docs/sequence-bootstrap.puml`](docs/sequence-bootstrap.puml)

---

## Scenario Catalog

| ID | Name | Risk | Hosts |
|---|---|---|---|
| `fim_burst_001` | FIM Burst Tamper Storm | medium | 1 |
| `trusted_binary_blend_001` | Trusted Binary Tamper Blend | medium | 1 |
| `sensitive_config_drift_001` | Sensitive Config Drift | medium | 1 |
| `auth_abuse_001` | Synthetic Multi-Host Auth Abuse | high | 2 |
| `remote_exec_artifacts_001` | Remote Execution Artifact Chain | high | 2 |
| `collection_staging_001` | Collection and Staging Run | high | 1 |
| `persistence_path_mutation_001` | Persistence Path Mutation | critical | 1 |
| `anti_forensics_pressure_001` | Anti-Forensics Pressure Test | critical | 1 |
| `dependency_swap_001` | Dependency Swap / Supply Chain Emulation | critical | 1 |
| `full_storyline_001` | Full Synthetic Intrusion Storyline | high | 2 |

The full storyline chains auth burst → remote execution artifacts → enumeration/staging → persistence-path mutation → anti-forensics → cleanup. One run, seven stages, one scorecard.

---

## Repo Structure

```
claudianShield/
├── runner/          executor.py — deterministic subprocess scenario engine
├── collectors/      event normalization, file/process/auth collection, correlation
├── scenarios/       JSON scenario definitions (10 scenarios + test fixtures)
├── evidence/        JSONL event output (gitignored)
├── reports/         execution logs and run scorecards (gitignored, .gitkeep)
├── tests/           validation harness for collectors
├── utils/           shared helpers (JSONL read/write)
├── scripts/         Linear backlog bootstrap
├── docs/            PlantUML architecture and sequence diagrams
└── docker/          Dockerfile.runner + docker-compose.yml
```

---

## Scoring

Each run scores across five dimensions:

| Dimension | Weight | What it measures |
|---|---|---|
| Detection Coverage | 30% | Did the expected detections fire? |
| Telemetry Completeness | 25% | Were all required event classes observed? |
| Correlation Quality | 20% | Were cross-host and cross-stage events linked? |
| Timeliness | 15% | Was activity surfaced before cleanup? |
| Analyst Usefulness | 10% | Does the alert tell a coherent story? |

---

## Running It

```bash
# Dry-run (no Docker required — validates parsing, safety gate, and plan)
python runner/executor.py scenarios/fim_burst_tamper.json --dry-run

# Live run against the victim container
python runner/executor.py scenarios/fim_burst_tamper.json --container claudian_victim

# Full intrusion storyline
python runner/executor.py scenarios/full_storyline.json --container claudian_victim

# Docker (spin up runner + victim)
cd docker
docker compose up
```

Execution logs land in `reports/<run-id>_exec_log.json` with per-step traces, telemetry coverage, and gap analysis.

---

## Local Setup

```bash
# 1. Clone
git clone https://github.com/dadopsmateomaddox/clawdianShield.git
cd clawdianShield

# 2. Python deps
pip install -r requirements.txt

# 3. Node deps (Linear tooling only)
npm install

# 4. Configure secrets — never commit real values
cp .env.example .env
# Edit .env — add LINEAR_API_KEY and ANTHROPIC_API_KEY

# 5. Seed Linear backlog (idempotent — skips existing issues)
npm run bootstrap-linear
```

**Environment:** Docker Desktop 4.70+ with WSL2 backend. PowerShell 7+ recommended.

---

## Telemetry Schema

All collectors emit JSONL to `evidence/` in a consistent schema:

```json
{
  "ts": "2026-04-23T00:00:00Z",
  "collector": "fim",
  "host": "workstation-01",
  "event": {}
}
```

| Module | Description | Status |
|---|---|---|
| `collectors/fim.py` | File integrity monitoring via stat snapshots | scaffolded |
| `collectors/proc.py` | Process creation events | scaffolded |
| `collectors/net.py` | Network connection events | scaffolded |

---

## Project Management

**Linear:** ClawdianShield project, team ClawCode_V-ClaudeCode  
**Branch naming:** `cls-<issue-id>/<short-description>`  
**Commits:** `CLS-<id>: <message>`  
**Milestones:** MVP Baseline → Telemetry → Detections → Scenarios → Evidence → Portfolio Packaging

GitHub PRs are linked to Linear issues automatically via `.github/workflows/linear-sync.yml`. When a PR is merged from a branch named `cls-<id>/...`, the corresponding Linear issue is closed.

---

## Security Notes

- `.env` is gitignored and cursorignored — never committed
- `.env.example` contains only placeholders — safe to commit
- All secrets are loaded via `dotenv` at runtime
- Rotate any key that has been visible in a terminal, chat, or log

---

## Status

**Phase 1 — Complete.**  
Core scenario definitions (10), collector scaffolding, Docker environment, and project tooling are done.

**Phase 2 — Scenario Engine initiated.**  
`runner/executor.py` is live: deterministic subprocess engine that translates scenario `behavior_profile` keys into `docker exec` shell commands against the victim container, with per-step execution logging and telemetry coverage gap analysis. Safety gate enforces lab-only constraints before any execution. Dry-run mode validates scenarios without Docker.

**Phase 3 — Next.**  
Wire the `claudian_victim` service into `docker-compose.yml`, activate collectors to capture artifacts produced by the executor, and build the correlation + scoring pass against live telemetry.
