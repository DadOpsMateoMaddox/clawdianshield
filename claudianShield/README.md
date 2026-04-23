# ClawdianShield

Detection engineering lab. Builds a full adversary emulation pipeline — telemetry collection, synthetic attack scenarios, detection scoring — as a working portfolio project, not a slide deck.

---

## The Point

Most security portfolios are certs and writeups. This is different. The goal here is to build something that actually runs: a black-box adversary emulation system that induces defender-relevant artifacts on a controlled lab, measures whether your detection stack caught them, and scores the gaps.

The scenarios don't use real exploit or credential attack logic. They're designed to produce the *signals* that defenders care about — auth anomalies, file tampering chains, cross-host traces, staging activity, persistence-path writes, anti-forensics signals — without depending on target internals or shipping anything operationally abusive. The point is detection coverage and telemetry quality, not malware cosplay.

---

## How It's Built

The dev workflow is called **RE Claw Code** — reverse engineering discipline applied to software development. Every component maps to a Linear issue. Every branch names the issue. Every commit references it. Nothing gets built without a tracked reason.

**Claude (Anthropic)** acts as AI pair programmer via Cursor for implementation, and as the red-team scenario generator via the API (wired in Phase 2 — `requirements.txt` has the stub). **GitHub Copilot** handles inline code review. Both are assistants. The engineering decisions are deliberate.

The project backlog was seeded programmatically via `scripts/linear-bootstrap.js`. The GitHub ↔ Linear sync is wired via `.github/workflows/linear-sync.yml` — PR merges close Linear issues automatically.

---

## Architecture

Four planes:

```
Control Plane       — load scenario JSON → validate safety constraints → build behavior plan
Execution Plane     — run synthetic behaviors (file tamper, auth, remote artifacts, staging, etc.)
Telemetry Plane     — collect, normalize, correlate events into JSONL
Evaluation Plane    — score expected vs observed, generate JSON report with coverage gaps
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
├── runner/          control plane + scoring + reporting
├── behaviors/       synthetic behavior modules (one class per behavior family)
├── collectors/      event normalization, file/process/auth collection, correlation
├── scenarios/       JSON scenario definitions
├── evidence/        JSONL event output (gitignored output, seeded artifacts)
├── reports/         run scorecards (gitignored output, .gitkeep holds the folder)
├── tests/           validation harness for collectors and behaviors
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

```powershell
# Run a single scenario
python -m runner.main scenarios/full_storyline.json

# Docker (single host)
cd docker
docker compose up

# Docker (multi-host with target node)
docker compose --profile multi-host up
```

Reports land in `reports/<run-id>.json`.

---

## Local Setup

```powershell
# Clone
git clone https://github.com/DadOpsMateoMaddox/clawdianshield.git
cd clawdianshield

# Python deps
pip install -r requirements.txt

# Node deps (Linear tooling only)
cd claudianShield
npm install

# Configure secrets
cp .env.example .env
# Edit .env — add LINEAR_API_KEY from linear.app/settings/api
# Add ANTHROPIC_API_KEY when Claude scenario gen is wired in (Phase 2)

# Seed Linear backlog (idempotent)
npm run bootstrap-linear
```

---

## Project Management

**Linear:** ClawdianShield project, team ClawCode_V-ClaudeCode  
**Branch naming:** `cls-<issue-id>/<short-description>`  
**Commits:** `CLS-<id>: <message>`  
**Milestones:** MVP Baseline → Telemetry → Detections → Scenarios → Evidence → Portfolio Packaging

---

## Status

Phase 1 in progress. Core runner, all 10 scenario definitions, and all behavior modules are built. Collectors are scaffolded. Phase 2 wires in the Claude API for automated scenario generation and adds the multi-host scheduler and correlation engine.


---

## What This Is and Why It Matters

Most security portfolios show certifications. ClawdianShield shows **working engineering**.

The goal is to build a complete detection pipeline from scratch — from raw host telemetry events, through detection rules, all the way to structured evidence output — and to do it with the same tooling and discipline used in production security engineering roles.

This isn't a CTF writeup or a course project. It's a lab environment designed to answer the question every hiring manager actually asks: *"Can you build the thing, not just talk about it?"*

**Core competencies demonstrated:**
- File Integrity Monitoring (FIM) — detecting tampering at the filesystem level
- Process and network telemetry collection
- Structured evidence output (JSONL) consumed by detection rules
- Reproducible attack scenarios against a seeded victim workstation
- Project tracking, sprint discipline, and engineering workflow via Linear

---

## How It Was Built

ClawdianShield is developed using a **RE Claw Code** workflow — a disciplined approach to building security tooling where reverse engineering principles (structured observation, evidence-first thinking, reproducible scenarios) are applied to the software development process itself.

The project uses **Claude (Anthropic)** as an AI pair programming partner via the Cursor editor, and **GitHub Copilot** for code review and inline suggestions. Rather than vibe-coding, every component is scoped to a Linear issue, branches follow a strict naming convention (`cls-<issue-id>/<description>`), and commits reference issue IDs (`CLS-42: add FIM collector`). The AI assists with implementation; the engineering decisions and security intent are deliberate and documented.

This workflow means:
- Nothing gets built without a tracked reason
- Every PR closes a Linear issue automatically (via GitHub Actions)
- The backlog was seeded programmatically via `scripts/linear-bootstrap.js` — even the project management is code

---

## Architecture

```
Host Events (FIM / Process / Network)
        │
        ▼
  collectors/          ← Python telemetry collectors
  (emit JSONL → evidence/)
        │
        ▼
  detections/          ← Detection rules applied to evidence
        │
        ▼
  evidence/            ← Structured JSONL output, screenshots
        │
        ▼
  scenarios/           ← Reproducible attack scenarios
  victim/              ← Seeded workstation artifacts
        │
        ▼
  tests/               ← Validation harness for all collectors
  docs/                ← Architecture + sequence diagrams (PlantUML)
```

Full PlantUML diagrams are in [`docs/architecture.puml`](docs/architecture.puml) and [`docs/sequence-bootstrap.puml`](docs/sequence-bootstrap.puml).

---

## Repository Structure

| Folder        | Purpose                                    | Linear Label | Milestone           |
| ------------- | ------------------------------------------ | ------------ | ------------------- |
| `collectors/` | FIM, process, network telemetry collectors | `telemetry`  | Telemetry           |
| `detections/` | Detection rules and evidence mapping       | `detections` | Detections          |
| `scenarios/`  | Attack scenario playbooks                  | `victim`     | Scenarios           |
| `victim/`     | Seeded developer workstation artifacts     | `victim`     | Scenarios           |
| `evidence/`   | JSONL event output and screenshots         | `utils`      | Evidence            |
| `utils/`      | Shared helpers (JSONL read/write, etc.)    | `utils`      | Evidence            |
| `tests/`      | Test harness for all collectors            | `tests`      | MVP Baseline        |
| `scripts/`    | Automation (Linear bootstrap, tooling)     | `automation` | MVP Baseline        |
| `docs/`       | Architecture and sequence diagrams         | `docs`       | Portfolio Packaging |
| `.github/`    | Issue templates, Linear sync workflow      | `automation` | MVP Baseline        |

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

Collectors planned:

| Module | Description | Status |
|---|---|---|
| `collectors/fim.py` | File integrity monitoring via stat snapshots | planned |
| `collectors/proc.py` | Process creation events | planned |
| `collectors/net.py` | Network connection events | planned |

---

## Project Management

**Linear project:** ClawdianShield  
**Team:** ClawCode_V-ClaudeCode  
**Milestones (in order):**

```
MVP Baseline → Telemetry → Detections → Scenarios → Evidence → Portfolio Packaging
```

The full backlog (17 issues) was created automatically via:

```powershell
cd claudianShield
npm run bootstrap-linear
```

GitHub PRs are linked to Linear issues automatically via `.github/workflows/linear-sync.yml`. When a PR is merged from a branch named `cls-<id>/...`, the corresponding Linear issue is closed.

**Branch naming:** `cls-<issue-id>/<short-description>`  
**Commit format:** `CLS-<id>: <message>`

---

## Local Setup

```powershell
# 1. Clone
git clone https://github.com/dadopsmateomaddox/clawdianShield.git
cd clawdianShield

# 2. Install Node dependencies (for Linear tooling)
npm install

# 3. Configure secrets — never commit real values
cp .env.example .env
# Edit .env and add your Linear API key

# 4. Seed Linear backlog (idempotent — skips existing issues)
npm run bootstrap-linear
```

**Get a Linear API key:** [linear.app/settings/api](https://linear.app/settings/api) → Personal API keys

---

## Security Notes

- `.env` is gitignored and cursorignored — never committed
- `.env.example` contains only placeholders — safe to commit
- All secrets are loaded via `dotenv` at runtime
- Rotate any key that has been visible in a terminal, chat, or log

---

## Status

Early build. MVP baseline in progress. Detection engineering is the primary deliverable.

