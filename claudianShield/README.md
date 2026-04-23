# ClawdianShield

> A hands-on detection engineering lab — built to demonstrate real-world threat visibility, telemetry collection, and evidence packaging as a portfolio artifact.

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

