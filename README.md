# Signal Hunter v3.0 — Timing Intelligence Engine

Port: 5302 | Stack: FastAPI + PostgreSQL 5433 + pgvector + LightRAG + GNN

## What It Does

Signal Hunter finds prospects who are mid-problem, mid-decision, mid-frustration — people whose buying window opens in 72 hours and nobody else knows it. It is a probabilistic timing intelligence engine, not a contact database.

Phase 0: Privacy-First Compliance Engine (data classification, audit log, erasure, APP 5, dark web TOS gating)
Phase 1: Core Engine (leads, radar dashboard, Momentum Score, storms, ELAINE integration, credits)

## Installation

```bash
cd /home/mani/signalhunter
pip install -r requirements.txt
```

## Configuration

```
DATABASE_URL=postgresql://amtl:amtl@localhost:5433/signalhunter
PORT=5302
```

## Usage

Access at http://amtl/signal/

### Key Endpoints
- `GET /health` — fleet health check
- `GET /signal/health` — subpath health
- `GET /signal/api/radar` — radar UI data (blips, storms)
- `GET /signal/api/today` — today's top 5 leads
- `GET /signal/api/leads` — all leads ranked by Momentum Score
- `GET /signal/api/leads/{id}` — full lead with signals, committee, timeline
- `POST /signal/api/leads/{id}/act` — mark lead as contacted
- `POST /signal/api/leads/{id}/pass` — archive lead
- `POST /signal/api/leads/{id}/outcome` — record won/lost
- `GET /signal/api/storms/active` — active Industry Storms
- `GET /signal/api/elaine/summary` — ELAINE morning briefing hook
- `GET /signal/api/privacy/audit` — signal audit log
- `POST /signal/api/privacy/forget` — right to erasure
- `GET /signal/api/privacy/report` — compliance report
- `GET /signal/api/credits/balance` — credit balance

## Health

```bash
curl http://localhost:5302/health
```

## Tests

```bash
cd /home/mani/signalhunter && python -m pytest beast_test.py -v
```

## Author

Mani Padisetti — Almost Magic Tech Lab
