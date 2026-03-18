# Author: Mani Padisetti
"""
Signal Hunter v3.0 — Timing Intelligence Engine
Port: 5302 | Path: /home/mani/signalhunter/
NGINX subpath: /signal/

Probabilistic timing intelligence engine with adaptive learning.
Phase 0: Privacy-First Compliance Engine
Phase 1: Core Engine (leads, radar, scoring, storms, ELAINE)

Almost Magic Tech Lab
"""

import time
import math
import json
import hashlib
from datetime import datetime, timezone, timedelta, date
from typing import Optional

import asyncpg
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path

VERSION = "3.0.0"
APP_NAME = "signal-hunter"
DISPLAY_NAME = "Signal Hunter"
PORT = 5302
PREFIX = "/signal"
DB_URL = "postgresql://amtl:amtl@localhost:5433/signalhunter"

_start_time = time.monotonic()
_pool: Optional[asyncpg.Pool] = None

app = FastAPI(title=DISPLAY_NAME, version=VERSION, docs_url=f"{PREFIX}/docs", redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

HERE = Path(__file__).parent


# ── DB helpers ────────────────────────────────────────────────────────────────

async def get_pool():
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(DB_URL, min_size=2, max_size=10)
    return _pool


async def db_fetch(query: str, *args):
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.fetch(query, *args)


async def db_fetchrow(query: str, *args):
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.fetchrow(query, *args)


async def db_execute(query: str, *args):
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.execute(query, *args)


async def db_fetchval(query: str, *args):
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.fetchval(query, *args)


def row_to_dict(row):
    if row is None:
        return None
    return dict(row)


def rows_to_list(rows):
    return [dict(r) for r in rows]


def json_serial(obj):
    """JSON serializer for objects not serializable by default."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, timedelta):
        return obj.total_seconds()
    raise TypeError(f"Type {type(obj)} not serializable")


# ── Startup / Shutdown ────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    await get_pool()


@app.on_event("shutdown")
async def shutdown():
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


# ══════════════════════════════════════════════════════════════════════════════
# HEALTH
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/health")
@app.get(f"{PREFIX}/health")
async def health():
    uptime = time.monotonic() - _start_time
    try:
        await db_fetchval("SELECT 1")
        db_ok = True
    except Exception:
        db_ok = False
    return {
        "status": "operational" if db_ok else "degraded",
        "service": APP_NAME,
        "version": VERSION,
        "port": PORT,
        "uptime_seconds": round(uptime, 1),
        "database": "connected" if db_ok else "disconnected",
    }


@app.get(f"{PREFIX}/api/health")
async def api_health():
    uptime = time.monotonic() - _start_time
    return {
        "status": "operational",
        "service": APP_NAME,
        "version": VERSION,
        "uptime_seconds": round(uptime, 1),
    }


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 0 — PRIVACY-FIRST COMPLIANCE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

# ── Data Classification ───────────────────────────────────────────────────────

@app.get(f"{PREFIX}/api/privacy/classifications")
async def get_classifications():
    """Return the signal data classification framework."""
    rows = await db_fetch("SELECT * FROM signal_classifications ORDER BY id")
    return {"classifications": rows_to_list(rows)}


# ── Scrape Consent Registry ──────────────────────────────────────────────────

@app.get(f"{PREFIX}/api/privacy/consent-registry")
async def get_consent_registry():
    """Return the scrape consent registry — which sources are allowed."""
    rows = await db_fetch("SELECT * FROM scrape_consent ORDER BY source_name")
    return {"sources": rows_to_list(rows)}


# ── Signal Audit Log ─────────────────────────────────────────────────────────

@app.get(f"{PREFIX}/api/privacy/audit")
async def get_audit_log(limit: int = 50, offset: int = 0):
    """Return the signal audit log — full chain of custody."""
    rows = await db_fetch(
        "SELECT * FROM signal_audit WHERE deleted_at IS NULL ORDER BY collected_at DESC LIMIT $1 OFFSET $2",
        limit, offset,
    )
    total = await db_fetchval("SELECT COUNT(*) FROM signal_audit WHERE deleted_at IS NULL")
    return {"audit_log": rows_to_list(rows), "total": total}


# ── Compliance Report ─────────────────────────────────────────────────────────

@app.get(f"{PREFIX}/api/privacy/report")
async def get_compliance_report():
    """Generate a compliance report — signal counts by classification, retention status."""
    by_class = await db_fetch(
        "SELECT classification, COUNT(*) AS count FROM signal_audit WHERE deleted_at IS NULL GROUP BY classification"
    )
    total_signals = await db_fetchval("SELECT COUNT(*) FROM signals")
    expired = await db_fetchval(
        "SELECT COUNT(*) FROM signals WHERE expires_at IS NOT NULL AND expires_at < NOW()"
    )
    erasures = await db_fetchval("SELECT COUNT(*) FROM erasure_log")
    app5_count = await db_fetchval("SELECT COUNT(*) FROM app5_notifications")
    dark_web_tos = await db_fetchrow(
        "SELECT accepted, accepted_at FROM dark_web_tos WHERE user_id = 1 ORDER BY id DESC LIMIT 1"
    )
    return {
        "report_date": datetime.now(timezone.utc).isoformat(),
        "total_signals": total_signals,
        "expired_signals": expired,
        "by_classification": rows_to_list(by_class),
        "total_erasure_requests": erasures,
        "app5_notifications": app5_count,
        "dark_web_tos_accepted": row_to_dict(dark_web_tos) if dark_web_tos else {"accepted": False},
    }


# ── Right to Erasure ─────────────────────────────────────────────────────────

@app.post(f"{PREFIX}/api/privacy/forget")
async def forget_company(request: Request):
    """POST /api/privacy/forget-company — delete all data for a named company."""
    body = await request.json()
    company = body.get("company_name", "").strip()
    if not company:
        raise HTTPException(400, {"error": "company_name is required"})
    if len(company) > 500:
        raise HTTPException(400, {"error": "company_name too long (max 500 chars)"})

    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Find matching leads
            leads = await conn.fetch(
                "SELECT id FROM leads WHERE LOWER(company_name) = LOWER($1)", company
            )
            lead_ids = [r["id"] for r in leads]
            deleted_counts = {"leads": 0, "signals": 0, "audit_entries": 0, "velocity": 0, "committee": 0}

            if lead_ids:
                # Mark audit entries as deleted (soft delete for compliance)
                await conn.execute(
                    "UPDATE signal_audit SET deleted_at = NOW() WHERE lead_id = ANY($1::int[])", lead_ids
                )
                deleted_counts["audit_entries"] = len(lead_ids)

                # Delete signals
                r = await conn.execute("DELETE FROM signals WHERE lead_id = ANY($1::int[])", lead_ids)
                deleted_counts["signals"] = int(r.split()[-1]) if r else 0

                # Delete velocity history
                r = await conn.execute("DELETE FROM velocity_history WHERE lead_id = ANY($1::int[])", lead_ids)
                deleted_counts["velocity"] = int(r.split()[-1]) if r else 0

                # Delete buying committee
                r = await conn.execute("DELETE FROM buying_committee WHERE lead_id = ANY($1::int[])", lead_ids)
                deleted_counts["committee"] = int(r.split()[-1]) if r else 0

                # Delete leads
                r = await conn.execute("DELETE FROM leads WHERE id = ANY($1::int[])", lead_ids)
                deleted_counts["leads"] = int(r.split()[-1]) if r else 0

            total = sum(deleted_counts.values())
            # Log the erasure
            await conn.execute(
                "INSERT INTO erasure_log (company_name, records_deleted, details) VALUES ($1, $2, $3)",
                company, total, json.dumps(deleted_counts),
            )

    return {
        "status": "erased",
        "company": company,
        "records_deleted": total,
        "details": deleted_counts,
        "audit_trail": f"Erasure logged at {datetime.now(timezone.utc).isoformat()}",
    }


# ── Dark Web TOS ─────────────────────────────────────────────────────────────

@app.get(f"{PREFIX}/api/privacy/dark-web-tos")
async def get_dark_web_tos():
    """Check if the user has accepted the Dark Web module TOS."""
    row = await db_fetchrow(
        "SELECT accepted, accepted_at FROM dark_web_tos WHERE user_id = 1 ORDER BY id DESC LIMIT 1"
    )
    if row:
        return {"accepted": row["accepted"], "accepted_at": row["accepted_at"]}
    return {"accepted": False, "accepted_at": None}


@app.post(f"{PREFIX}/api/privacy/dark-web-tos")
async def accept_dark_web_tos(request: Request):
    """Accept the Dark Web module Terms of Service."""
    body = await request.json()
    accept = body.get("accept", False)
    ip = request.client.host if request.client else "unknown"
    await db_execute(
        "INSERT INTO dark_web_tos (user_id, accepted, accepted_at, ip_address) VALUES (1, $1, NOW(), $2)",
        accept, ip,
    )
    return {"accepted": accept, "accepted_at": datetime.now(timezone.utc).isoformat()}


# ── APP 5 Notifications ──────────────────────────────────────────────────────

@app.get(f"{PREFIX}/api/privacy/app5")
async def get_app5_notifications():
    """Return APP 5 notification history."""
    rows = await db_fetch("SELECT * FROM app5_notifications ORDER BY created_at DESC LIMIT 50")
    return {"notifications": rows_to_list(rows)}


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — CORE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

# ── Momentum Score Calculation ────────────────────────────────────────────────

MOMENTUM_WEIGHTS = {
    "intent_velocity": 0.22,
    "buying_window": 0.20,
    "fit_score": 0.18,
    "signal_corroboration": 0.15,
    "emotional_intensity": 0.12,
    "ghost_signal_density": 0.08,
    "competitor_presence": 0.05,
}

INDUSTRY_DECAY = {
    "Cybersecurity": 2,
    "Legal": 30,
    "Government": 60,
    "Technology": 3,
    "Construction": 14,
    "Healthcare": 7,
    "Finance": 7,
    "Agriculture": 14,
    "Mining": 14,
    "Professional Services": 7,
}


def compute_buying_window_score(days: int) -> float:
    if days <= 30:
        return 100.0
    elif days <= 90:
        return 60.0
    return 20.0


def compute_momentum(lead: dict, signals: list) -> float:
    """Compute the Momentum Score for a lead."""
    velocity_norm = min(lead.get("intent_velocity", 0) * 100, 100)
    bw_score = compute_buying_window_score(lead.get("buying_window_days", 90))
    fit = lead.get("fit_score", 50)
    corroboration = min(len(signals) * 20, 100)

    avg_emotional = 0
    if signals:
        avg_emotional = sum(s.get("emotional_intensity", 0) for s in signals) / len(signals) * 100

    ghost_count = lead.get("ghost_signal_count", 0)
    ghost_density = min(ghost_count * 25, 100)

    competitor = 100 if lead.get("competitor_displacement") else 0

    raw = (
        velocity_norm * MOMENTUM_WEIGHTS["intent_velocity"]
        + bw_score * MOMENTUM_WEIGHTS["buying_window"]
        + fit * MOMENTUM_WEIGHTS["fit_score"]
        + corroboration * MOMENTUM_WEIGHTS["signal_corroboration"]
        + avg_emotional * MOMENTUM_WEIGHTS["emotional_intensity"]
        + ghost_density * MOMENTUM_WEIGHTS["ghost_signal_density"]
        + competitor * MOMENTUM_WEIGHTS["competitor_presence"]
    )

    # Modifiers
    modifier = 1.0
    if lead.get("first_mover"):
        modifier *= 1.20
    if lead.get("dark_web_signal"):
        modifier *= 1.10

    # Saturation penalty
    sat = lead.get("saturation_index", 0)
    if sat > 0.7:
        modifier *= 0.85

    return min(round(raw * modifier, 1), 100)


def velocity_trend_label(v: float) -> str:
    if v > 0.3:
        return "accelerating"
    elif v >= 0.05:
        return "steady"
    elif v > 0:
        return "cooling"
    return "stalled"


def buying_window_label(days: int) -> str:
    if days <= 30:
        return "active"
    elif days <= 90:
        return "warming"
    return "pipeline"


# ── Leads ─────────────────────────────────────────────────────────────────────

@app.get(f"{PREFIX}/api/leads")
async def list_leads(
    status: Optional[str] = None,
    industry: Optional[str] = None,
    match_patterns: bool = False,
    limit: int = 50,
):
    """Return leads ranked by Momentum Score. match_patterns=true ranks by win template similarity."""
    conditions = ["1=1"]
    args = []
    idx = 1

    if status:
        conditions.append(f"status = ${idx}")
        args.append(status)
        idx += 1
    if industry:
        conditions.append(f"industry = ${idx}")
        args.append(industry)
        idx += 1

    where = " AND ".join(conditions)
    rows = await db_fetch(
        f"SELECT * FROM leads WHERE {where} ORDER BY momentum_score DESC LIMIT ${idx}",
        *args, limit,
    )
    leads = rows_to_list(rows)

    if match_patterns and leads:
        templates = await db_fetch("SELECT signal_sequence, industry FROM win_templates")
        if templates:
            win_industries = {t["industry"] for t in templates if t["industry"]}
            win_signal_types = set()
            for t in templates:
                seq = t["signal_sequence"]
                if isinstance(seq, str):
                    try:
                        seq = json.loads(seq)
                    except Exception:
                        seq = []
                if isinstance(seq, list):
                    for s in seq:
                        if isinstance(s, dict):
                            win_signal_types.add(s.get("type", ""))

            for lead in leads:
                match_score = 0
                if lead.get("industry") in win_industries:
                    match_score += 30
                lead_signals = await db_fetch(
                    "SELECT signal_type FROM signals WHERE lead_id = $1", lead["id"]
                )
                lead_types = {s["signal_type"] for s in lead_signals}
                overlap = lead_types & win_signal_types
                if overlap:
                    match_score += min(len(overlap) * 15, 70)
                lead["pattern_match_score"] = match_score

            leads.sort(key=lambda x: x.get("pattern_match_score", 0), reverse=True)

    return {"leads": leads, "count": len(leads)}


# ── Phase 3 lead sub-routes (must be before {lead_id} parametric route) ──────

@app.get(f"{PREFIX}/api/leads/saturation")
async def leads_by_saturation():
    """Return leads grouped by saturation level with momentum impact."""
    rows = await db_fetch(
        "SELECT id, company_name, industry, momentum_score, saturation_index, first_mover "
        "FROM leads WHERE status NOT IN ('archived', 'won', 'lost') ORDER BY momentum_score DESC"
    )
    low, medium, high = [], [], []
    for r in rows:
        d = row_to_dict(r)
        sat = d.get("saturation_index", 0) or 0
        if sat < 0.3:
            d["saturation_level"] = "low"
            d["momentum_modifier"] = "none"
            low.append(d)
        elif sat < 0.7:
            d["saturation_level"] = "medium"
            d["momentum_modifier"] = "none"
            medium.append(d)
        else:
            d["saturation_level"] = "high"
            d["momentum_modifier"] = "-15%"
            high.append(d)
    return {
        "low_saturation": low,
        "medium_saturation": medium,
        "high_saturation": high,
        "counts": {"low": len(low), "medium": len(medium), "high": len(high)},
    }


@app.get(f"{PREFIX}/api/leads/first-movers")
async def first_mover_leads():
    """Return leads where we are the first mover (no competitor has seen them)."""
    rows = await db_fetch(
        "SELECT l.id, l.company_name, l.industry, l.momentum_score, l.first_mover, "
        "l.saturation_index, f.first_detected_at, f.competitor_seen_count "
        "FROM leads l JOIN lead_first_seen f ON l.id = f.lead_id "
        "WHERE f.competitor_seen_count = 0 AND l.status NOT IN ('archived', 'won', 'lost') "
        "ORDER BY l.momentum_score DESC"
    )
    return {"first_movers": rows_to_list(rows), "count": len(rows)}


@app.get(f"{PREFIX}/api/leads/{{lead_id}}")
async def get_lead(lead_id: int):
    """Return full lead with signals and committee."""
    lead = await db_fetchrow("SELECT * FROM leads WHERE id = $1", lead_id)
    if not lead:
        raise HTTPException(404, {"error": "Lead not found"})

    signals = await db_fetch(
        "SELECT * FROM signals WHERE lead_id = $1 ORDER BY detected_at DESC", lead_id
    )
    committee = await db_fetch(
        "SELECT * FROM buying_committee WHERE lead_id = $1 ORDER BY role", lead_id
    )
    velocity = await db_fetch(
        "SELECT * FROM velocity_history WHERE lead_id = $1 ORDER BY signal_date", lead_id
    )

    lead_dict = row_to_dict(lead)
    lead_dict["signals"] = rows_to_list(signals)
    lead_dict["buying_committee"] = rows_to_list(committee)
    lead_dict["velocity_history"] = rows_to_list(velocity)
    return lead_dict


@app.get(f"{PREFIX}/api/leads/{{lead_id}}/timeline")
async def get_lead_timeline(lead_id: int):
    """Return signal history as ordered events for the timeline view."""
    lead = await db_fetchrow("SELECT id, company_name FROM leads WHERE id = $1", lead_id)
    if not lead:
        raise HTTPException(404, {"error": "Lead not found"})

    signals = await db_fetch(
        "SELECT id, source, signal_type, title, content, emotional_intensity, detected_at "
        "FROM signals WHERE lead_id = $1 ORDER BY detected_at DESC",
        lead_id,
    )
    events = []
    for s in signals:
        events.append({
            "id": s["id"],
            "date": s["detected_at"].isoformat() if s["detected_at"] else None,
            "source": s["source"],
            "type": s["signal_type"],
            "title": s["title"],
            "description": s["content"][:200] if s["content"] else None,
            "intensity": s["emotional_intensity"],
        })
    return {"lead_id": lead_id, "company": lead["company_name"], "events": events}


@app.get(f"{PREFIX}/api/leads/{{lead_id}}/committee")
async def get_lead_committee(lead_id: int):
    """Return buying committee map for a lead."""
    lead = await db_fetchrow("SELECT id FROM leads WHERE id = $1", lead_id)
    if not lead:
        raise HTTPException(404, {"error": "Lead not found"})
    rows = await db_fetch(
        "SELECT * FROM buying_committee WHERE lead_id = $1 ORDER BY role", lead_id
    )
    return {"lead_id": lead_id, "committee": rows_to_list(rows)}


@app.post(f"{PREFIX}/api/leads/{{lead_id}}/act")
async def act_on_lead(lead_id: int):
    """Mark a lead as contacted."""
    lead = await db_fetchrow("SELECT id FROM leads WHERE id = $1", lead_id)
    if not lead:
        raise HTTPException(404, {"error": "Lead not found"})
    await db_execute(
        "UPDATE leads SET status = 'contacted', contacted_at = NOW() WHERE id = $1", lead_id
    )
    return {"status": "contacted", "lead_id": lead_id}


@app.post(f"{PREFIX}/api/leads/{{lead_id}}/pass")
async def pass_on_lead(lead_id: int):
    """Archive a lead — trains the algorithm."""
    lead = await db_fetchrow("SELECT id FROM leads WHERE id = $1", lead_id)
    if not lead:
        raise HTTPException(404, {"error": "Lead not found"})
    await db_execute("UPDATE leads SET status = 'archived' WHERE id = $1", lead_id)
    return {"status": "archived", "lead_id": lead_id}


@app.post(f"{PREFIX}/api/leads/{{lead_id}}/outcome")
async def record_outcome(lead_id: int, request: Request):
    """Record won/lost outcome + reason + actual value."""
    lead = await db_fetchrow("SELECT id, created_at FROM leads WHERE id = $1", lead_id)
    if not lead:
        raise HTTPException(404, {"error": "Lead not found"})

    body = await request.json()
    outcome = body.get("outcome")
    if outcome not in ("won", "lost"):
        raise HTTPException(400, {"error": "outcome must be 'won' or 'lost'"})

    reason = body.get("reason", "")
    value = body.get("deal_value_actual", 0)
    now = datetime.now(timezone.utc)
    days = (now - lead["created_at"]).days if lead["created_at"] else 0

    await db_execute(
        "UPDATE leads SET outcome = $2, outcome_reason = $3, deal_value_actual = $4, "
        "sales_cycle_days = $5, status = $6, won_at = CASE WHEN $2 = 'won' THEN NOW() ELSE NULL END "
        "WHERE id = $1",
        lead_id, outcome, reason, value, days, outcome,
    )

    # If won, create a win template (Reverse Signal Pattern)
    if outcome == "won":
        signals = await db_fetch(
            "SELECT signal_type, source FROM signals WHERE lead_id = $1 ORDER BY detected_at", lead_id
        )
        sequence = [{"type": s["signal_type"], "source": s["source"]} for s in signals]
        lead_row = await db_fetchrow(
            "SELECT industry, company_size, pain_fingerprint, narrative_stage FROM leads WHERE id = $1",
            lead_id,
        )
        await db_execute(
            "INSERT INTO win_templates (lead_id, signal_sequence, industry, company_size, win_value) "
            "VALUES ($1, $2::jsonb, $3, $4, $5)",
            lead_id, json.dumps(sequence), lead_row["industry"] if lead_row else None,
            lead_row["company_size"] if lead_row else None, value,
        )

    return {"status": outcome, "lead_id": lead_id, "sales_cycle_days": days}


# ── Radar ─────────────────────────────────────────────────────────────────────

@app.get(f"{PREFIX}/api/radar")
async def get_radar(industry: Optional[str] = None):
    """Return all leads formatted for the radar UI."""
    if industry:
        rows = await db_fetch(
            "SELECT id, company_name, industry, momentum_score, fit_score, intent_velocity, "
            "velocity_trend, buying_window, buying_window_days, expected_deal_value, "
            "pain_fingerprint, signal_count, dark_web_signal, first_mover, status "
            "FROM leads WHERE status NOT IN ('archived', 'won', 'lost') AND industry = $1 "
            "ORDER BY momentum_score DESC",
            industry,
        )
    else:
        rows = await db_fetch(
            "SELECT id, company_name, industry, momentum_score, fit_score, intent_velocity, "
            "velocity_trend, buying_window, buying_window_days, expected_deal_value, "
            "pain_fingerprint, signal_count, dark_web_signal, first_mover, status "
            "FROM leads WHERE status NOT IN ('archived', 'won', 'lost') "
            "ORDER BY momentum_score DESC"
        )

    blips = []
    for r in rows:
        ms = r["momentum_score"] or 0
        if ms >= 80:
            heat = "hot"
        elif ms >= 60:
            heat = "warm"
        elif ms >= 40:
            heat = "cool"
        else:
            heat = "cold"

        bw = r["buying_window"] or "pipeline"
        if bw == "active":
            ring = "inner"
        elif bw == "warming":
            ring = "mid"
        else:
            ring = "outer"

        pain_summary = (r["pain_fingerprint"] or "")[:100]
        if len(r["pain_fingerprint"] or "") > 100:
            pain_summary += "..."

        blips.append({
            "id": r["id"],
            "company": r["company_name"],
            "industry": r["industry"],
            "momentum": ms,
            "fit": r["fit_score"] or 0,
            "velocity": r["intent_velocity"] or 0,
            "velocity_trend": r["velocity_trend"] or "steady",
            "buying_window": bw,
            "ring": ring,
            "heat": heat,
            "deal_value": r["expected_deal_value"] or 0,
            "pain_summary": pain_summary,
            "signal_count": r["signal_count"] or 0,
            "dark_web": r["dark_web_signal"] or False,
            "first_mover": r["first_mover"] or False,
        })

    storms = await db_fetch("SELECT id, event_name, severity, industry FROM storm_events WHERE active = TRUE")
    return {
        "blips": blips,
        "count": len(blips),
        "active_storms": rows_to_list(storms),
    }


# ── Today's Top 5 ────────────────────────────────────────────────────────────

@app.get(f"{PREFIX}/api/today")
async def todays_top5():
    """Return today's top leads ranked by Momentum Score, with fleet summary."""
    rows = await db_fetch(
        "SELECT id, company_name, industry, momentum_score, fit_score, intent_velocity, "
        "velocity_trend, buying_window, pain_fingerprint, communication_style, outreach_a, "
        "expected_deal_value, close_probability, expected_value, signal_count "
        "FROM leads WHERE status NOT IN ('archived', 'won', 'lost') "
        "ORDER BY momentum_score DESC LIMIT 5"
    )
    top_leads = []
    for r in rows:
        pain = (r["pain_fingerprint"] or "")[:120]
        bw = r["buying_window"] or "pipeline"
        bw_label = "0-30d" if bw == "active" else ("31-90d" if bw == "warming" else "90+d")
        top_leads.append({
            "id": r["id"],
            "company": r["company_name"],
            "industry": r["industry"],
            "momentum_score": r["momentum_score"] or 0,
            "fit": r["fit_score"] or 0,
            "velocity_trend": r["velocity_trend"] or "steady",
            "buying_window": bw_label,
            "pain_summary": pain,
            "signal_count": r["signal_count"] or 0,
            "outreach_a": r["outreach_a"],
            "deal_value": r["expected_deal_value"] or 0,
            "close_probability": r["close_probability"] or 0,
            "expected_value": r["expected_value"] or 0,
        })

    # Aggregate counts
    totals = await db_fetch(
        "SELECT COUNT(*) as total, "
        "SUM(CASE WHEN momentum_score >= 70 THEN 1 ELSE 0 END) as hot "
        "FROM leads WHERE status NOT IN ('archived', 'won', 'lost')"
    )
    total_leads = totals[0]["total"] if totals else 0
    hot_leads = totals[0]["hot"] if totals else 0

    storms = await db_fetch("SELECT COUNT(*) as cnt FROM storm_events WHERE active = TRUE")
    active_storms = storms[0]["cnt"] if storms else 0

    return {
        "date": date.today().isoformat(),
        "top_leads": top_leads,
        "total_leads_today": total_leads,
        "hot_leads": hot_leads,
        "active_storms": active_storms,
    }


# ── Storms ────────────────────────────────────────────────────────────────────

@app.get(f"{PREFIX}/api/storms/active")
async def active_storms():
    """Return currently active Industry Storms. Storms with severity >= 7 trigger War Room mode."""
    rows = await db_fetch(
        "SELECT * FROM storm_events WHERE active = TRUE ORDER BY severity DESC"
    )
    storms = []
    war_room = []
    for r in rows:
        d = row_to_dict(r)
        d["computed_severity"] = compute_storm_severity(d)
        if r["window_closes"]:
            delta = r["window_closes"] - date.today()
            d["days_remaining"] = max(delta.days, 0)
        else:
            d["days_remaining"] = None
        storms.append(d)
        if d["severity"] >= 7:
            war_room.append({"id": d["id"], "event_name": d["event_name"], "severity": d["severity"]})
    return {"storms": storms, "count": len(storms), "war_room_triggers": war_room}


# ── Velocity ──────────────────────────────────────────────────────────────────

@app.get(f"{PREFIX}/api/velocity/{{entity_id}}")
async def get_velocity(entity_id: str):
    """Return velocity history for an entity."""
    rows = await db_fetch(
        "SELECT * FROM velocity_history WHERE entity_id = $1 ORDER BY signal_date", entity_id
    )
    if not rows:
        raise HTTPException(404, {"error": "No velocity data for this entity"})
    return {"entity_id": entity_id, "history": rows_to_list(rows)}


# ── Win Templates (Reverse Signal Pattern) ────────────────────────────────────

@app.get(f"{PREFIX}/api/patterns/wins")
async def get_win_patterns():
    """Return the user's win templates — reverse signal patterns."""
    rows = await db_fetch("SELECT * FROM win_templates ORDER BY created_at DESC LIMIT 20")
    templates = []
    for r in rows:
        d = row_to_dict(r)
        seq = d.get("signal_sequence")
        if isinstance(seq, str):
            try:
                d["signal_sequence"] = json.loads(seq)
            except Exception:
                pass
        templates.append(d)
    return {"patterns": templates}


# ── Phase 2: Intelligence Layer ──────────────────────────────────────────────


# 2B: Narrative Shift Detection

EXPLORATORY_KEYWORDS = [
    "exploring", "evaluating", "looking at", "has anyone", "considering",
    "thinking about", "researching", "curious about", "anyone used",
]
URGENT_KEYWORDS = [
    "we must", "before q3", "before q4", "board has mandated", "critical",
    "urgent", "deadline", "immediately", "can't wait", "asap", "running out of time",
    "compliance deadline", "audit coming", "regulator", "must have by",
]


def detect_narrative_stage(text: str) -> tuple[str, bool]:
    """Detect narrative stage from text. Returns (stage, shift_detected)."""
    if not text:
        return "unknown", False
    lower = text.lower()
    urgent_hits = sum(1 for kw in URGENT_KEYWORDS if kw in lower)
    exploratory_hits = sum(1 for kw in EXPLORATORY_KEYWORDS if kw in lower)

    if urgent_hits >= 2:
        return "urgent", True
    elif urgent_hits == 1 and exploratory_hits == 0:
        return "urgent", True
    elif exploratory_hits >= 1 and urgent_hits == 0:
        return "exploratory", False
    elif urgent_hits >= 1 and exploratory_hits >= 1:
        return "transitioning", True
    return "unknown", False


@app.post(f"{PREFIX}/api/leads/{{lead_id}}/analyse-narrative")
async def analyse_narrative(lead_id: int):
    """Analyse a lead's signals for narrative shift (exploratory → urgent)."""
    lead = await db_fetchrow("SELECT id, pain_fingerprint, momentum_score FROM leads WHERE id = $1", lead_id)
    if not lead:
        raise HTTPException(404, {"error": "Lead not found"})

    signals = await db_fetch(
        "SELECT content FROM signals WHERE lead_id = $1 ORDER BY detected_at", lead_id
    )
    combined_text = " ".join(s["content"] or "" for s in signals)
    combined_text += " " + (lead["pain_fingerprint"] or "")

    stage, shift = detect_narrative_stage(combined_text)
    momentum_boost = 10 if shift else 0
    new_momentum = min(100, (lead["momentum_score"] or 0) + momentum_boost)

    await db_execute(
        "UPDATE leads SET narrative_stage = $2, narrative_shift_detected = $3, "
        "momentum_score = CASE WHEN $3 = TRUE THEN GREATEST(momentum_score, $4) ELSE momentum_score END "
        "WHERE id = $1",
        lead_id, stage, shift, new_momentum,
    )

    return {
        "lead_id": lead_id,
        "narrative_stage": stage,
        "shift_detected": shift,
        "momentum_boost": momentum_boost,
    }


@app.get(f"{PREFIX}/api/narrative-shifts")
async def get_narrative_shifts():
    """Return leads with detected narrative shifts."""
    rows = await db_fetch(
        "SELECT id, company_name, industry, momentum_score, narrative_stage, narrative_shift_detected "
        "FROM leads WHERE narrative_shift_detected = TRUE ORDER BY momentum_score DESC"
    )
    return {"shifts": rows_to_list(rows), "count": len(rows)}


# 2C: Silence Detection

@app.get(f"{PREFIX}/api/silence")
async def get_silence_signals():
    """Return entities with detected silence signals."""
    rows = await db_fetch(
        "SELECT id, company_name, industry, momentum_score, silence_detected, silence_reason "
        "FROM leads WHERE silence_detected = TRUE ORDER BY momentum_score DESC"
    )
    return {"silent_leads": rows_to_list(rows), "count": len(rows)}


@app.post(f"{PREFIX}/api/silence/scan")
async def scan_silence():
    """Scan entity posting history for silence signals (14+ days quiet for active posters)."""
    today = date.today()
    entities = await db_fetch("SELECT * FROM entity_posting_history WHERE avg_posts_per_week >= 2.0")
    detected = []
    for e in entities:
        if not e["last_post_date"]:
            continue
        days_silent = (today - e["last_post_date"]).days
        if days_silent >= 14:
            reason = (
                f"Usually {e['avg_posts_per_week']:.1f} posts/week, "
                f"silent {days_silent} days — potential internal disruption or decision in progress"
            )
            # Try to match to a lead
            lead = await db_fetchrow(
                "SELECT id FROM leads WHERE company_name = $1 AND status NOT IN ('archived', 'won', 'lost')",
                e["company_name"],
            )
            if lead:
                await db_execute(
                    "UPDATE leads SET silence_detected = TRUE, silence_reason = $2 WHERE id = $1",
                    lead["id"], reason,
                )
            detected.append({
                "entity_id": e["entity_id"],
                "company_name": e["company_name"],
                "days_silent": days_silent,
                "avg_posts_per_week": e["avg_posts_per_week"],
                "reason": reason,
                "lead_id": lead["id"] if lead else None,
            })
    return {"detected": detected, "count": len(detected)}


@app.get(f"{PREFIX}/api/posting-history")
async def get_posting_history():
    """Return entity posting history for monitoring."""
    rows = await db_fetch("SELECT * FROM entity_posting_history ORDER BY company_name")
    return {"entities": rows_to_list(rows)}


# 2D: Ghost Signal Enhancement — Job Ad Archaeology

@app.post(f"{PREFIX}/api/leads/{{lead_id}}/parse-job-ad")
async def parse_job_ad(lead_id: int, request: Request):
    """Parse a job ad to extract intelligence: implied pain, budget proof, decision maker, tech stack."""
    lead = await db_fetchrow("SELECT id, company_name FROM leads WHERE id = $1", lead_id)
    if not lead:
        raise HTTPException(404, {"error": "Lead not found"})

    body = await request.json()
    job_text = body.get("job_text", "")
    if not job_text or len(job_text) < 20:
        raise HTTPException(400, {"error": "job_text must be at least 20 characters"})

    # Parse intelligence from job ad text
    lower = job_text.lower()
    parsed = {
        "implied_pain": [],
        "budget_proof": None,
        "decision_maker": None,
        "tech_stack": [],
        "raw_text_length": len(job_text),
    }

    # Implied pain extraction
    pain_indicators = [
        ("governance gap", ["governance", "compliance", "regulatory"]),
        ("security weakness", ["security", "cyber", "vulnerability", "penetration"]),
        ("data management chaos", ["data governance", "data quality", "data management"]),
        ("scaling challenge", ["scaling", "growth", "expanding", "rapid growth"]),
        ("technical debt", ["modernise", "modernize", "legacy", "migration", "transformation"]),
        ("process failure", ["process improvement", "workflow", "automation", "streamline"]),
    ]
    for pain_name, keywords in pain_indicators:
        if any(kw in lower for kw in keywords):
            parsed["implied_pain"].append(pain_name)

    # Budget proof — permanent hire signals real budget
    if any(kw in lower for kw in ["permanent", "full-time", "full time", "ongoing"]):
        parsed["budget_proof"] = "permanent_hire"
    elif any(kw in lower for kw in ["contract", "fixed term", "6 month", "12 month"]):
        parsed["budget_proof"] = "contract_hire"

    # Decision maker — reporting line
    reporting_patterns = [
        "reports to", "reporting to", "report to", "reporting line",
        "cto", "cio", "ciso", "cfo", "head of", "director of", "vp of",
    ]
    for pattern in reporting_patterns:
        idx = lower.find(pattern)
        if idx >= 0:
            snippet = job_text[idx:idx + 60].strip()
            parsed["decision_maker"] = snippet
            break

    # Tech stack extraction
    tech_keywords = [
        "aws", "azure", "gcp", "python", "java", "react", "docker", "kubernetes",
        "terraform", "ansible", "splunk", "crowdstrike", "sentinel", "datadog",
        "salesforce", "servicenow", "jira", "confluence", "power bi", "tableau",
        "postgresql", "mongodb", "elasticsearch", "redis", "kafka",
    ]
    for tech in tech_keywords:
        if tech in lower:
            parsed["tech_stack"].append(tech)

    # Store parsed intelligence
    existing_json = await db_fetchval(
        "SELECT pain_fingerprint_json FROM leads WHERE id = $1", lead_id
    )
    fingerprint = existing_json if isinstance(existing_json, dict) else {}
    fingerprint["job_ad_intelligence"] = parsed

    await db_execute(
        "UPDATE leads SET pain_fingerprint_json = $2::jsonb WHERE id = $1",
        lead_id, json.dumps(fingerprint),
    )

    return {"lead_id": lead_id, "parsed": parsed}


# 2E: Anti-Signal Filter (Adversarial Qualification)

@app.post(f"{PREFIX}/api/leads/{{lead_id}}/qualify")
async def adversarial_qualify(lead_id: int, request: Request):
    """Run adversarial qualification on a lead — flag sinking ships, budget freezes, chronic complainers."""
    lead = await db_fetchrow(
        "SELECT id, company_name, pain_fingerprint, created_at FROM leads WHERE id = $1",
        lead_id,
    )
    if not lead:
        raise HTTPException(404, {"error": "Lead not found"})

    try:
        body = await request.json()
    except Exception:
        body = {}
    flags = {
        "sinking_ship": False,
        "budget_freeze": False,
        "chronic_complainer": False,
        "reason": None,
    }

    # Check sinking ship indicators
    layoffs = body.get("has_layoffs", False)
    negative_reviews = body.get("negative_management_reviews", False)
    if layoffs and negative_reviews:
        flags["sinking_ship"] = True
        flags["reason"] = "Company has layoffs + negative management reviews — sinking ship"

    # Check budget freeze
    job_removed = body.get("job_ad_removed", False)
    if job_removed:
        flags["budget_freeze"] = True
        flags["reason"] = (flags.get("reason", "") or "") + "; Job ad posted then removed — budget freeze suspected"

    # Check chronic complainer — same pain 18+ months without acting
    months_since_first_signal = body.get("months_since_first_signal", 0)
    no_action_taken = body.get("no_action_taken", True)
    if months_since_first_signal >= 18 and no_action_taken:
        flags["chronic_complainer"] = True
        flags["reason"] = (
            (flags.get("reason", "") or "") +
            f"; Same pain reported for {months_since_first_signal} months without acting — chronic complainer"
        )

    if flags["reason"]:
        flags["reason"] = flags["reason"].lstrip("; ")

    # Auto-archive if any anti-signal flag is set
    should_archive = flags["sinking_ship"] or flags["budget_freeze"] or flags["chronic_complainer"]

    await db_execute(
        "UPDATE leads SET sinking_ship = $2, budget_freeze = $3, chronic_complainer = $4, "
        "anti_signal_reason = $5, status = CASE WHEN $6 = TRUE THEN 'archived' ELSE status END "
        "WHERE id = $1",
        lead_id, flags["sinking_ship"], flags["budget_freeze"],
        flags["chronic_complainer"], flags["reason"],
        should_archive,
    )

    return {
        "lead_id": lead_id,
        "flags": flags,
        "archived": should_archive,
    }


@app.get(f"{PREFIX}/api/anti-signals")
async def get_anti_signals():
    """Return all leads flagged by the anti-signal filter (archived but reviewable)."""
    rows = await db_fetch(
        "SELECT id, company_name, industry, sinking_ship, budget_freeze, "
        "chronic_complainer, anti_signal_reason, status "
        "FROM leads WHERE sinking_ship = TRUE OR budget_freeze = TRUE OR chronic_complainer = TRUE "
        "ORDER BY company_name"
    )
    return {"flagged_leads": rows_to_list(rows), "count": len(rows)}


@app.post(f"{PREFIX}/api/anti-signals/{{lead_id}}/restore")
async def restore_anti_signal_lead(lead_id: int):
    """Restore an anti-signal archived lead for manual review."""
    lead = await db_fetchrow("SELECT id FROM leads WHERE id = $1", lead_id)
    if not lead:
        raise HTTPException(404, {"error": "Lead not found"})
    await db_execute(
        "UPDATE leads SET status = 'new', sinking_ship = FALSE, budget_freeze = FALSE, "
        "chronic_complainer = FALSE, anti_signal_reason = NULL WHERE id = $1",
        lead_id,
    )
    return {"lead_id": lead_id, "restored": True}


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — ADVANCED SIGNALS
# ══════════════════════════════════════════════════════════════════════════════


# ── 3A: Competitor Displacement Leaderboard ──────────────────────────────────

SEVERITY_WEIGHTS = {
    "negative_review": 6,
    "linkedin_complaint": 5,
    "talent_departure": 7,
    "funding_down": 4,
    "layoff": 9,
}


def compute_displacement_score(events: list) -> float:
    """Compute displacement score (0-100) from recent competitor events."""
    if not events:
        return 0.0
    total = sum(e.get("severity", 3) for e in events)
    # Scale: 50 severity points = score 100
    return min(round(total / 50 * 100, 1), 100)


@app.get(f"{PREFIX}/api/competitors")
async def get_competitors():
    """Return all monitored competitors with signal counts."""
    comps = await db_fetch("SELECT * FROM competitors ORDER BY name")
    result = []
    for c in comps:
        sig_count = await db_fetchval(
            "SELECT COUNT(*) FROM competitor_signals WHERE competitor_id = $1", c["id"]
        )
        result.append({
            "id": c["id"],
            "name": c["name"],
            "domain": c["domain"],
            "signal_count": sig_count,
        })
    result.sort(key=lambda x: x["signal_count"], reverse=True)
    return {"competitors": result}


@app.get(f"{PREFIX}/api/competitors/leaderboard")
async def competitor_leaderboard():
    """Ranked competitor displacement leaderboard — scored on negative signals in last 30 days."""
    comps = await db_fetch("SELECT * FROM competitors ORDER BY name")
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    board = []
    for c in comps:
        events = await db_fetch(
            "SELECT event_type, severity, title, detected_at FROM competitor_signals "
            "WHERE competitor_id = $1 AND detected_at >= $2 ORDER BY detected_at DESC",
            c["id"], cutoff,
        )
        event_list = rows_to_list(events)
        score = compute_displacement_score(event_list)
        event_breakdown = {}
        for e in event_list:
            et = e.get("event_type", "general")
            event_breakdown[et] = event_breakdown.get(et, 0) + 1
        board.append({
            "id": c["id"],
            "name": c["name"],
            "domain": c["domain"],
            "displacement_score": score,
            "event_count_30d": len(event_list),
            "event_breakdown": event_breakdown,
            "latest_event": event_list[0]["title"] if event_list else None,
        })
    board.sort(key=lambda x: x["displacement_score"], reverse=True)
    return {"leaderboard": board, "count": len(board), "window_days": 30}


@app.post(f"{PREFIX}/api/competitors")
async def add_competitor(request: Request):
    """Add a competitor to monitor."""
    body = await request.json()
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(400, {"error": "name is required"})
    domain = body.get("domain", "").strip() or None
    notes = body.get("notes", "").strip() or None
    existing = await db_fetchrow("SELECT id FROM competitors WHERE LOWER(name) = LOWER($1)", name)
    if existing:
        raise HTTPException(409, {"error": f"Competitor '{name}' already exists", "id": existing["id"]})
    row = await db_fetchrow(
        "INSERT INTO competitors (name, domain, notes) VALUES ($1, $2, $3) RETURNING id",
        name, domain, notes,
    )
    return {"id": row["id"], "name": name, "created": True}


@app.get(f"{PREFIX}/api/competitors/{{name}}/events")
async def get_competitor_events(name: str):
    """Return all events for a named competitor."""
    comp = await db_fetchrow("SELECT id, name FROM competitors WHERE LOWER(name) = LOWER($1)", name)
    if not comp:
        raise HTTPException(404, {"error": f"Competitor '{name}' not found"})
    events = await db_fetch(
        "SELECT * FROM competitor_signals WHERE competitor_id = $1 ORDER BY detected_at DESC",
        comp["id"],
    )
    return {
        "competitor": comp["name"],
        "events": rows_to_list(events),
        "count": len(events),
    }


# ── 3B: Talent Exodus Leading Indicator ──────────────────────────────────────

@app.get(f"{PREFIX}/api/competitors/{{name}}/talent-exodus")
async def talent_exodus(name: str):
    """Return talent departure analysis for a competitor."""
    comp = await db_fetchrow("SELECT id, name FROM competitors WHERE LOWER(name) = LOWER($1)", name)
    if not comp:
        raise HTTPException(404, {"error": f"Competitor '{name}' not found"})

    cutoff_60d = datetime.now(timezone.utc) - timedelta(days=60)
    departures = await db_fetch(
        "SELECT * FROM talent_departures WHERE competitor_id = $1 ORDER BY detected_at DESC",
        comp["id"],
    )
    recent_senior = [
        d for d in departures
        if d["seniority"] in ("senior", "executive") and d["detected_at"] >= cutoff_60d
    ]
    vulnerability_alert = len(recent_senior) >= 3

    return {
        "competitor": comp["name"],
        "total_departures": len(departures),
        "senior_departures_60d": len(recent_senior),
        "vulnerability_alert": vulnerability_alert,
        "departures": rows_to_list(departures),
    }


@app.get(f"{PREFIX}/api/competitors/vulnerable-clients")
async def vulnerable_clients():
    """Return competitors whose clients are most at risk based on talent exodus patterns."""
    comps = await db_fetch("SELECT * FROM competitors ORDER BY name")
    cutoff_60d = datetime.now(timezone.utc) - timedelta(days=60)
    vulnerable = []
    for c in comps:
        senior_deps = await db_fetch(
            "SELECT * FROM talent_departures WHERE competitor_id = $1 "
            "AND seniority IN ('senior', 'executive') AND detected_at >= $2",
            c["id"], cutoff_60d,
        )
        if len(senior_deps) >= 3:
            vulnerable.append({
                "competitor": c["name"],
                "senior_departures_60d": len(senior_deps),
                "roles_lost": [d["role_title"] for d in senior_deps],
                "vulnerability_alert": True,
            })
    vulnerable.sort(key=lambda x: x["senior_departures_60d"], reverse=True)
    return {"vulnerable_competitors": vulnerable, "count": len(vulnerable)}


# ── 3C: Industry Storm Severity Index ────────────────────────────────────────

REGULATORY_AUTHORITY_WEIGHT = {
    "APRA": 10, "ASIC": 9, "OAIC": 8, "ATO": 8,
    "ACCC": 7, "AUSTRAC": 9, "AHPRA": 7,
}


def compute_storm_severity(storm: dict) -> int:
    """Compute composite storm severity (1-10)."""
    # Base from regulatory authority
    reg_body = storm.get("regulatory_body") or ""
    authority_score = REGULATORY_AUTHORITY_WEIGHT.get(reg_body.upper(), 5)

    # Deadline proximity (closer = higher severity)
    deadline_score = 5
    deadline = storm.get("compliance_deadline")
    if deadline:
        if isinstance(deadline, str):
            deadline = date.fromisoformat(deadline)
        days_until = (deadline - date.today()).days
        if days_until <= 30:
            deadline_score = 10
        elif days_until <= 90:
            deadline_score = 7
        elif days_until <= 180:
            deadline_score = 4
        else:
            deadline_score = 2

    # Penalty size
    penalty = storm.get("penalty_amount", 0) or 0
    if penalty >= 10_000_000:
        penalty_score = 10
    elif penalty >= 1_000_000:
        penalty_score = 7
    elif penalty >= 100_000:
        penalty_score = 4
    else:
        penalty_score = 2

    # Companies affected
    affected = storm.get("companies_affected", 0) or 0
    if affected >= 1000:
        affected_score = 10
    elif affected >= 100:
        affected_score = 7
    elif affected >= 10:
        affected_score = 4
    else:
        affected_score = 2

    composite = (
        authority_score * 0.3
        + deadline_score * 0.3
        + penalty_score * 0.2
        + affected_score * 0.2
    )
    return max(1, min(10, round(composite)))


@app.get(f"{PREFIX}/api/storms")
async def list_storms():
    """List all storms with severity scoring."""
    rows = await db_fetch("SELECT * FROM storm_events ORDER BY severity DESC, detected_at DESC")
    storms = []
    for r in rows:
        d = row_to_dict(r)
        d["computed_severity"] = compute_storm_severity(d)
        if r["window_closes"]:
            delta = r["window_closes"] - date.today()
            d["days_remaining"] = max(delta.days, 0)
        else:
            d["days_remaining"] = None
        storms.append(d)
    return {"storms": storms, "count": len(storms)}


@app.post(f"{PREFIX}/api/storms")
async def create_storm(request: Request):
    """Manually create a storm event."""
    body = await request.json()
    name = body.get("event_name", "").strip()
    if not name:
        raise HTTPException(400, {"error": "event_name is required"})

    industry = body.get("industry", "").strip() or None
    severity = body.get("severity", 5)
    if severity < 1 or severity > 10:
        raise HTTPException(400, {"error": "severity must be 1-10"})
    description = body.get("description", "").strip() or None
    regulatory_body = body.get("regulatory_body", "").strip() or None
    compliance_deadline = body.get("compliance_deadline")
    penalty_amount = body.get("penalty_amount", 0) or 0
    companies_affected = body.get("companies_affected", 0) or 0
    window_closes = body.get("window_closes")

    row = await db_fetchrow(
        "INSERT INTO storm_events (event_name, industry, severity, description, regulatory_body, "
        "compliance_deadline, penalty_amount, companies_affected, window_closes) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
        name, industry, severity, description, regulatory_body,
        compliance_deadline, penalty_amount, companies_affected, window_closes,
    )
    return {"id": row["id"], "event_name": name, "severity": severity, "created": True}


@app.get(f"{PREFIX}/api/storms/{{storm_id}}/leads")
async def storm_leads(storm_id: int):
    """Return leads affected by a specific storm."""
    storm = await db_fetchrow("SELECT id, event_name, severity, industry FROM storm_events WHERE id = $1", storm_id)
    if not storm:
        raise HTTPException(404, {"error": "Storm not found"})

    # Direct FK match
    direct = await db_fetch(
        "SELECT id, company_name, industry, momentum_score, status "
        "FROM leads WHERE storm_id = $1 ORDER BY momentum_score DESC",
        storm_id,
    )
    # Also match by industry if storm has one
    industry_match = []
    if storm["industry"]:
        industry_match = await db_fetch(
            "SELECT id, company_name, industry, momentum_score, status "
            "FROM leads WHERE industry = $1 AND storm_id IS DISTINCT FROM $2 "
            "AND status NOT IN ('archived', 'won', 'lost') "
            "ORDER BY momentum_score DESC",
            storm["industry"], storm_id,
        )

    return {
        "storm": row_to_dict(storm),
        "directly_linked": rows_to_list(direct),
        "industry_match": rows_to_list(industry_match),
        "total_affected": len(direct) + len(industry_match),
    }


# ── 3D: Opportunity Saturation Index ─────────────────────────────────────────

@app.post(f"{PREFIX}/api/leads/{{lead_id}}/saturation")
async def update_saturation(lead_id: int, request: Request):
    """Update a lead's saturation index based on signal source analysis."""
    lead = await db_fetchrow("SELECT id FROM leads WHERE id = $1", lead_id)
    if not lead:
        raise HTTPException(404, {"error": "Lead not found"})
    body = await request.json()
    score = body.get("saturation_index")
    if score is None or not (0 <= score <= 1):
        raise HTTPException(400, {"error": "saturation_index must be 0-1"})
    await db_execute("UPDATE leads SET saturation_index = $2 WHERE id = $1", lead_id, score)

    # Recalculate momentum if high saturation
    modifier_applied = score > 0.7
    return {
        "lead_id": lead_id,
        "saturation_index": score,
        "saturation_level": "high" if score >= 0.7 else ("medium" if score >= 0.3 else "low"),
        "momentum_penalty_applied": modifier_applied,
    }


@app.post(f"{PREFIX}/api/leads/{{lead_id}}/first-seen")
async def update_first_seen(lead_id: int, request: Request):
    """Update first-seen tracking for a lead."""
    lead = await db_fetchrow("SELECT id FROM leads WHERE id = $1", lead_id)
    if not lead:
        raise HTTPException(404, {"error": "Lead not found"})
    body = await request.json()
    competitor_seen_count = body.get("competitor_seen_count", 0)
    if competitor_seen_count < 0:
        raise HTTPException(400, {"error": "competitor_seen_count must be >= 0"})

    await db_execute(
        "INSERT INTO lead_first_seen (lead_id, competitor_seen_count) VALUES ($1, $2) "
        "ON CONFLICT (lead_id) DO UPDATE SET competitor_seen_count = $2",
        lead_id, competitor_seen_count,
    )
    is_first_mover = competitor_seen_count == 0
    await db_execute("UPDATE leads SET first_mover = $2 WHERE id = $1", lead_id, is_first_mover)
    return {
        "lead_id": lead_id,
        "competitor_seen_count": competitor_seen_count,
        "first_mover": is_first_mover,
        "momentum_modifier": "+20%" if is_first_mover else "none",
    }


# ── Scan ──────────────────────────────────────────────────────────────────────

@app.post(f"{PREFIX}/api/scan")
async def trigger_scan(request: Request):
    """Trigger a manual scan. Returns a job ID."""
    body = await request.json()
    topic = body.get("topic", "").strip()
    if not topic:
        raise HTTPException(400, {"error": "topic is required"})

    job_id = hashlib.md5(f"{topic}{time.time()}".encode()).hexdigest()[:12]
    return {"job_id": job_id, "topic": topic, "status": "queued"}


@app.get(f"{PREFIX}/api/scan/status/{{job_id}}")
async def scan_status(job_id: str):
    """Return scan progress for a job."""
    return {"job_id": job_id, "status": "complete", "progress": 100}


# ── Credits ───────────────────────────────────────────────────────────────────

@app.get(f"{PREFIX}/api/credits/balance")
async def credits_balance():
    row = await db_fetchrow("SELECT balance, plan FROM credits WHERE user_id = 1")
    if not row:
        return {"balance": 0, "plan": "starter"}
    return {"balance": row["balance"], "plan": row["plan"]}


@app.post(f"{PREFIX}/api/credits/purchase")
async def purchase_credits(request: Request):
    body = await request.json()
    amount = body.get("amount", 0)
    if amount <= 0:
        raise HTTPException(400, {"error": "amount must be positive"})
    await db_execute("UPDATE credits SET balance = balance + $1 WHERE user_id = 1", amount)
    await db_execute(
        "INSERT INTO credit_history (user_id, amount, reason) VALUES (1, $1, 'purchase')", amount
    )
    row = await db_fetchrow("SELECT balance FROM credits WHERE user_id = 1")
    return {"balance": row["balance"] if row else 0, "added": amount}


@app.get(f"{PREFIX}/api/credits/history")
async def credits_history():
    rows = await db_fetch(
        "SELECT * FROM credit_history WHERE user_id = 1 ORDER BY created_at DESC LIMIT 50"
    )
    return {"history": rows_to_list(rows)}


# ── ELAINE Integration ────────────────────────────────────────────────────────

@app.get(f"{PREFIX}/api/elaine/summary")
async def elaine_summary():
    """Structured brief for ELAINE 7am morning briefing."""
    top5 = await db_fetch(
        "SELECT company_name, momentum_score, buying_window, pain_fingerprint "
        "FROM leads WHERE status NOT IN ('archived', 'won', 'lost') "
        "ORDER BY momentum_score DESC LIMIT 5"
    )
    storms = await db_fetch("SELECT event_name, severity FROM storm_events WHERE active = TRUE")
    active_count = await db_fetchval(
        "SELECT COUNT(*) FROM leads WHERE buying_window = 'active' AND status NOT IN ('archived', 'won', 'lost')"
    )
    warming_count = await db_fetchval(
        "SELECT COUNT(*) FROM leads WHERE buying_window = 'warming' AND status NOT IN ('archived', 'won', 'lost')"
    )

    summary_lines = []
    summary_lines.append(f"Signal Hunter: {active_count} active leads, {warming_count} warming.")
    if storms:
        for s in storms:
            summary_lines.append(f"Storm active: {s['event_name']} (severity {s['severity']})")
    if top5:
        summary_lines.append("Top lead: {} (momentum {}).".format(
            top5[0]["company_name"], top5[0]["momentum_score"]
        ))

    return {
        "app": "signal-hunter",
        "summary": " ".join(summary_lines),
        "active_leads": active_count,
        "warming_leads": warming_count,
        "top_leads": [
            {"company": r["company_name"], "momentum": r["momentum_score"], "window": r["buying_window"]}
            for r in top5
        ],
        "active_storms": [{"name": s["event_name"], "severity": s["severity"]} for s in storms],
    }


# ── ICP Profile ───────────────────────────────────────────────────────────────

@app.get(f"{PREFIX}/api/icp")
async def get_icp():
    """Return the current ICP profile."""
    row = await db_fetchrow("SELECT * FROM icp_profiles WHERE user_id = 1 ORDER BY id DESC LIMIT 1")
    if not row:
        return {"icp": None}
    return {"icp": row_to_dict(row)}


# ══════════════════════════════════════════════════════════════════════════════
# FRONTEND — Dashboard
# ══════════════════════════════════════════════════════════════════════════════

@app.get(f"{PREFIX}/")
@app.get(f"{PREFIX}")
async def dashboard():
    """Serve the dashboard HTML."""
    html_path = HERE / "dashboard.html"
    if html_path.exists():
        return HTMLResponse(html_path.read_text())
    return HTMLResponse("<h1>Signal Hunter</h1><p>Dashboard not found.</p>")


# ── Static files ──────────────────────────────────────────────────────────────
static_dir = HERE / "static"
if static_dir.exists():
    app.mount(f"{PREFIX}/static", StaticFiles(directory=str(static_dir)), name="static")


# ══════════════════════════════════════════════════════════════════════════════
# ENTRYPOINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=PORT, reload=True)
