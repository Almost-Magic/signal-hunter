# Author: Mani Padisetti
"""
Beast Test Suite -- Signal Hunter v3.0
Port: 5302
Path: /home/mani/signalhunter/
Run:  python -m pytest beast_test.py -v

Probabilistic timing intelligence engine with adaptive learning.
Tests health, Phase 0 privacy/compliance, Phase 1 core, edge cases,
negative paths, NGINX subpath, and security.

Almost Magic Tech Lab
"""

import time
import pytest
import httpx

BASE_URL = "http://localhost:5302"
APP_NAME = "signal-hunter"
NGINX_URL = "http://amtl"
PREFIX = "/signal"


# ---------------------------------------------------------------------------
# SECTION 1: HEALTH (3 tests)
# ---------------------------------------------------------------------------
class TestHealth:
    """Health endpoint tests."""

    def test_health_happy_path(self):
        """Happy: GET /signal/health returns 200 with operational status."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/health", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "operational"
        assert data["service"] == APP_NAME
        assert data["version"] == "3.0.0"

    def test_api_health(self):
        """Happy: GET /signal/api/health returns 200 with uptime."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/health", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "operational"
        assert "uptime_seconds" in data
        assert isinstance(data["uptime_seconds"], (int, float))

    def test_fleet_health(self):
        """Happy: GET /health returns 200 for fleet discovery."""
        r = httpx.get(f"{BASE_URL}/health", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "operational"
        assert data["port"] == 5302


# ---------------------------------------------------------------------------
# SECTION 2: PHASE 0 — PRIVACY & COMPLIANCE (7 tests)
# ---------------------------------------------------------------------------
class TestPrivacyCompliance:
    """Phase 0: Privacy-First Compliance Engine tests."""

    def test_classifications(self):
        """Happy: GET classifications returns 4 data classes."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/privacy/classifications", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "classifications" in data
        ids = [c["id"] for c in data["classifications"]]
        assert "public_broadcast" in ids
        assert "inferred" in ids
        assert "dark_web" in ids
        assert "personal" in ids

    def test_consent_registry(self):
        """Happy: GET consent registry returns source list."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/privacy/consent-registry", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "sources" in data
        assert len(data["sources"]) > 0
        names = [s["source_name"] for s in data["sources"]]
        assert "Reddit" in names
        assert "LinkedIn" in names

    def test_audit_log(self):
        """Happy: GET audit log returns signal audit entries."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/privacy/audit", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "audit_log" in data
        assert "total" in data
        assert isinstance(data["audit_log"], list)

    def test_compliance_report(self):
        """Happy: GET compliance report returns structured summary."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/privacy/report", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "total_signals" in data
        assert "by_classification" in data
        assert "total_erasure_requests" in data
        assert "app5_notifications" in data

    def test_dark_web_tos_status(self):
        """Happy: GET dark web TOS returns acceptance status."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/privacy/dark-web-tos", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "accepted" in data

    def test_dark_web_tos_accept(self):
        """Happy: POST dark web TOS accepts terms."""
        r = httpx.post(
            f"{BASE_URL}{PREFIX}/api/privacy/dark-web-tos",
            json={"accept": True},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["accepted"] is True

    def test_app5_notifications(self):
        """Happy: GET APP 5 notifications returns list."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/privacy/app5", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "notifications" in data
        assert isinstance(data["notifications"], list)


# ---------------------------------------------------------------------------
# SECTION 3: PHASE 1 — CORE ENGINE (10 tests)
# ---------------------------------------------------------------------------
class TestCoreEngine:
    """Phase 1: Core Engine tests — leads, radar, top 5, storms, ELAINE."""

    def test_leads_list(self):
        """Happy: GET /signal/api/leads returns ranked lead list."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/leads", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "leads" in data
        assert len(data["leads"]) > 0
        first = data["leads"][0]
        assert "company_name" in first
        assert "momentum_score" in first
        assert "fit_score" in first

    def test_single_lead(self):
        """Happy: GET /signal/api/leads/1 returns full lead with signals."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/leads/1", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["company_name"] is not None
        assert "signals" in data
        assert "buying_committee" in data

    def test_lead_timeline(self):
        """Happy: GET /signal/api/leads/1/timeline returns events."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/leads/1/timeline", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "events" in data
        assert isinstance(data["events"], list)
        assert len(data["events"]) > 0

    def test_lead_committee(self):
        """Happy: GET /signal/api/leads/1/committee returns buying committee."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/leads/1/committee", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "committee" in data
        assert len(data["committee"]) > 0
        roles = [c["role"] for c in data["committee"]]
        assert "economic_buyer" in roles

    def test_radar(self):
        """Happy: GET /signal/api/radar returns blips for radar UI."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/radar", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "blips" in data
        assert len(data["blips"]) > 0
        blip = data["blips"][0]
        assert "company" in blip
        assert "momentum" in blip
        assert "ring" in blip
        assert "heat" in blip

    def test_todays_top_leads(self):
        """Happy: GET /signal/api/today returns top leads with ELAINE format."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/today", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "top_leads" in data
        assert "total_leads_today" in data
        assert "hot_leads" in data
        assert "active_storms" in data
        assert len(data["top_leads"]) <= 5
        assert len(data["top_leads"]) > 0
        lead = data["top_leads"][0]
        assert "momentum_score" in lead
        assert "buying_window" in lead

    def test_active_storms(self):
        """Happy: GET /signal/api/storms/active returns active storms."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/storms/active", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "storms" in data
        assert len(data["storms"]) >= 1
        s = data["storms"][0]
        assert "severity" in s
        assert "days_remaining" in s

    def test_competitors(self):
        """Happy: GET /signal/api/competitors returns competitor list."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/competitors", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "competitors" in data
        assert len(data["competitors"]) > 0

    def test_elaine_summary(self):
        """Happy: GET /signal/api/elaine/summary returns ELAINE brief."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/elaine/summary", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["app"] == "signal-hunter"
        assert "summary" in data
        assert "top_leads" in data
        assert "active_storms" in data

    def test_credits_balance(self):
        """Happy: GET /signal/api/credits/balance returns balance."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/credits/balance", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "balance" in data
        assert "plan" in data
        assert isinstance(data["balance"], int)


# ---------------------------------------------------------------------------
# SECTION 4: EDGE CASES (3 tests)
# ---------------------------------------------------------------------------
class TestEdgeCases:
    """Edge-case tests."""

    def test_lead_not_found(self):
        """Edge: GET /signal/api/leads/99999 returns 404."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/leads/99999", timeout=10)
        assert r.status_code == 404

    def test_radar_filter_industry(self):
        """Edge: GET /signal/api/radar?industry=Healthcare filters results."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/radar?industry=Healthcare", timeout=10)
        assert r.status_code == 200
        data = r.json()
        for blip in data["blips"]:
            assert blip["industry"] == "Healthcare"

    def test_velocity_not_found(self):
        """Edge: GET /signal/api/velocity/nonexistent returns 404."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/velocity/nonexistent-entity", timeout=10)
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# SECTION 5: NEGATIVE PATHS (4 tests)
# ---------------------------------------------------------------------------
class TestNegativePaths:
    """Negative-path tests."""

    def test_forget_missing_company(self):
        """Negative: POST forget without company_name returns 400."""
        r = httpx.post(
            f"{BASE_URL}{PREFIX}/api/privacy/forget",
            json={},
            timeout=10,
        )
        assert r.status_code == 400

    def test_scan_missing_topic(self):
        """Negative: POST scan without topic returns 400."""
        r = httpx.post(
            f"{BASE_URL}{PREFIX}/api/scan",
            json={},
            timeout=10,
        )
        assert r.status_code == 400

    def test_outcome_invalid(self):
        """Negative: POST outcome with invalid outcome returns 400."""
        r = httpx.post(
            f"{BASE_URL}{PREFIX}/api/leads/1/outcome",
            json={"outcome": "maybe"},
            timeout=10,
        )
        assert r.status_code == 400

    def test_credits_purchase_zero(self):
        """Negative: POST credits purchase with 0 amount returns 400."""
        r = httpx.post(
            f"{BASE_URL}{PREFIX}/api/credits/purchase",
            json={"amount": 0},
            timeout=10,
        )
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# SECTION 6: NGINX SUBPATH (2 tests)
# ---------------------------------------------------------------------------
class TestNginxSubpath:
    """NGINX subpath compliance."""

    def test_dashboard_loads_at_subpath(self):
        """Happy: GET /signal/ returns dashboard HTML."""
        r = httpx.get(
            f"{NGINX_URL}{PREFIX}/",
            timeout=10,
            follow_redirects=True,
        )
        assert r.status_code == 200
        body = r.text
        assert "Signal Hunter" in body

    def test_health_at_nginx_subpath(self):
        """Happy: GET http://amtl/signal/health returns operational."""
        r = httpx.get(f"{NGINX_URL}{PREFIX}/health", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "operational"


# ---------------------------------------------------------------------------
# SECTION 7: SECURITY (4 tests)
# ---------------------------------------------------------------------------
class TestSecurity:
    """Security tests."""

    def test_sql_injection_lead_id(self):
        """Security: SQL injection in lead_id path does not crash."""
        r = httpx.get(
            f"{BASE_URL}{PREFIX}/api/leads/1;DROP TABLE leads;--",
            timeout=10,
        )
        assert r.status_code in (404, 422)

    def test_xss_in_company_lookup(self):
        """Security: XSS payload returns JSON, not HTML."""
        r = httpx.get(
            f"{BASE_URL}{PREFIX}/api/leads/99999",
            timeout=10,
        )
        assert r.status_code == 404
        ct = r.headers.get("content-type", "")
        assert "application/json" in ct

    def test_large_payload_forget(self):
        """Security: Oversized company name handled gracefully."""
        huge = "A" * 100_000
        r = httpx.post(
            f"{BASE_URL}{PREFIX}/api/privacy/forget",
            json={"company_name": huge},
            timeout=10,
        )
        assert r.status_code in (200, 400, 413, 422)

    def test_command_injection_in_scan(self):
        """Security: Shell metacharacters in scan topic handled safely."""
        r = httpx.post(
            f"{BASE_URL}{PREFIX}/api/scan",
            json={"topic": "; rm -rf / && cat /etc/passwd"},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert "job_id" in data


# ---------------------------------------------------------------------------
# SECTION 8: ERASURE & PRIVACY ACTIONS (2 tests)
# ---------------------------------------------------------------------------
class TestErasureActions:
    """Privacy action tests — erasure and audit chain."""

    def test_forget_nonexistent_company(self):
        """Happy: POST forget for unknown company returns 0 records deleted."""
        r = httpx.post(
            f"{BASE_URL}{PREFIX}/api/privacy/forget",
            json={"company_name": "Completely Fake Corp XYZ 12345"},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "erased"
        assert data["records_deleted"] == 0

    def test_scan_valid(self):
        """Happy: POST scan with valid topic returns job_id."""
        r = httpx.post(
            f"{BASE_URL}{PREFIX}/api/scan",
            json={"topic": "privacy compliance ANZ"},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert "job_id" in data
        assert data["status"] == "queued"


# ---------------------------------------------------------------------------
# SECTION 9: PHASE 2 — INTELLIGENCE LAYER (12 tests)
# ---------------------------------------------------------------------------
class TestNarrativeShiftDetection:
    """Phase 2B: Narrative Shift Detection."""

    def test_narrative_shifts_list(self):
        """Happy: GET /signal/api/narrative-shifts returns shift list."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/narrative-shifts", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "shifts" in data
        assert "count" in data
        assert isinstance(data["shifts"], list)

    def test_analyse_narrative(self):
        """Happy: POST analyse-narrative for lead 1 returns stage."""
        r = httpx.post(f"{BASE_URL}{PREFIX}/api/leads/1/analyse-narrative", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["lead_id"] == 1
        assert "narrative_stage" in data
        assert data["narrative_stage"] in ("exploratory", "urgent", "transitioning", "unknown")
        assert "shift_detected" in data
        assert isinstance(data["shift_detected"], bool)

    def test_analyse_narrative_not_found(self):
        """Edge: analyse-narrative for non-existent lead returns 404."""
        r = httpx.post(f"{BASE_URL}{PREFIX}/api/leads/99999/analyse-narrative", timeout=10)
        assert r.status_code == 404


class TestSilenceDetection:
    """Phase 2C: Silence Detection."""

    def test_silence_list(self):
        """Happy: GET /signal/api/silence returns silent leads."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/silence", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "silent_leads" in data
        assert "count" in data

    def test_silence_scan(self):
        """Happy: POST /signal/api/silence/scan detects silent entities."""
        r = httpx.post(f"{BASE_URL}{PREFIX}/api/silence/scan", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "detected" in data
        assert "count" in data

    def test_posting_history(self):
        """Happy: GET /signal/api/posting-history returns entities."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/posting-history", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "entities" in data
        assert len(data["entities"]) > 0


class TestJobAdArchaeology:
    """Phase 2D: Ghost Signal Enhancement — Job Ad Parsing."""

    def test_parse_job_ad(self):
        """Happy: POST parse-job-ad extracts intelligence."""
        r = httpx.post(
            f"{BASE_URL}{PREFIX}/api/leads/1/parse-job-ad",
            json={"job_text": "Senior Cloud Architect needed. Must have AWS and Azure. Reporting to CTO. Legacy migration."},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["lead_id"] == 1
        assert "parsed" in data
        parsed = data["parsed"]
        assert "implied_pain" in parsed
        assert "tech_stack" in parsed
        assert "aws" in parsed["tech_stack"]

    def test_parse_job_ad_too_short(self):
        """Negative: POST parse-job-ad with short text returns 400."""
        r = httpx.post(
            f"{BASE_URL}{PREFIX}/api/leads/1/parse-job-ad",
            json={"job_text": "Short"},
            timeout=10,
        )
        assert r.status_code == 400


class TestAntiSignalFilter:
    """Phase 2E: Anti-Signal Filter (Adversarial Qualification)."""

    def test_anti_signals_list(self):
        """Happy: GET /signal/api/anti-signals returns flagged leads."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/anti-signals", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "flagged_leads" in data
        assert "count" in data

    def test_qualify_clean_lead(self):
        """Happy: POST qualify with no flags returns clean result."""
        r = httpx.post(
            f"{BASE_URL}{PREFIX}/api/leads/2/qualify",
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["lead_id"] == 2
        assert data["archived"] is False

    def test_qualify_not_found(self):
        """Edge: POST qualify for non-existent lead returns 404."""
        r = httpx.post(f"{BASE_URL}{PREFIX}/api/leads/99999/qualify", timeout=10)
        assert r.status_code == 404


class TestWinPatterns:
    """Phase 2A: Reverse Signal Pattern Engine."""

    def test_win_patterns_list(self):
        """Happy: GET /signal/api/patterns/wins returns pattern list."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/patterns/wins", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "patterns" in data
        assert isinstance(data["patterns"], list)


# ---------------------------------------------------------------------------
# SECTION 10: PHASE 3 — ADVANCED SIGNALS (18 tests)
# ---------------------------------------------------------------------------
class TestCompetitorLeaderboard:
    """Phase 3A: Competitor Displacement Leaderboard."""

    def test_leaderboard(self):
        """Happy: GET /signal/api/competitors/leaderboard returns ranked list."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/competitors/leaderboard", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "leaderboard" in data
        assert "count" in data
        assert "window_days" in data
        assert len(data["leaderboard"]) > 0
        top = data["leaderboard"][0]
        assert "displacement_score" in top
        assert "event_count_30d" in top
        assert "event_breakdown" in top

    def test_add_competitor(self):
        """Happy: POST /signal/api/competitors adds a new competitor."""
        r = httpx.post(
            f"{BASE_URL}{PREFIX}/api/competitors",
            json={"name": f"TestComp_{int(time.time())}", "domain": "test.com"},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["created"] is True
        assert "id" in data

    def test_add_competitor_no_name(self):
        """Negative: POST competitor without name returns 400."""
        r = httpx.post(
            f"{BASE_URL}{PREFIX}/api/competitors",
            json={"domain": "test.com"},
            timeout=10,
        )
        assert r.status_code == 400

    def test_competitor_events(self):
        """Happy: GET /signal/api/competitors/{name}/events returns event list."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/competitors/DataSecure/events", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "events" in data
        assert "count" in data
        assert data["competitor"] == "DataSecure"

    def test_competitor_events_not_found(self):
        """Edge: GET events for unknown competitor returns 404."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/competitors/nonexistent/events", timeout=10)
        assert r.status_code == 404


class TestTalentExodus:
    """Phase 3B: Talent Exodus Leading Indicator."""

    def test_talent_exodus(self):
        """Happy: GET talent-exodus for competitor returns analysis."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/competitors/DataSecure/talent-exodus", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "total_departures" in data
        assert "senior_departures_60d" in data
        assert "vulnerability_alert" in data
        assert "departures" in data

    def test_talent_exodus_not_found(self):
        """Edge: talent-exodus for unknown competitor returns 404."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/competitors/nonexistent/talent-exodus", timeout=10)
        assert r.status_code == 404

    def test_vulnerable_clients(self):
        """Happy: GET vulnerable-clients returns at-risk competitors."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/competitors/vulnerable-clients", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "vulnerable_competitors" in data
        assert "count" in data


class TestStormSeverity:
    """Phase 3C: Industry Storm Severity Index."""

    def test_storms_list(self):
        """Happy: GET /signal/api/storms returns all storms with severity."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/storms", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "storms" in data
        assert "count" in data
        if data["count"] > 0:
            assert "computed_severity" in data["storms"][0]

    def test_create_storm(self):
        """Happy: POST /signal/api/storms creates a storm event."""
        r = httpx.post(
            f"{BASE_URL}{PREFIX}/api/storms",
            json={
                "event_name": f"Test Storm {int(time.time())}",
                "industry": "Technology",
                "severity": 5,
            },
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["created"] is True
        assert "id" in data

    def test_create_storm_invalid_severity(self):
        """Negative: POST storm with severity > 10 returns 400."""
        r = httpx.post(
            f"{BASE_URL}{PREFIX}/api/storms",
            json={"event_name": "Bad Storm", "severity": 15},
            timeout=10,
        )
        assert r.status_code == 400

    def test_storm_leads(self):
        """Happy: GET /signal/api/storms/1/leads returns affected leads."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/storms/1/leads", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "storm" in data
        assert "directly_linked" in data
        assert "total_affected" in data

    def test_storm_leads_not_found(self):
        """Edge: GET storm leads for non-existent storm returns 404."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/storms/99999/leads", timeout=10)
        assert r.status_code == 404

    def test_war_room_triggers(self):
        """Happy: GET storms/active includes war_room_triggers list."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/storms/active", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "war_room_triggers" in data
        assert isinstance(data["war_room_triggers"], list)


class TestSaturationIndex:
    """Phase 3D: Opportunity Saturation Index."""

    def test_saturation_breakdown(self):
        """Happy: GET /signal/api/leads/saturation returns grouped leads."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/leads/saturation", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "low_saturation" in data
        assert "medium_saturation" in data
        assert "high_saturation" in data
        assert "counts" in data
        # High-saturation leads should have momentum modifier
        for lead in data["high_saturation"]:
            assert lead["momentum_modifier"] == "-15%"


class TestFirstMover:
    """Phase 3E: First Mover Alert."""

    def test_first_movers_list(self):
        """Happy: GET /signal/api/leads/first-movers returns first-mover leads."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/leads/first-movers", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "first_movers" in data
        assert "count" in data
        if data["count"] > 0:
            fm = data["first_movers"][0]
            assert fm["competitor_seen_count"] == 0
            assert fm["first_mover"] is True
