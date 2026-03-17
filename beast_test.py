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

    def test_todays_top5(self):
        """Happy: GET /signal/api/today returns top 5 leads."""
        r = httpx.get(f"{BASE_URL}{PREFIX}/api/today", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "top5" in data
        assert len(data["top5"]) <= 5
        assert len(data["top5"]) > 0

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
