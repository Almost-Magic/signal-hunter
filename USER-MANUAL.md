# Signal Hunter v3.0 — User Manual

## Overview

Signal Hunter is a timing intelligence engine that finds prospects who are mid-problem, mid-decision, or mid-frustration. It surfaces leads based on real-time signal analysis, not cold lists.

## Accessing Signal Hunter

- **Direct**: http://localhost:5302/signal/
- **Via NGINX**: http://amtl/signal/

## The Radar Dashboard

The main view is a sonar radar screen:

- **Inner ring (0-30 days)**: Active buying window — act today
- **Middle ring (31-90 days)**: Warming leads — nurture now
- **Outer ring (90+ days)**: Pipeline — monitor

Each blip represents a lead:
- **Size**: estimated deal value
- **Colour**: intent velocity (pulsing red = accelerating, amber = steady, blue = cooling, grey = monitor)
- **Hover**: glassmorphic tooltip with company, Momentum Score, pain summary
- **Click**: opens full lead detail panel

## Today's Top 5

Pinned at the top of all views. Five leads ranked by Momentum Score. Each shows company name, score, pain summary, and a one-click "Send Draft A" button.

## Lead Detail Panel

Click any lead to open the detail panel:
- **Momentum Score**: the single number that matters (0-100)
- **Score Breakdown**: weighted components (intent velocity, buying window, fit, corroboration, emotional intensity, ghost signals, competitor presence)
- **Signal Stack**: layered badges showing corroborating signals (Reddit, LinkedIn, job ads, funding, dark web, competitor complaints)
- **Pain Fingerprint**: semantic profile of the prospect's exact language and emotional register
- **Pain Vocabulary**: word cloud of their pain language
- **Buying Committee**: inferred stakeholders (Economic Buyer, Technical Evaluator, Champion, Gatekeeper)
- **Intent Trajectory**: timeline of signal events with predicted decision point
- **Outreach Drafts**: three personalised drafts (Observation, Industry, Warm Path)
- **ROI Calculator**: estimated deal value, close probability, expected value

## Actions

- **Act**: marks the lead as contacted, pushes to Ripple (when available)
- **Pass**: archives the lead, trains the algorithm

## Daily Review (One-Swipe Mode)

Full-screen card per lead. Use keyboard shortcuts:
- **R**: Act on lead
- **P**: Pass
- **Arrow keys**: navigate between cards

## Industry Storms

When a severity 7+ event is detected (e.g., Privacy Act Reform 2026), the War Room banner appears with storm details and countdown timer. Click the storm indicator in the header to toggle.

## Vertical Agents

The left rail shows industry vertical filters:
- All, Cyber, AI/DT, Legal, Finance, Construction, Healthcare
- Click any chip to filter the radar to that industry

## Privacy & Compliance

Signal Hunter has a built-in Privacy-First Compliance Engine:
- **Data Classification**: all signals classified as Public Broadcast, Inferred, Dark Web, or Personal
- **Scrape Consent Registry**: sources checked before collection
- **Right to Erasure**: delete all data for any company on demand
- **Audit Log**: full chain of custody for every signal collected
- **APP 5 Notifications**: triggered if personal data from non-public sources is surfaced
- **Dark Web Module**: gated by Terms of Service acceptance

## Dark/Light Theme

Click the moon/sun icon in the header to toggle between dark (#0A0E14) and light themes.

## Credits

Your credit balance is shown in the header. Credits are consumed when generating full lead intelligence packages.
