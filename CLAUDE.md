# Internal Phishing Detection Tool

## Overview

An internal phishing email checker for enterprises. Users check suspicious emails and get instant YES/NO verdicts. CISO gets visibility into what's hitting the organization.

**Demo Domain:** forzon.ca

**Tagline:** "Is this phishing? Find out in seconds."

---

## Problem

Current "Report Phishing" buttons:
- User clicks → "Thanks for reporting" → learns nothing
- Email disappears into vendor cloud
- CISO has no visibility into volume or campaigns
- Data goes to third party
- Costs $3-10/user/year

---

## Solution

| For Users | For CISO |
|-----------|----------|
| Instant YES/NO verdict | Real-time threat visibility |
| Plain English explanation | Campaign detection alerts |
| Learns what to look for | Department targeting stats |
| Keeps control of email | Accuracy metrics |
| | All data stays internal |

---

## Two Input Methods

### Method 1: Outlook Side Panel

```
User opens suspicious email
        ↓
Clicks [Is This Phishing?] button in ribbon
        ↓
Side panel opens
        ↓
Analysis runs
        ↓
Shows verdict
```

### Method 2: Forward Email

```
User forwards to phishing@forzon.ca
        ↓
Server receives via Graph API
        ↓
Analyzes
        ↓
Replies with verdict
```

Same analysis engine. Two entry points.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CORPORATE NETWORK                            │
│                                                                     │
│                                                                     │
│   INPUT METHOD 1: Add-in                                            │
│   ┌─────────────────────┐                                          │
│   │ User Outlook        │                                          │
│   │                     │                                          │
│   │ Clicks [Is This     │      POST /api/check                     │
│   │ Phishing?] button   │─────────────────────────┐                │
│   │                     │                         │                │
│   └─────────────────────┘                         │                │
│                                                   │                │
│                                                   ▼                │
│   INPUT METHOD 2: Forward          ┌─────────────────────────────┐ │
│   ┌─────────────────────┐          │                             │ │
│   │ User forwards to    │          │      LINUX SERVER           │ │
│   │ phishing@forzon.ca│          │                             │ │
│   └──────────┬──────────┘          │ ┌─────────────────────────┐ │ │
│              │                     │ │     Analysis API        │ │ │
│              ▼                     │ │                         │ │ │
│   ┌─────────────────────┐          │ │  POST /api/check        │ │ │
│   │ O365 Mailbox        │          │ │  - Parse headers        │ │ │
│   │ phishing@forzon.ca│          │ │  - Check signals        │ │ │
│   └──────────┬──────────┘          │ │  - Calculate score      │ │ │
│              │                     │ │  - Return verdict       │ │ │
│              │ Graph API           │ │                         │ │ │
│              │ (server polls       │ └────────────┬────────────┘ │ │
│              │  or webhook)        │              │              │ │
│              │                     │              ▼              │ │
│              └────────────────────▶│ ┌─────────────────────────┐ │ │
│                                    │ │     SQLite              │ │ │
│                                    │ │                         │ │ │
│                                    │ │  - Submissions          │ │ │
│                                    │ │  - Feedback             │ │ │
│                                    │ │  - Campaigns            │ │ │
│                                    │ │  - Whitelist            │ │ │
│                                    │ │                         │ │ │
│                                    │ └─────────────────────────┘ │ │
│                                    │                             │ │
│                                    │ ┌─────────────────────────┐ │ │
│   OUTPUT: Add-in                   │ │  Graph API Client       │ │ │
│   ┌─────────────────────┐          │ │                         │ │ │
│   │ Side panel shows    │◀─────────│ │  - Read phishing@ inbox │ │ │
│   │ verdict instantly   │          │ │  - Send reply emails    │ │ │
│   └─────────────────────┘          │ │  - Lookup user dept     │ │ │
│                                    │ │                         │ │ │
│   OUTPUT: Forward                  │ └─────────────────────────┘ │ │
│   ┌─────────────────────┐          │                             │ │
│   │ User receives       │◀─────────│                             │ │
│   │ reply email with    │          └─────────────────────────────┘ │
│   │ verdict             │                       ▲                  │
│   └─────────────────────┘                       │                  │
│                                                 │                  │
│   ┌─────────────────────┐                       │                  │
│   │ CISO Dashboard      │───────────────────────┘                  │
│   │ (Web UI)            │                                          │
│   └─────────────────────┘                                          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Both methods hit the same `/api/check` endpoint. Same analysis. Same database.**

- **Add-in:** Calls API directly, gets response, shows in panel
- **Forward:** Server reads mailbox via Graph API, calls same analysis, sends reply via Graph API

---

## Microsoft vs Internal Tool Checks

| Check | Microsoft O365 | Internal Tool |
|-------|----------------|--------------|
| SPF/DKIM/DMARC | ✅ Does it | ✅ Reads Microsoft's result |
| Spam score (SCL) | ✅ Does it | ✅ Reads Microsoft's result |
| Phishing score (PCL) | ✅ Does it | ✅ Reads Microsoft's result |
| Known malware signatures | ✅ Does it | ❌ Not needed |
| Global threat intel | ✅ Does it | ❌ Not needed |
| **Domain age check** | ❌ | ✅ **We add this** |
| **Reply-To mismatch** | ❌ | ✅ **We add this** |
| **Lookalike domain detection** | ⚠️ Limited | ✅ **We add this** |
| **Suspicious TLD check** | ❌ | ✅ **We add this** |
| **Internal blacklist** | ❌ | ✅ **We add this** |
| **Internal whitelist** | ❌ | ✅ **We add this** |
| **Campaign detection (your org)** | ❌ | ✅ **We add this** |
| **User feedback loop** | ❌ | ✅ **We add this** |
| **Plain English explanation** | ❌ | ✅ **We add this** |
| **CISO dashboard** | ❌ | ✅ **We add this** |

**Microsoft is the foundation. Internal Tool adds internal intelligence and user visibility.**

---

## How Analysis Works

### We Don't Guess - We Read What Microsoft Already Knows

O365 adds headers to every email with their verdict:

```
Authentication-Results: spf=fail; dkim=fail; dmarc=fail
X-Forefront-Antispam-Report: CAT:PHSH; SCL:9; PCL:5
X-MS-Exchange-Organization-SCL: 9
```

We parse these headers and translate to plain English.

### Signals & Weights

| Signal | Weight | Source | Provider |
|--------|--------|--------|----------|
| Microsoft says phishing (CAT:PHSH) | +40 | O365 header | Microsoft |
| SPF fail | +15 | O365 header | Microsoft |
| DKIM fail | +15 | O365 header | Microsoft |
| DMARC fail | +10 | O365 header | Microsoft |
| High spam score (SCL ≥ 7) | +10 | O365 header | Microsoft |
| High phishing score (PCL ≥ 5) | +15 | O365 header | Microsoft |
| Domain age < 7 days | +15 | WHOIS lookup | Internal Tool |
| Domain age < 30 days | +10 | WHOIS lookup | Internal Tool |
| Reply-To mismatch | +10 | Header comparison | Internal Tool |
| Lookalike domain (paypa1, micros0ft) | +15 | Pattern match | Internal Tool |
| Suspicious TLD (.xyz, .tk, etc) | +10 | Domain check | Internal Tool |
| Urgency language | +5 | Content scan | Internal Tool |
| Credential request | +5 | Content scan | Internal Tool |
| Generic greeting | +5 | Content scan | Internal Tool |
| Suspicious link | +10 | URL analysis | Internal Tool |
| On internal blacklist | +30 | Our database | Internal Tool |
| On internal whitelist | -40 | Our database | Internal Tool |

**Microsoft signals:** 6 (max +105 points)
**Internal Tool signals:** 11 (max +125 points, or -40 for whitelist)

### Confidence Score

```
Raw score = sum of triggered signals
Confidence = min(raw score, 100)
```

### Verdict Thresholds

| Score | Verdict |
|-------|---------|
| 70-100 | 🔴 PHISHING |
| 40-69 | 🟡 SUSPICIOUS |
| 0-39 | 🟢 LIKELY SAFE |

### Weights Are Tunable

**Starting weights are based on published research. Sources cited below.**

| Signal | Weight | Rationale | Source |
|--------|--------|-----------|--------|
| Microsoft CAT:PHSH | +40 | Highest - Microsoft explicitly flagged it as phishing | Microsoft detection |
| SPF fail | +15 | Strong - sender IP not authorized | Email authentication standard |
| DKIM fail | +15 | Strong - message signature invalid | Email authentication standard |
| DMARC fail | +10 | Medium - policy check failed | Email authentication standard |
| SCL ≥ 7 | +10 | Medium - Microsoft spam score | Microsoft detection |
| PCL ≥ 5 | +15 | Strong - Microsoft phishing score | Microsoft detection |
| Domain < 7 days | +15 | Strong - 63% of phishing domains blocked within 4 days of registration | DNS Research Federation |
| Domain < 30 days | +10 | Medium - 41% of phishing domains used within 14 days of registration | Interisle 2022 |
| Reply-To mismatch | +10 | Medium - common deception tactic | Industry pattern |
| Lookalike domain | +15 | Strong - clear impersonation attempt | Industry pattern |
| Suspicious TLD | +10 | Medium - 42% of phishing in new gTLDs (.xyz, .top, etc) | Interisle 2024 |
| Urgency language | +5 | Weak - legitimate emails use this too | Heuristic |
| Credential request | +5 | Weak - context matters | Heuristic |
| Generic greeting | +5 | Weak - some legitimate bulk email does this | Heuristic |
| Suspicious link | +10 | Medium - depends on destination | URL analysis |
| Internal blacklist | +30 | Strong - we've seen this before | Internal data |
| Internal whitelist | -40 | Strong - verified safe | Internal data |

---

### Research Sources (Real Reports)

**Domain Age Statistics:**

| Finding | Source | Link |
|---------|--------|------|
| 63% of phishing domains blocked within 4 days of registration | DNS Research Federation (2023) | https://dnsrf.org/blog/phishing-attacks--newly-registered-domains-still-a-prominent-threat/ |
| 41% of phishing domains used within 14 days of registration | Interisle Phishing Landscape 2022 | https://interisle.net/PhishingLandscape2022.pdf |
| 77% of phishing domains were maliciously registered | APWG / Interisle (2024) | https://apwg.org/phishing-ended-2023-with-a-bang/ |
| Phishing sites: 1/3 inactive within 24 hours, 70% within 30 days | DNSFilter (2021 study) | https://www.dnsfilter.com/blog/risks-and-dangers-of-new-domains |

**TLD Abuse Statistics:**

| Finding | Source | Link |
|---------|--------|------|
| 42% of phishing domains in new gTLDs (vs 25% prior year) | Interisle Phishing Landscape 2024 | https://interisle.net/PhishingLandscape2024.pdf |
| Top phishing TLDs: .COM, .TOP, .ORG, .SHOP, .XYZ | APWG (2024) | https://apwg.org/phishing-ended-2023-with-a-bang/ |

**Overall Phishing Statistics:**

| Finding | Source | Link |
|---------|--------|------|
| ~1.9 million phishing attacks worldwide (2024) | Interisle Phishing Landscape 2024 | https://interisle.net/PhishingLandscape2024.pdf |
| 90% of cyberattacks begin with phishing | CISA | Referenced in Interisle 2025 |
| $16.6 billion direct financial losses (2024, US) | FBI IC3 | Referenced in Interisle 2025 |
| Phishing responsible for 41% of all cyber incidents | IBM | Referenced in Keepnet Labs |

**Email Authentication:**

| Finding | Source | Link |
|---------|--------|------|
| 68% of domains have no SPF record | RedHunt Labs (2025) | https://redhuntlabs.com/blog/internet-wide-study-state-of-spf-dkim-and-dmarc/ |
| 41% of banking institutions lack DMARC | PowerDMARC (2025) | https://powerdmarc.com/email-phishing-dmarc-statistics/ |

---

### Free Reports To Download

1. **Interisle Phishing Landscape** (Annual, free)
   - https://interisle.net/PhishingLandscape2024.pdf
   - Best data on domain age, TLD abuse, attack volumes

2. **APWG Phishing Activity Trends** (Quarterly, free)
   - https://apwg.org/trendsreports/
   - Industry standard phishing metrics

3. **Cybercrime Information Center** (Ongoing, free)
   - https://cybercrimeinfocenter.org/phishing-activity/
   - Real-time TLD and registrar rankings

---

### How To Tune Weights

1. Start with these weights (based on research)
2. Collect user feedback (was verdict correct?)
3. Analyze false positives (what triggered incorrectly?)
4. Adjust weights (e.g., if urgency language causes too many FPs, lower it)
5. Review monthly

**CISO can adjust in settings:**
```
CONFIDENCE TUNING

Verdict thresholds:
├── Phishing: 70+      [____]
├── Suspicious: 40-69  [____]
└── Safe: below 40     [____]

Signal weights:
├── Microsoft verdict: 40   [____]
├── SPF fail: 15            [____]
├── Domain age: 15          [____]
└── ... (all configurable)
```

**Goal:** Transparent, evidence-based, improvable over time.

---

## User Interface

### Side Panel Flow

```
1. User receives suspicious email
2. User clicks [Is This Phishing?] button in Outlook ribbon
3. Side panel opens on right
4. Shows "Analyzing..." briefly
5. Shows verdict
```

### Side Panel (Outlook Add-in)

```
┌─────────────────────┐
│ IS THIS PHISHING?   │
│                     │
│       🔴 YES        │
│                     │
│ Confidence: 87%     │
│                     │
│ Why:                │
│ • Microsoft flagged │
│ • SPF failed        │
│ • New domain        │
│ • Fake PayPal URL   │
│                     │
│ [Delete] [Report]   │
│                     │
│ ─────────────────── │
│ Was this correct?   │
│ [👍 Yes] [👎 No]    │
│                     │
└─────────────────────┘
```

### Outlook Ribbon Button

```
┌─────────────────────────────────────────────────────────────────┐
│ Home  Send/Receive  Folder  View  Help                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [New Email] [Delete] [Reply] [Forward]  ...   [🔍 Is This     │
│                                                  Phishing?]     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Email Reply (Forward Method)

```
From: phishing@forzon.ca
To: user@yourcompany.com
Subject: RE: Urgent: Your account limited

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 YES - THIS IS PHISHING

Confidence: 87%

Why:
• Sender domain is fake (paypa1.xyz)
• SPF failed
• Link goes to malicious site

Action: Delete this email.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Was this correct?
👍 Yes: https://phishcheck.forzon.ca/feedback/abc123?correct=yes
👎 No:  https://phishcheck.forzon.ca/feedback/abc123?correct=no

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## CISO Dashboard

### Overview Tab

```
┌─────────────────────────────────────────────────────────────────┐
│ JUSTPHISHING                              Today: Jan 22, 2026   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  TODAY              THIS WEEK         THIS MONTH               │
│  ┌─────────┐        ┌─────────┐       ┌─────────┐              │
│  │   847   │        │  4,521  │       │ 18,392  │              │
│  │ checked │        │ checked │       │ checked │              │
│  │         │        │         │       │         │              │
│  │ 🔴 142  │        │ 🔴 687  │       │ 🔴 2,841│              │
│  │ phishing│        │ phishing│       │ phishing│              │
│  └─────────┘        └─────────┘       └─────────┘              │
│                                                                 │
│  TOP TARGETS (This Week)          TOP THEMES (This Week)       │
│  ├── Finance (34%)                ├── Microsoft 365 reset (41%)│
│  ├── HR (22%)                     ├── PayPal verify (27%)      │
│  ├── Engineering (18%)            ├── DocuSign (15%)           │
│  └── Executive (12%)              └── Voicemail (9%)           │
│                                                                 │
│  THREAT ORIGINS                   ADOPTION                     │
│  ├── Russia 31%                   ├── Users active: 12,847     │
│  ├── Nigeria 24%                  │   (23% of org)             │
│  ├── China 18%                    └── Avg checks/user: 3.2     │
│  └── Other 27%                                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Campaign Detection & Alerts

When X users check same email within Y time → Alert triggered.

```
🔴 CAMPAIGN ALERT - CRITICAL

Coordinated phishing attack detected

Subject: "Urgent: Verify your Microsoft 365 account"
Sender: security@micros0ft-verify.xyz
First seen: 10:42 AM
Users affected: 67 (and growing)

Targets:
├── Finance: 23
├── HR: 18
├── Engineering: 14
└── Other: 12

[View Details] [Export IOCs] [Block Sender]
```

Alert thresholds (configurable):

| Threshold | Alert Level |
|-----------|-------------|
| 10 users in 1 hour | ⚠️ Warning |
| 30 users in 2 hours | 🟠 Elevated |
| 60 users in 4 hours | 🔴 Critical |

### Accuracy Tab

```
┌─────────────────────────────────────────────────────────────┐
│ ACCURACY (Last 30 Days)                                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Total verdicts:           2,841                            │
│  User feedback received:     412 (14.5%)                    │
│                                                             │
│  VERDICT        CONFIRMED    DISPUTED    ACCURACY           │
│  🔴 Phishing      312          8          97.5%             │
│  🟡 Suspicious     54          12         81.8%             │
│  🟢 Safe           38          2          95.0%             │
│                                                             │
│  FALSE POSITIVES (We said phishing, was actually safe)      │
│  • 3 - Vendor invoices (new vendor domain)                  │
│  • 2 - Partner emails (SPF misconfigured on their end)      │
│  • 2 - Marketing emails (urgency language)                  │
│  • 1 - Internal email routed externally                     │
│                                                             │
│  [View All Disputed] [Manage Whitelist]                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Dashboard Tabs

| Tab | Contents |
|-----|----------|
| Overview | Volume, trends, top threats, adoption |
| Campaigns | Active alerts, history, affected users, IOCs |
| Accuracy | Verdicts, false positives/negatives, whitelist |
| Submissions | All checked emails, filterable |
| Settings | Thresholds, notifications, weights, API keys |

---

## Feedback Loop

### User Reports Incorrect Verdict

```
┌─────────────────────────────────────┐
│                                     │
│  You marked this as SAFE            │
│                                     │
│  Help us improve:                   │
│  Why was this legitimate?           │
│                                     │
│  ○ Known sender (vendor/partner)    │
│  ○ Expected email (invoice, etc)    │
│  ○ Verified by phone/other channel  │
│  ○ Other: [____________]            │
│                                     │
│  [Submit]                           │
│                                     │
└─────────────────────────────────────┘
```

### SOC Reviews Disputed Verdicts

```
DISPUTED VERDICT

Original verdict:    🔴 PHISHING (87%)
User feedback:       "This was safe"
Reason:              "Known vendor, verified by phone"
Reported by:         j.smith@yourcompany.com

SOC REVIEW
Status:    ○ Pending  ○ Confirmed FP  ○ Rejected
Notes:     [_________________________________]

[Add to Whitelist]  [Dismiss]
```

### Whitelist Management

Confirmed false positives → Add to whitelist → Future emails score lower.

---

## Department Detection

User's department pulled from Azure AD:

```
GET /users/user@yourcompany.com?$select=mail,department

Response:
{
  "mail": "user@yourcompany.com",
  "department": "Finance"
}
```

Requires `User.Read.All` permission (admin consent, one-time).

---

## Data Model

```sql
-- All checked emails
CREATE TABLE submissions (
    id UUID PRIMARY KEY,
    fingerprint VARCHAR(32) NOT NULL,      -- For deduplication/campaigns
    submitted_at TIMESTAMP DEFAULT NOW(),
    submitted_by VARCHAR(255),
    submission_method VARCHAR(20),          -- 'addon' or 'forward'
    department VARCHAR(100),
    
    -- Original email
    original_sender VARCHAR(255),
    sender_domain VARCHAR(255),
    subject VARCHAR(500),
    headers TEXT,
    body_html TEXT,
    
    -- Analysis
    verdict VARCHAR(20),                    -- 'phishing', 'suspicious', 'safe'
    confidence INT,
    signals JSONB,                          -- Which signals triggered
    
    -- Campaign linking
    campaign_id UUID REFERENCES campaigns(id)
);

-- Detected campaigns
CREATE TABLE campaigns (
    id UUID PRIMARY KEY,
    name VARCHAR(255),
    fingerprint VARCHAR(32),
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    user_count INT,
    status VARCHAR(20),                     -- 'active', 'monitoring', 'stopped'
    indicators JSONB
);

-- User feedback
CREATE TABLE feedback (
    id UUID PRIMARY KEY,
    submission_id UUID REFERENCES submissions(id),
    user_email VARCHAR(255),
    original_verdict VARCHAR(20),
    user_says VARCHAR(20),                  -- 'correct', 'false_positive', 'false_negative'
    reason VARCHAR(50),
    notes TEXT,
    submitted_at TIMESTAMP,
    
    -- SOC review
    reviewed_by VARCHAR(255),
    reviewed_at TIMESTAMP,
    review_status VARCHAR(20),              -- 'pending', 'confirmed', 'rejected'
    added_to_whitelist BOOLEAN
);

-- Trusted senders/domains
CREATE TABLE whitelist (
    id UUID PRIMARY KEY,
    type VARCHAR(20),                       -- 'domain', 'sender'
    value VARCHAR(255),
    reason TEXT,
    added_by VARCHAR(255),
    added_at TIMESTAMP
);
```

---

## Tech Stack (Claude Code Optimized)

| Component | Choice | Why |
|-----------|--------|-----|
| Backend + Dashboard | Flask | Simple, single codebase, no build steps |
| Database | SQLite | Zero config, just a file |
| Styling | Tailwind CSS (CDN) | No build step needed |
| Charts | Chart.js (CDN) | Simple, just include script |
| Auth | Flask session + hardcoded user | Simple for demo |
| Outlook Add-in | HTML + JS (Office.js CDN) | Microsoft standard |
| Hosting | Your OVH Linux server | Nginx + Gunicorn |

---

## Project Structure

```
phishcheck/
├── app.py                    # Main Flask app (routes + API)
├── analyzer.py               # Email analysis logic
├── graph_client.py           # Microsoft Graph API
├── models.py                 # SQLite models
├── config.py                 # Settings
├── requirements.txt
├── templates/
│   ├── base.html             # Layout with Tailwind CDN
│   ├── login.html
│   ├── dashboard.html        # Overview stats + charts
│   ├── submissions.html      # All checked emails
│   ├── campaigns.html        # Campaign alerts
│   └── accuracy.html         # Feedback + whitelist
├── static/
│   └── (minimal, use CDN)
├── addon/
│   ├── manifest.xml          # Add-in config
│   ├── taskpane.html         # Side panel UI
│   └── taskpane.js           # Logic
├── phishcheck.db           # SQLite file (auto-created)
└── CLAUDE.md
```

---

## Requirements.txt

```
flask
python-dotenv
requests
dnspython
gunicorn
msal
```

---

## Permissions Required

| Permission | Purpose | Risk |
|------------|---------|------|
| Mail.Read (Application) | Read phishing@ mailbox | Low - one mailbox only |
| Mail.Send (Application) | Reply to users | Low - from phishing@ only |
| User.Read.All (Application) | Get user's department | Low - directory data only |

All require admin consent (one-time).

---

## Server Requirements

| Spec | MVP/Pilot | Production |
|------|-----------|------------|
| CPU | 2 cores | 4-8 cores |
| RAM | 4 GB | 8-16 GB |
| Storage | 50 GB | 100 GB |
| OS | Ubuntu 22.04 | Ubuntu 22.04 |

---

## Deployment Steps (Production)

| Step | Owner | Effort |
|------|-------|--------|
| 1. Provision internal Linux VM | IT Ops | 1 day |
| 2. Create shared mailbox phishing@forzon.ca | Exchange Admin | 1 hour |
| 3. Create Azure AD app registration | Azure Admin | 2 hours |
| 4. Grant Graph API permissions (admin consent) | Azure Admin | 30 min |
| 5. Deploy server (Docker) | You | 1 day |
| 6. Deploy add-in to pilot group | M365 Admin | 1 hour |
| 7. Test with pilot users | Security Team | 1 week |
| 8. Roll out org-wide | M365 Admin | 1 hour |

---

## Rollback Plan

```
If issues arise:
1. Disable add-in from M365 admin center (instant)
2. Stop Docker container
3. Disable phishing@ mailbox

Full rollback: < 5 minutes
```

---

## Security & Privacy

| Concern | Answer |
|---------|--------|
| Data leaves network? | No - all internal |
| Third-party access? | No - self-hosted |
| What data is stored? | Email metadata, headers, verdict, feedback |
| How long retained? | Configurable (30/60/90 days) |
| Who can access dashboard? | CISO/SOC (role-based) |
| Audit trail? | All checks logged with timestamp |

---

## CISO Pitch

### Current State vs Internal Tool

```
CURRENT                          JUSTPHISHING
─────────────────────────────    ─────────────────────────────
User clicks "Report"             User clicks "Is This Phishing?"

"Thanks for reporting"           "🔴 YES - Here's why..."

User learns nothing              User learns every time

CISO sees nothing                CISO sees:
                                 • Real-time volume
                                 • Campaign alerts
                                 • Department targeting
                                 • Attack trends
                                 • Accuracy metrics

Data goes to vendor              Data stays internal

Costs $$$                        Free (internal build)
```

### Value Proposition

> "Right now, users click 'Report Phishing' and get 'Thanks.'
>
> They don't know if it was actually phishing.
> You don't know how many users are being targeted.
>
> With Internal Tool:
> - Users get instant answers. They learn.
> - You see everything. Real-time.
> - 60 users check the same email? You're alerted immediately.
> - All data stays internal. No vendor. No cost.
>
> We turn a dead-end button into a security intelligence platform."

### Handling Objections

| Objection | Response |
|-----------|----------|
| "How accurate is it?" | We use Microsoft's own verdicts from O365 headers. Same accuracy as Defender. Plus our additional checks. |
| "What if Microsoft is wrong?" | Then we're wrong too - but we add extra checks (domain age, lookalikes) that catch what Microsoft misses. User feedback closes the loop. |
| "What about false positives?" | Tracked and reported. Users can dispute. SOC reviews. System learns via whitelist. |
| "Does data leave our network?" | No. All internal. Self-hosted. |
| "What permissions does it need?" | Read one mailbox. Deploy add-in. User directory lookup. All read-only. |
| "What if it goes down?" | Email still works. Users just can't check. Rollback in 5 minutes. |
| "Who maintains it?" | Initially you. Simple Docker deployment. IT can own long-term. |

---

## Comparison to Existing Tools

| Feature | Report Button | Proofpoint | Cofense | Internal Tool |
|---------|---------------|------------|---------|--------------|
| Instant verdict to user | ❌ | ❌ | ❌ | ✅ |
| Explains why | ❌ | ❌ | ❌ | ✅ |
| User learns | ❌ | ❌ | ❌ | ✅ |
| CISO real-time visibility | ❌ | ⚠️ Portal | ⚠️ Portal | ✅ |
| Campaign detection | ❌ | ⚠️ | ⚠️ | ✅ |
| Data stays internal | ❌ | ❌ | ❌ | ✅ |
| Cost | - | $$$ | $$$ | Free |

---

## Test Environment

| Component | Where |
|-----------|-------|
| M365 Dev Tenant | Free developer account |
| Linux Server | OVH (or local Docker) |
| Domain | forzon.ca |
| Shared Mailbox | phishing@forzon.ca |

### Getting Started

1. Sign up: https://developer.microsoft.com/en-us/microsoft-365/dev-program
2. Get 25 free E5 licenses for 90 days
3. Create shared mailbox
4. Register Azure AD app
5. Deploy to OVH server
6. Build add-in
7. Demo to CISO

---

## Build Plan (4 Hours)

| Time | Task | Output |
|------|------|--------|
| 30 min | Flask app + routes | app.py with dashboard and API routes |
| 15 min | SQLite models | models.py with submissions, feedback, whitelist |
| 30 min | Analyzer | analyzer.py with header parsing, scoring |
| 1 hour | Dashboard UI | Templates with Tailwind, Chart.js |
| 30 min | Outlook add-in | Side panel that calls API |
| 30 min | Graph API client | Read phishing@ mailbox, send replies |
| 30 min | Test with M365 | Real emails in dev tenant |
| 15 min | Polish | Fix bugs, improve UI |

---

## Claude Code Prompts

Start with:
```
"Read CLAUDE.md and create the Flask app with routes for dashboard and API"
```

Then:
```
"Create the analyzer.py with header parsing and scoring logic"
```

Then:
```
"Create the dashboard templates with Tailwind and Chart.js"
```

Then:
```
"Create the Outlook add-in files"
```

Then:
```
"Create the Graph API client for reading mailbox and sending replies"
```

---

## Demo Setup (OVH Server)

```bash
# Clone/upload project
cd /var/www/phishcheck

# Install dependencies
pip install -r requirements.txt

# Run with Gunicorn
gunicorn -w 2 -b 127.0.0.1:5000 app:app

# Nginx config
server {
    listen 443 ssl;
    server_name phishcheck.forzon.ca;
    
    ssl_certificate /etc/letsencrypt/live/.../fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/.../privkey.pem;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## M365 Dev Tenant Setup

1. Sign up: https://developer.microsoft.com/en-us/microsoft-365/dev-program
2. Create Azure AD app registration:
   - Name: Internal Tool
   - Permissions: Mail.Read, Mail.Send, User.Read.All
   - Admin consent: Grant
3. Create shared mailbox: phishing@forzon.ca
4. Sideload add-in for testing

---

## What To Show CISO

1. Open Outlook (M365 dev tenant)
2. Open a test phishing email
3. Click [Is This Phishing?] button
4. Side panel shows: 🔴 YES + confidence + reasons
5. Click feedback: "Was this correct?"
6. Open dashboard in browser:
   - Stats: emails checked, phishing detected
   - Chart: volume over time
   - Table: recent submissions
   - Campaign alert example
   - Accuracy metrics
7. Pitch: "Imagine 55K employees using this"

---

## File Structure

```
phishcheck/
├── app.py                    # Main Flask app (routes + API)
├── analyzer.py               # Email analysis logic
├── graph_client.py           # Microsoft Graph API
├── models.py                 # SQLite models
├── config.py                 # Settings (client ID, secrets)
├── requirements.txt
├── templates/
│   ├── base.html             # Layout (Tailwind CDN, Chart.js CDN)
│   ├── login.html            # Simple login form
│   ├── dashboard.html        # Overview: stats, charts
│   ├── submissions.html      # Table of all checked emails
│   ├── campaigns.html        # Active campaign alerts
│   └── accuracy.html         # Feedback, false positives, whitelist
├── addon/
│   ├── manifest.xml          # Office add-in manifest
│   ├── taskpane.html         # Side panel UI
│   └── taskpane.js           # Call API, show results
├── phishcheck.db           # SQLite database (auto-created)
└── CLAUDE.md                 # This file
```

---

## Success Metrics

| Metric | Target |
|--------|--------|
| User adoption | 50% check at least 1 email/week |
| Detection rate | Surface 100% of O365-flagged phishing |
| Time to verdict | < 3 seconds |
| False positive rate | < 5% |
| User satisfaction | > 80% confirm verdict correct |
| Campaign detection | Alert within 1 hour of coordinated attack |

---

## Future Enhancements

| Feature | Value |
|---------|-------|
| Mobile app | Check on phone |
| Teams bot | /phishcheck in chat |
| SIEM integration | Feed IOCs to Splunk/Sentinel |
| Automated blocking | Block sender after X reports |
| Phishing simulation | Send test phishes, track who clicks |
| Training integration | Auto-enroll users who need help |

---

## Notes

- Weights are starting points - tune based on feedback data
- Department detection requires User.Read.All permission
- Campaign fingerprint = hash of sender_domain + subject + body_snippet + links
- All times in UTC
- Dashboard access should be role-based (CISO, SOC, read-only)



<claude-mem-context>
# Recent Activity

<!-- This section is auto-generated by claude-mem. Edit content outside the tags. -->

### Feb 6, 2026

| ID | Time | T | Title | Read |
|----|------|---|-------|------|
| #1165 | 8:32 PM | 🔵 | PhishCheck Environment Configuration Template | ~530 |
| #1152 | 8:28 PM | 🔵 | PhishCheck Production Configuration and Credentials | ~565 |
| #1149 | 8:27 PM | 🔵 | Comprehensive Email Phishing Analyzer with Multi-Layer Detection | ~815 |
</claude-mem-context>