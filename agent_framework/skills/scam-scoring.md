# Skill Playbook: Final Scam Scoring & Escalation Rubric (`scam-scoring.md`)

Combine outputs from all tools and content analysis into a **Final Risk Score (0–100)** and map it to a deterministic **Escalated Action**.

## 1. Component Weighting Rubric (Total: 0–100 Points)

### A. Sender/Receiver Integrity & Cryptographic Auth (0–35 points)
- **DMARC `fail` or `none` on a high-value/spoofed domain**: +15 pts
- **SPF `fail` or `softfail`**: +8 pts
- **DKIM `fail` or `none`**: +7 pts
- **Lookalike / Homograph / Typosquatted Sender Domain** (e.g., `paypaI-support.com` vs `paypal.com`): +20 pts
- **`From` vs. `Reply-To` or `Return-Path` Domain Mismatch** (pointing to an untrusted external domain): +12 pts
- **Trusted Domain Bonus**: If the sender domain is verified in the **Trusted Domains Redis DB** AND passes SPF + DKIM + DMARC (`pass`), set this entire component score to **0 points**.
*(Cap Component A at 35 points)*

### B. URL & Attachment Threat Intelligence (0–30 points)
- **Confirmed Malicious / Phishing URL** flagged by Scan APIs: +30 pts
- **Suspicious URL Heuristics** (newly registered / untrusted TLD `.xyz`, `.top`, `.zip`, raw IP address URL, punycode `xn--`, credential-harvesting path keywords `/login`, `/verify`, `/secure-update` on untrusted domain): +18 pts
- **Anchor Text vs. Href Domain Mismatch**: +15 pts
- **High-Risk Attachment Extension** (`.exe`, `.scr`, `.iso`, `.hta`, `.lnk`, double extensions like `.pdf.exe`): +25 pts
*(Cap Component B at 30 points)*

### C. Psychological & Content Analysis (0–35 points)
- Derived directly from `content-analysis.md` (Urgency + Fear + Authority Impersonation + Lure Mechanics).
*(Cap Component C at 35 points)*

### D. Campaign History Boost (0–15 points bonus, capped at 100 total)
- If `campaign_memory` reports a prior confirmed phishing campaign matching the sender/subject/URL fingerprint, add **+15 points** (total score capped at 100).

---

## 2. Escalated Action Thresholds

| Final Risk Score | Risk Level | Escalated Action | Contextual UI Behavior |
| :--- | :--- | :--- | :--- |
| **85 – 100** | `CRITICAL` | `QUARANTINE_AND_BLOCK` | Red critical banner; move email to quarantine, block sender/URLs, alert SOC. |
| **60 – 84** | `HIGH` | `WARN_AND_DISABLE_LINKS` | Orange high-risk banner; rewrite/disable all clickable links and attachments. |
| **30 – 59** | `MEDIUM` | `CAUTION_BANNER` | Yellow caution banner; highlight external sender & urge out-of-band verification. |
| **0 – 29** | `LOW` | `ALLOW` | Green verified badge; normal delivery with no user interruption. |

