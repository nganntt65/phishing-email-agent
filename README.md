# CampusGuard AI: Phishing Email Agentic AI System

*AI-Powered Email Security for Students.* Not sure if that university email is real? Analyze suspicious emails, uncover warning signs, and get evidence-based guidance before taking action.

A student-facing scam checker built on an agentic pipeline: **FastAPI**, **Gemini** (google-genai), a **trusted-domains store** (Redis or in-memory), **skill playbooks in Markdown**, **campaign memory** (SQLite) and a **WebSocket** analyst view.

Three ways to check something:

| Input | How | Endpoint |
|---|---|---|
| **Link** | paste a URL | `POST /api/v1/scan-url` |
| **Email PDF** | Print → Save as PDF, then upload | `POST /api/v1/analyze/upload` |
| **Email source** | `.eml` file or pasted text | `POST /api/v1/analyze`, `/analyze/upload`, `WS /ws/analyze` |

Every result says **what we found, why it matters and what to do next**, plus *How we decided*: score breakdown, verbatim evidence (LLM quotes are checked against the email), confidence, and what couldn't be checked. If Gemini isn't used, the result says so and why. Fallbacks are never silent.

## Run it (Windows, PowerShell)

```powershell
git clone https://github.com/yardannaufal/Campus-Guard-AI.git
cd Campus-Guard-AI
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

Open <http://localhost:8000>. Tabs: **Scan** (students), **Analyst** (full pipeline), **Evaluation** (metrics).

macOS / Linux: same steps with `.venv/bin/python`.

### Gemini key and other settings

Easiest: copy `.env.example` to `.env`, paste your key after `GEMINI_API_KEY=`, and (re)start the server. The app reads `.env` on startup; `.env` is git-ignored. Step-by-step guide with checks and troubleshooting: [SETUP.md](SETUP.md).

Or set them in the same terminal **before** starting uvicorn (these win over `.env`):

```powershell
$env:GEMINI_API_KEY = "your-own-key"           # enables Gemini reasoning (free key: Google AI Studio)
$env:GEMINI_MODEL = "gemini-3-flash-preview"   # default; falls back to gemini-2.5-flash
# Optional, off by default. CampusGuard AI is generic (any university). A university that deploys it
# can name its official domains to get "looks like OUR login domain" checks and a portal button:
$env:CAMPUS_NAME = "My University"
$env:CAMPUS_DOMAINS = "myuni.ac.id"            # official domains, comma-separated
$env:CAMPUS_PORTAL_URL = "https://portal.myuni.ac.id"
$env:SAFE_BROWSING_API_KEY = "..."             # optional Google Safe Browsing lookups
$env:REDIS_URL = "redis://localhost:6379/0"    # optional; in-memory store is used if Redis isn't reachable
```

Never commit keys. `.env` is git-ignored; `.env.example` (no secrets) is the template that is committed.

## Evaluation

```powershell
.venv\Scripts\python.exe eval\generate_dataset.py --seed 42   # 260 synthetic items, reproducible
.venv\Scripts\python.exe eval\run_eval.py --split dev           # tune on dev only
.venv\Scripts\python.exe eval\run_eval.py                       # final numbers on the test split
```

Results go to `eval/results/latest/` (`report.md`, `summary.json`, `results.jsonl`) (the Evaluation tab does not show them; it runs the live app instead, see below). See [eval/README.md](eval/README.md) for the protocol and how to read the numbers.

Current rule-engine result (no Gemini, threshold 60): 251 of 260 items right, 0 false alarms, recall 0.93 (test split: precision 1.000, recall 0.934, F1 0.966). Synthetic data: these numbers describe this dataset, not real-world accuracy.

The Evaluation tab can also run the live app on 10, 50, 100, 200 random items or all items, and count right and wrong from that run. Random runs don't repeat items within a browser session. You can add your own labelled `.eml`, `.pdf`, `.txt` files and links there; they are stored in `eval/added/` (git-ignored) and join the live runs, but not `eval/run_eval.py`.

## Tests

```powershell
.venv\Scripts\python.exe -m pytest -q
```

Tests use a throwaway campaign database, the in-memory trusted list and no live Gemini calls (Gemini is mocked).

## Layout

```
app/
  main.py              API, WebSocket, evaluation endpoints
  orchestrator.py      agent loop: sanitize -> skills -> tools -> memory -> LLM -> result
  llm.py               Gemini calls with explicit status (USED / SKIPPED / FAILED), disk cache
  link_scan.py         stand-alone link scan and labels
  pdf_parser.py        Print-to-PDF emails: text, printed headers, link targets
  evidence.py          verbatim quotes, groundedness check, plain-language finding
  summary.py           student-facing result card (same shape for every input)
  domains.py           trusted-domain matching, campus lookalike detection
  tools/               sender integrity (SPF/DKIM/DMARC), URL + attachment scan
  static/              UI (no CDN; works offline)
agent_framework/       base prompt + skill playbooks (.md)
eval/                  dataset generator, ML baseline, metrics, harness
```
